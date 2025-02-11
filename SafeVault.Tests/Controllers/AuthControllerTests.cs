using SafeVault.Controllers;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Moq;
using SafeVault.DTO;
using Microsoft.Extensions.Options;

namespace SafeVault.Tests.Controllers;

public class AuthControllerTests
{
    private readonly Mock<UserManager<ApplicationUser>> _mockUserManager;
    private readonly Mock<RoleManager<IdentityRole>> _mockRoleManager;
    private readonly Mock<JwtService> _mockJwtService;
    private readonly AuthController _authController;
    private readonly Mock<IPasswordHasher<ApplicationUser>> _mockPasswordHasher;

    public AuthControllerTests()
    {
        // Mock UserManager
        var userStoreMock = new Mock<IUserStore<ApplicationUser>>();
        _mockUserManager = new Mock<UserManager<ApplicationUser>>(
            userStoreMock.Object, null, null, null, null, null, null, null, null
        );

        // Mock RoleManager
        var roleStoreMock = new Mock<IRoleStore<IdentityRole>>();
        _mockRoleManager = new Mock<RoleManager<IdentityRole>>(
            roleStoreMock.Object, null, null, null, null
        );

        // Mock IPasswordHasher<ApplicationUser>
        _mockPasswordHasher = new Mock<IPasswordHasher<ApplicationUser>>();
        _mockUserManager.Object.PasswordHasher = _mockPasswordHasher.Object;

        // Mock JwtService
        var jwtSettings = new JwtSettings
        {
            // fake secret key
            SecretKey = "bT2sXaVXLtp6DGf9y2iHTMyLDGERvuysDoskuDJmCZ9eQvtqJ23qDHv7A43b",
            ValidIssuer = "TestIssuer",
            ValidAudience = "TestAudience",
            TokenLifetimeInMinutes = 60
        };
        var mockJwtSettings = new Mock<IOptions<JwtSettings>>();
        mockJwtSettings.Setup(x => x.Value).Returns(jwtSettings);

        var jwtService = new JwtService(mockJwtSettings.Object);

        // Initialize AuthController
        _authController = new AuthController(
            _mockUserManager.Object,
            _mockRoleManager.Object,
            jwtService
        );
    }

    [Fact]
    public async Task Register_ValidUser_ReturnsOk()
    {
        // Arrange
        var model = new RegisterDto { Username = "testuser", Email = "test@example.com", Password = "Password123!" };

        _mockUserManager.Setup(um => um.CreateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);
        _mockUserManager.Setup(um => um.AddToRoleAsync(It.IsAny<ApplicationUser>(), "User"))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _authController.Register(model);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal("User registered successfully.", okResult.Value);
    }

    [Fact]
    public async Task Register_InvalidModelState_ReturnsBadRequest()
    {
        // Arrange
        _authController.ModelState.AddModelError("error", "some error");

        var model = new RegisterDto { Username = "testuser", Email = "test@example.com", Password = "Password123!" };

        // Act
        var result = await _authController.Register(model);

        // Assert
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Register_UserCreationFails_ReturnsBadRequest()
    {
        // Arrange
        var model = new RegisterDto { Username = "testuser", Email = "test@example.com", Password = "Password123!" };

        _mockUserManager.Setup(um => um.CreateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Error creating user." }));

        // Act
        var result = await _authController.Register(model);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Error creating user.", ((IEnumerable<IdentityError>)badRequestResult.Value).First().Description);
    }
    
    [Fact]
    public async Task Login_UserNotFound_ReturnsUnauthorized()
    {
        // Arrange
        var model = new LoginDto { Username = "nonexistentuser", Password = "Password123!" };

        _mockUserManager.Setup(um => um.FindByNameAsync(model.Username))
            .ReturnsAsync((ApplicationUser)null);

        // Act
        var result = await _authController.Login(model);

        // Assert
        var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("Invalid username or password.", unauthorizedResult.Value);
    }

    [Fact]
    public async Task Login_InvalidPassword_ReturnsUnauthorized()
    {
        // Arrange
        var loginDto = new LoginDto { Username = "testuser", Password = "WrongPassword" };
        var user = new ApplicationUser { UserName = "testuser" };

        // Set a valid hashed password for a different password
        var passwordHasher = new PasswordHasher<ApplicationUser>();
        user.PasswordHash = passwordHasher.HashPassword(user, "CorrectPassword123!"); // The actual, correct password

        _mockUserManager.Setup(um => um.FindByNameAsync(loginDto.Username))
            .ReturnsAsync(user);
        _mockPasswordHasher.Setup(ph => ph.VerifyHashedPassword(user, user.PasswordHash, loginDto.Password))
            .Returns(PasswordVerificationResult.Failed);

        // Act
        var result = await _authController.Login(loginDto);

        // Assert
        var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal("Invalid username or password.", unauthorizedResult.Value);
    }

    [Fact]
    public async Task Login_ValidCredentials_ReturnsOkWithToken()
    {
        // Arrange
        var loginDto = new LoginDto { Username = "testuser", Password = "Password123!" };
        var user = new ApplicationUser { UserName = "testuser" };

        // Set a valid hashed password
        var passwordHasher = new PasswordHasher<ApplicationUser>();
        user.PasswordHash = passwordHasher.HashPassword(user, loginDto.Password);

        _mockUserManager.Setup(um => um.FindByNameAsync(loginDto.Username))
            .ReturnsAsync(user);
        _mockPasswordHasher.Setup(ph => ph.VerifyHashedPassword(user, user.PasswordHash, loginDto.Password))
            .Returns(PasswordVerificationResult.Success);

        // Act
        var result = await _authController.Login(loginDto);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var token = ((dynamic)okResult.Value).Token;
        Assert.NotNull(token); // Ensure token is returned
    }


    [Fact]
    public async Task SeedRoles_RolesCreatedSuccessfully_ReturnsOk()
    {
        // Arrange
        _mockRoleManager.Setup(rm => rm.RoleExistsAsync(It.IsAny<string>()))
            .ReturnsAsync(false);
        _mockRoleManager.Setup(rm => rm.CreateAsync(It.IsAny<IdentityRole>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _authController.SeedRoles();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal("Roles created successfully.", okResult.Value);
    }
}
