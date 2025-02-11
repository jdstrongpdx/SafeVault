using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Models;
using SafeVault.DTO;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly JwtService _jwtService;


    // Bcrypt-based password hasher NOTE: automatically includes salting
    private readonly IPasswordHasher<ApplicationUser> _passwordHasher;

    public AuthController(UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        JwtService jwtService
        )
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _jwtService = jwtService;

        // PasswordHasher instance
        _passwordHasher = new PasswordHasher<ApplicationUser>();
    }

    // Register a new user
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        // Create a new user instance
        var user = new ApplicationUser
        {
            UserName = model.Username,
            Email = model.Email
        };

        // Hash the password before storing the user
        user.PasswordHash = _passwordHasher.HashPassword(user, model.Password);

        var result = await _userManager.CreateAsync(user);

        if (!result.Succeeded) return BadRequest(result.Errors);
        
        // Assign default role of User
        await _userManager.AddToRoleAsync(user, "User");

        return Ok("User registered successfully.");
    }

    // Login and issue JWT
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto model)
    {
        var user = await _userManager.FindByNameAsync(model.Username);
        if (user == null) return Unauthorized("Invalid username or password.");

        // Verify the password using the PasswordHasher
        var passwordVerificationResult = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password);
        if (passwordVerificationResult != PasswordVerificationResult.Success)
            return Unauthorized("Invalid username or password.");

        // Generate JWT token
        var token = _jwtService.GenerateToken(model.Username);

        return Ok(new { Token = token });

    }

    // Logout (for session clearing, if needed)
    [Authorize]
    [HttpPost("logout")]
    public IActionResult Logout()
    {
        // Logging out would typically involve clearing a client-side token
        return Ok("Logged out successfully.");
    }

    // Seed roles
    [HttpPost("seed-roles")]
    public async Task<IActionResult> SeedRoles()
    {
        var roles = new[] { "Admin", "User", "Guest" };

        foreach (var role in roles)
        {
            if (!await _roleManager.RoleExistsAsync(role))
            {
                await _roleManager.CreateAsync(new IdentityRole(role));
            }
        }

        return Ok("Roles created successfully.");
    }
}