using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.DTO;
using SafeVault.Services;
using SafeVault.Utilities;

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

        // Validate allowed characters in input fields
        if (!ValidationHelpers.IsValidInput(model.Username) || 
            !ValidationHelpers.IsValidInput(model.Email, ".@"))
        {
            return BadRequest("Invalid characters detected in input.");
        }

        // Validate XSS-specific attack patterns in user input fields
        if (!ValidationHelpers.IsValidXssInput(model.Username) || 
            !ValidationHelpers.IsValidXssInput(model.Email))
        {
            return BadRequest("Input contains potentially malicious content.");
        }

        var user = new ApplicationUser
        {
            UserName = model.Username,
            Email = model.Email
        };

        // Ensure secure password hashing (with salting)
        user.PasswordHash = _passwordHasher.HashPassword(user, model.Password);
        var result = await _userManager.CreateAsync(user);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        await _userManager.AddToRoleAsync(user, "User");

        return Ok("User registered successfully.");
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto model)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        if (!ValidationHelpers.IsValidInput(model.Username) || 
            !ValidationHelpers.IsValidXssInput(model.Username))
        {
            return BadRequest("Invalid input provided.");
        }

        var user = await _userManager.FindByNameAsync(model.Username);
        if (user == null) return Unauthorized("Invalid username or password.");

        var passwordVerificationResult = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password);
        if (passwordVerificationResult != PasswordVerificationResult.Success)
            return Unauthorized("Invalid username or password.");

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