using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/data")]
public class AccessController : ControllerBase
{
    [HttpGet("admin")]
    [Authorize(Policy = "AdminPolicy")]
    public IActionResult GetAdminData()
    {
        return Ok("This data is accessible to Admins only.");
    }

    [HttpGet("user")]
    [Authorize(Policy = "UserPolicy")]
    public IActionResult GetUserData()
    {
        return Ok("This data is accessible to Users only.");
    }

    [HttpGet("guest")]
    [Authorize(Policy = "GuestPolicy")]
    public IActionResult GetGuestData()
    {
        return Ok("This data is accessible to Guests.");
    }
}
