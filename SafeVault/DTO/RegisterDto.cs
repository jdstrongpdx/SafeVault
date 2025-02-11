namespace SafeVault.DTO;
using System.ComponentModel.DataAnnotations;

public class RegisterDto
{
    [Required, MinLength(5), MaxLength(20)]
    public string Username { get; set; }

    [Required, EmailAddress]
    public string Email { get; set; }

    [Required, MinLength(8), MaxLength(50)]
    [RegularExpression("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=]).*$", 
        ErrorMessage = "Password must have at least one uppercase letter, one lowercase letter, one digit, and one special character.")]
    public string Password { get; set; }
}
