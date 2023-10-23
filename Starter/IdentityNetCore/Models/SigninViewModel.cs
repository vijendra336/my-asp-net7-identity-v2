using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models
{
    public class SigninViewModel
    {
        [Required]
        [DataType(DataType.EmailAddress, ErrorMessage = "EmailAddress is missing or Invalid")]
        public string Username { get; set; }
        [Required]
        [DataType(DataType.Password, ErrorMessage = "Password must be provided")]
        public string Password { get; set; }
        public bool RememberMe { get; set; }
    }
}
