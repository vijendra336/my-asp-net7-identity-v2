using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models
{
    public class SignupViewModel
    {
        [Required]
        [DataType(DataType.EmailAddress, ErrorMessage = "EmailAddress is missing or Invalid")]
        public string Email { get; set; }
        [Required]
        [DataType (DataType.Password , ErrorMessage = "Incorrect or missing password")]
        public string Password { get; set; }
    }
}
