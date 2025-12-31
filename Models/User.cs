using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
namespace JWTAuthServer.Models
{
    [Index(nameof(Email), Name = "IX_Unique_Email", IsUnique = true)]
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Firstname { get; set; }

        public string? Lastname { get; set; }

        [Required]
        [StringLength(100)]
        public string Password { get; set; }

        // Navigation property for many-to-many relationship with Role
        public ICollection<UserRole> UserRoles { get; set; }

        // Navigation property for refresh tokens
        public ICollection<RefreshToken> RefreshTokens { get; set; }
    }
}