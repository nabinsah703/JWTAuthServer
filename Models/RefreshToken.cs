using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthServer.Models
{
    [Index(nameof(Token), Name = "IX_Token_Unique", IsUnique = true)]
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }

        // The refresh token string (should be a secure random string)
        [Required]
        public string Token { get; set; }

        // The user associated with the refresh token
        [Required]
        public int UserId { get; set; }

        [ForeignKey("UserId")]
        public User User { get; set; }

        // The client associated with the refresh token
        [Required]
        public int ClientId { get; set; }

        [ForeignKey(nameof(ClientId))]
        public Client Client { get; set; }

        // Token expiration date
        [Required]
        public DateTime ExpiresAt { get; set; }

        // Indicates if the token has been revoked
        [Required]
        public bool IsRevoked { get; set; } = false;

        // Date when the token was created
        [Required]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Date when the token was revoked
        public DateTime? RevokedAt { get; set; }
    }
}