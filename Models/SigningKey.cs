using System.ComponentModel.DataAnnotations;

namespace JWTAuthServer.Models
{
    public class SigningKey
    {
        [Key]
        public int Id { get; set; }

        // Unique identifier for the key (Key ID).
        [Required]
        [MaxLength(100)]
        public string KeyId { get; set; }

        // The RSA private key.
        [Required]
        public string PrivateKey { get; set; }

        // The RSA public key in XML or PEM format.
        [Required]
        public string PublicKey { get; set; }

        // Indicates if the key is active.
        [Required]
        public bool IsActive { get; set; }

        // Date when the key was created.
        [Required]
        public DateTime CreatedAt { get; set; }

        // Date when the key is set to expire.
        [Required]
        public DateTime ExpiresAt { get; set; }
    }
}