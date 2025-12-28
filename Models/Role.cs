using System.ComponentModel.DataAnnotations;
namespace JWTAuthServer.Models
{
    public class Role
    {
        // Primary key for the Role entity.
        [Key]
        public int Id { get; set; }

        // Name of the role (e.g., Admin, User).
        [Required]
        [MaxLength(50)]
        public string Name { get; set; }

        //Role Description
        public string? Description { get; set; }

        // Navigation property for the relationship with UserRole.
        public ICollection<UserRole> UserRoles { get; set; }
    }
}