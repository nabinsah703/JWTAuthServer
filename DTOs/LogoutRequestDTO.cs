using System.ComponentModel.DataAnnotations;
namespace JWTAuthServer.DTOs
{
    public class LogoutRequestDTO
    {
        public required string RefreshToken { get; set; }
        public required string ClientId { get; set; }
        public bool IsLogoutFromAllDevices { get; set; }
    }
}