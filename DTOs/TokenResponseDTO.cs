namespace JWTAuthServer.DTOs
{
    public class TokenResponseDTO
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
    }
}