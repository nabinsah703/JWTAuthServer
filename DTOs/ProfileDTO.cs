namespace JWTAuthServer.DTOs
{
    public class ProfileDTO
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Firstname { get; set; }
        public string? Lastname { get; set; }
        public List<string> Roles { get; set; }
    }
}