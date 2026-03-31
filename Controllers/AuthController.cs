using JWTAuthServer.Data;
using JWTAuthServer.DTOs;
using JWTAuthServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        // Private fields to hold the configuration and database context
        // Holds configuration settings from appsettings.json or environment variables
        private readonly IConfiguration _configuration;

        // Database context for interacting with the database
        private readonly ApplicationDbContext _context;

        // Constructor that injects IConfiguration and ApplicationDbContext via dependency injection
        public AuthController(IConfiguration configuration, ApplicationDbContext context)
        {
            // Assign the injected IConfiguration to the private field
            _configuration = configuration;

            // Assign the injected ApplicationDbContext to the private field
            _context = context;
        }

        // Define the Login endpoint that responds to POST requests at 'api/Auth/Login'
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDto)
        {
            // Validate the incoming model based on data annotations in LoginDTO
            if (!ModelState.IsValid)
            {
                // If the model is invalid, return a 400 Bad Request with validation errors
                return BadRequest(ModelState);
            }

            // Query the Clients table to verify if the provided ClientId exists
            var client = _context.Clients
                .FirstOrDefault(c => c.ClientId == loginDto.ClientId);

            // If the client does not exist, return a 401 Unauthorized response
            if (client == null)
            {
                return Unauthorized("Invalid client credentials.");
            }

            // Retrieve the user from the Users table by matching the email (case-insensitive)
            // Also include the UserRoles and associated Roles for later use
            var user = await _context.Users
                .Include(u => u.UserRoles) // Include the UserRoles navigation property
                    .ThenInclude(ur => ur.Role) // Then include the Role within each UserRole
                .FirstOrDefaultAsync(u => u.Email.ToLower() == loginDto.Email.ToLower());

            // If the user does not exist, return a 401 Unauthorized response
            if (user == null)
            {
                // For security reasons, avoid specifying whether the client or user was invalid
                return Unauthorized("Invalid credentials.");
            }

            // Verify the provided password against the stored hashed password using BCrypt
            bool isPasswordValid = BCrypt.Net.BCrypt.Verify(loginDto.Password, user.Password);

            // If the password is invalid, return a 401 Unauthorized response
            if (!isPasswordValid)
            {
                // Again, avoid specifying whether the client or user was invalid
                return Unauthorized("Invalid credentials.");
            }

            // At this point, authentication is successful. Proceed to generate a JWT token.
            var token = GenerateJwtToken(user, client);
            // Generate Refresh Token
            var refreshToken = GenerateRefreshToken();
            // Hash the refresh token before storing
            var hashedRefreshToken = HashToken(refreshToken);
            // Create RefreshToken entity
            var refreshTokenEntity = new RefreshToken
            {
                Token = hashedRefreshToken,
                UserId = user.Id,
                ClientId = client.Id,
                //Refresh tokens are set to expire after 7 days (you can adjust this as needed).
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false
            };
            // The hashed refresh token, along with associated user and client information, is stored in the RefreshTokens table.
            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();
            // Return both tokens to the client
            return Ok(new TokenResponseDTO
            {
                Token = token,
                RefreshToken = refreshToken
            });
        }

        // Private method responsible for generating a JWT token for an authenticated user
        private string GenerateJwtToken(User user, Client client)
        {
            // Retrieve the active signing key from the SigningKeys table
            var signingKey = _context.SigningKeys.FirstOrDefault(k => k.IsActive);

            // If no active signing key is found, throw an exception
            if (signingKey == null)
            {
                throw new Exception("No active signing key available.");
            }

            // Convert the Base64-encoded private key string back to a byte array
            var privateKeyBytes = Convert.FromBase64String(signingKey.PrivateKey);

            // Create a new RSA instance for cryptographic operations
            var rsa = RSA.Create();

            // Import the RSA private key into the RSA instance
            rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

            // Create a new RsaSecurityKey using the RSA instance
            var rsaSecurityKey = new RsaSecurityKey(rsa)
            {
                // Assign the Key ID to link the JWT with the correct public key
                KeyId = signingKey.KeyId
            };

            // Define the signing credentials using the RSA security key and specifying the algorithm
            var creds = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);

            // Initialize a list of claims to include in the JWT
            var claims = new List<Claim>
            {
                // Subject (sub) claim with the user's ID
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),

                // JWT ID (jti) claim with a unique identifier for the token
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),

                // Name claim with the user's first name
                new Claim(ClaimTypes.Name, user.Firstname),

                // NameIdentifier claim with the user's email
                new Claim(ClaimTypes.NameIdentifier, user.Email),

                // Email claim with the user's email
                new Claim(ClaimTypes.Email, user.Email)
            };

            // Iterate through the user's roles and add each as a Role claim
            foreach (var userRole in user.UserRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole.Role.Name));
            }

            // Define the JWT token's properties, including issuer, audience, claims, expiration, and signing credentials
            var tokenDescriptor = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"], // The token issuer, typically your application's URL
                audience: client.ClientURL, // The intended recipient of the token, typically the client's URL
                claims: claims, // The list of claims to include in the token
                expires: DateTime.UtcNow.AddHours(1), // Token expiration time set to 1 hour from now
                signingCredentials: creds // The credentials used to sign the token
            );

            // Create a JWT token handler to serialize the token
            var tokenHandler = new JwtSecurityTokenHandler();

            // Serialize the token to a string
            var token = tokenHandler.WriteToken(tokenDescriptor);

            // Return the serialized JWT token
            return token;
        }


        // Only authenticated users can access the Logout endpoint.
        [Authorize]
        [HttpPost]
        [Route("Logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequestDTO requestDto)
        {
            //  Ensures that the incoming request contains both RefreshToken and ClientId.
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // The user ID is extracted from the access token's claims to ensure that
            // the refresh token being revoked belongs to the authenticated user.
            var userIdClaim = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
            {
                return Unauthorized("Invalid access token.");
            }

            // Ensure that the refresh token being revoked belongs to the authenticated user.
            if (!int.TryParse(userIdClaim.Value, out int userId))
            {
                return Unauthorized("Invalid user ID in access token.");
            }

            // Hash the incoming refresh token to compare with stored hash
            var hashedToken = HashToken(requestDto.RefreshToken);

            // The hashed token, ClientId and User Id are used to locate the corresponding RefreshToken entity in the database.
            // Includes the User and Client entities for potential additional operations.
            var storedRefreshToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                .Include(rt => rt.Client)
                .FirstOrDefaultAsync(rt => rt.Token == hashedToken && rt.Client.ClientId == requestDto.ClientId && rt.UserId == userId);

            // Checks if the refresh token exists.
            if (storedRefreshToken == null)
            {
                return Unauthorized("Invalid refresh token.");
            }

            // Ensures the token hasn't already been revoked to prevent redundant operations.
            if (storedRefreshToken.IsRevoked)
            {
                return BadRequest("Refresh token is already revoked.");
            }

            // Revoke the refresh token
            // Sets IsRevoked to true and updates the RevokedAt timestamp.
            storedRefreshToken.IsRevoked = true;
            storedRefreshToken.RevokedAt = DateTime.UtcNow;

            if (requestDto.IsLogoutFromAllDevices)
            {
                // Revoke all refresh tokens for the user
                // This is useful if you want to logout the user from all other devices.
                var userRefreshTokens = await _context.RefreshTokens
                    .Where(rt => rt.UserId == storedRefreshToken.UserId && !rt.IsRevoked)
                    .ToListAsync();

                foreach (var token in userRefreshTokens)
                {
                    token.IsRevoked = true;
                    token.RevokedAt = DateTime.UtcNow;
                }
            }

            //foreach (var token in userRefreshTokens)
            //{
            //    token.IsRevoked = true;
            //    token.RevokedAt = DateTime.UtcNow;
            //}

            // Persists the changes to the database.
            await _context.SaveChangesAsync();

            // Returns a success message upon successful revocation.
            return Ok(new
            {
                Message = "Logout successful. Refresh token has been revoked."
            });
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDTO requestDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            // Hash the incoming refresh token to compare with stored hash
            var hashedToken = HashToken(requestDto.RefreshToken);
            // Check if the refresh token exists and matches the provided ClientId.
            // Retrieve the refresh token from the database
            var storedRefreshToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                    .ThenInclude(u => u.UserRoles)
                        .ThenInclude(ur => ur.Role)
                .Include(rt => rt.Client)
                .FirstOrDefaultAsync(rt => rt.Token == hashedToken && rt.Client.ClientId == requestDto.ClientId);
            if (storedRefreshToken == null)
            {
                return Unauthorized("Invalid refresh token.");
            }
            // Ensure the token hasn't been revoked.
            if (storedRefreshToken.IsRevoked)
            {
                return Unauthorized("Refresh token has been revoked.");
            }
            // Ensure the token hasn't expired.
            if (storedRefreshToken.ExpiresAt < DateTime.UtcNow)
            {
                return Unauthorized("Refresh token has expired.");
            }
            // Retrieve the user and client
            var user = storedRefreshToken.User;
            var client = storedRefreshToken.Client;
            // The existing refresh token is marked as revoked to prevent reuse.
            storedRefreshToken.IsRevoked = true;
            storedRefreshToken.RevokedAt = DateTime.UtcNow;
            // Generate a new refresh token
            var newRefreshToken = GenerateRefreshToken();
            var hashedNewRefreshToken = HashToken(newRefreshToken);
            var newRefreshTokenEntity = new RefreshToken
            {
                Token = hashedNewRefreshToken,
                UserId = user.Id,
                ClientId = client.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(7), // Adjust as needed
                CreatedAt = DateTime.UtcNow,
                IsRevoked = false
            };
            // Store the new refresh token
            _context.RefreshTokens.Add(newRefreshTokenEntity);
            // Generate new JWT access token
            var newJwtToken = GenerateJwtToken(user, client);
            // Save changes to the database
            await _context.SaveChangesAsync();
            // Return the new tokens to the client
            return Ok(new TokenResponseDTO
            {
                Token = newJwtToken,
                RefreshToken = newRefreshToken
            });
        }
        // Private method responsible for generating a JWT token for an authenticated user

        // Helper method to generate a secure random refresh token
        private string GenerateRefreshToken()
        {
            //A secure random string is generated using RandomNumberGenerator
            var randomNumber = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }


        // Helper method to hash tokens before storing them
        private string HashToken(string token)
        {
            //The refresh token is hashed using SHA256 before storing it in the database to prevent token theft from compromising security.
            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(hashedBytes);
        }
    }
}