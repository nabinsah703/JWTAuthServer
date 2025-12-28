using JWTAuthServer.Data;
using JWTAuthServer.DTOs;
using JWTAuthServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        // Constructor injecting the ApplicationDbContext
        public UsersController(ApplicationDbContext context)
        {
            _context = context;
        }

        // Registers a new user.
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDto)
        {
            // Validate the incoming model.
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Check if the email already exists.
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == registerDto.Email.ToLower());

            if (existingUser != null)
            {
                return Conflict(new { message = "Email is already registered." });
            }

            // Hash the password using BCrypt.
            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(registerDto.Password);

            // Create a new user entity.
            var newUser = new User
            {
                Firstname = registerDto.Firstname,
                Lastname = registerDto.Lastname,
                Email = registerDto.Email,
                Password = hashedPassword
            };

            // Add the new user to the database.
            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            // Optionally, assign a default role to the new user.
            // For example, assign the "User" role.
            var userRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "User");
            if (userRole != null)
            {
                var newUserRole = new UserRole
                {
                    UserId = newUser.Id,
                    RoleId = userRole.Id
                };
                _context.UserRoles.Add(newUserRole);
                await _context.SaveChangesAsync();
            }

            return CreatedAtAction(nameof(GetProfile), new { id = newUser.Id }, new { message = "User registered successfully." });
        }

        // Retrieves the authenticated user's profile.
        [HttpGet("GetProfile")]
        [Authorize]
        public async Task<IActionResult> GetProfile()
        {
            // Extract the user's email from the JWT token claims.
            var emailClaim = User.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Email);
            if (emailClaim == null)
            {
                return Unauthorized(new { message = "Invalid token: Email claim missing." });
            }

            string userEmail = emailClaim.Value;

            // Retrieve the user from the database, including roles.
            var user = await _context.Users
                .Include(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => u.Email.ToLower() == userEmail.ToLower());

            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            // Map the user entity to ProfileDTO.
            var profile = new ProfileDTO
            {
                Id = user.Id,
                Email = user.Email,
                Firstname = user.Firstname,
                Lastname = user.Lastname,
                Roles = user.UserRoles.Select(ur => ur.Role.Name).ToList()
            };

            return Ok(profile);
        }

        // Updates the authenticated user's profile.
        [HttpPut("UpdateProfile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileDTO updateDto)
        {
            // Validate the incoming model.
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Extract the user's email from the JWT token claims.
            var emailClaim = User.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Email);
            if (emailClaim == null)
            {
                return Unauthorized(new { message = "Invalid token: Email claim missing." });
            }

            string userEmail = emailClaim.Value;

            // Retrieve the user from the database.
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == userEmail.ToLower());

            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            // Update fields if provided.
            if (!string.IsNullOrEmpty(updateDto.Firstname))
            {
                user.Firstname = updateDto.Firstname;
            }

            if (!string.IsNullOrEmpty(updateDto.Lastname))
            {
                user.Lastname = updateDto.Lastname;
            }

            if (!string.IsNullOrEmpty(updateDto.Email))
            {
                // Check if the new email is already taken by another user.
                var emailExists = await _context.Users
                    .AnyAsync(u => u.Email.ToLower() == updateDto.Email.ToLower() && u.Id != user.Id);

                if (emailExists)
                {
                    return Conflict(new { message = "Email is already in use by another account." });
                }

                user.Email = updateDto.Email;
            }

            if (!string.IsNullOrEmpty(updateDto.Password))
            {
                // Hash the new password before storing.
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(updateDto.Password);
                user.Password = hashedPassword;
            }

            // Save the changes to the database.
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Profile updated successfully." });
        }
    }
}