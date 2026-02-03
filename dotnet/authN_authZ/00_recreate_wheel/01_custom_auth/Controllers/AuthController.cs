using System.Diagnostics;
using _01_custom_auth.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace _01_custom_auth.Controllers
{
    [Route("[controller]")]
    public class AuthController : Controller
    {
        private readonly AuthService _auth;
        public record RegisterRequest(string Email, string Password);

        public AuthController(AuthService auth)
        {
            _auth = auth;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken ct)
        {
            try
            {
                var userId = await _auth.RegisterAsync(request.Email, request.Password, ct);
                return Ok(new { userId });
            }
            catch (ArgumentException ex)
            {

                return BadRequest(new { error = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(new { error = ex.Message });
            }
        }

    }
}