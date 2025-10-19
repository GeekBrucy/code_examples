using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

/// <summary>
/// Controller demonstrating the difference between [Authorize] and [Authorize(AuthenticationSchemes = "...")]
/// This is for educational purposes to show when scheme specification matters.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthSchemeComparisonController : ControllerBase
{
    private readonly ILogger<AuthSchemeComparisonController> _logger;

    public AuthSchemeComparisonController(ILogger<AuthSchemeComparisonController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Endpoint using [Authorize] without specifying a scheme.
    /// Currently works because only Certificate auth is configured.
    /// BUT: If you add JWT/Cookie auth later, this would accept those too!
    /// </summary>
    [Authorize]
    [HttpGet("any-auth")]
    public IActionResult AnyAuthenticationAccepted()
    {
        _logger.LogInformation("AnyAuthenticationAccepted called");

        return Ok(new
        {
            message = "This endpoint uses [Authorize] without a scheme",
            behavior = "Currently accepts only Certificate auth (because that's all we configured)",
            warning = "If you add JWT/Cookie auth later, this endpoint would accept those too!",
            authenticationType = User.Identity?.AuthenticationType,
            isAuthenticated = User.Identity?.IsAuthenticated,
            claims = User.Claims.Select(c => new { c.Type, c.Value })
        });
    }

    /// <summary>
    /// Endpoint explicitly requiring Certificate authentication.
    /// Will ONLY accept certificate auth, even if other schemes are added later.
    /// This is the secure, explicit approach.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Certificate")]
    [HttpGet("certificate-only")]
    public IActionResult CertificateAuthenticationOnly()
    {
        _logger.LogInformation("CertificateAuthenticationOnly called");

        var clientCert = HttpContext.Connection.ClientCertificate;

        return Ok(new
        {
            message = "This endpoint uses [Authorize(AuthenticationSchemes = \"Certificate\")]",
            behavior = "Only accepts Certificate authentication, now and forever",
            guarantee = "Even if you add JWT/Cookie auth, this endpoint will ONLY accept certificates",
            authenticationType = User.Identity?.AuthenticationType,
            isAuthenticated = User.Identity?.IsAuthenticated,
            certificateSubject = clientCert?.Subject,
            claims = User.Claims.Select(c => new { c.Type, c.Value })
        });
    }

    /// <summary>
    /// Demonstrates what happens with no authentication.
    /// Compare the HTTP status codes:
    /// - /any-auth without cert: 401 Unauthorized
    /// - /certificate-only without cert: 403 Forbidden
    /// </summary>
    [HttpGet("public")]
    public IActionResult NoAuthRequired()
    {
        return Ok(new
        {
            message = "This endpoint has no [Authorize] attribute",
            behavior = "Anyone can access this, no authentication required",
            isAuthenticated = User.Identity?.IsAuthenticated ?? false,
            tip = "Try calling /any-auth and /certificate-only without a certificate to see different status codes"
        });
    }

    /// <summary>
    /// Example of accepting multiple authentication schemes.
    /// Useful for migration scenarios or multi-client APIs.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Certificate,Bearer")]
    [HttpGet("multi-auth")]
    public IActionResult MultipleAuthenticationSchemes()
    {
        // Note: This will return 403 until we add Bearer (JWT) authentication
        // Demonstrates that you can specify multiple schemes

        return Ok(new
        {
            message = "This endpoint accepts Certificate OR Bearer (JWT) authentication",
            behavior = "Multiple schemes separated by comma",
            note = "Will return 403 until Bearer auth is configured",
            authenticationType = User.Identity?.AuthenticationType,
            isAuthenticated = User.Identity?.IsAuthenticated
        });
    }
}
