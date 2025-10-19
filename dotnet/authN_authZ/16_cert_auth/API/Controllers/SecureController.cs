using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using API.Services;

namespace API.Controllers;

/// <summary>
/// Controller demonstrating certificate authentication for secured endpoints.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class SecureController : ControllerBase
{
    private readonly ILogger<SecureController> _logger;
    private readonly ICertificateValidationService _certValidationService;

    public SecureController(
        ILogger<SecureController> logger,
        ICertificateValidationService certValidationService)
    {
        _logger = logger;
        _certValidationService = certValidationService;
    }

    /// <summary>
    /// Public endpoint - no authentication required.
    /// </summary>
    [HttpGet("public")]
    public IActionResult GetPublicData()
    {
        return Ok(new
        {
            message = "This is a public endpoint - no certificate required",
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Protected endpoint - requires valid client certificate.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Certificate")]
    [HttpGet("protected")]
    public IActionResult GetProtectedData()
    {
        // The [Authorize] attribute with Certificate scheme ensures that:
        // 1. A client certificate was provided
        // 2. The certificate passed validation (our custom validation service)
        // 3. The user is authenticated before reaching this code

        var clientCert = HttpContext.Connection.ClientCertificate;

        // This null check is defensive - should not happen after [Authorize] passes
        if (clientCert == null)
        {
            return Unauthorized(new { message = "No client certificate provided" });
        }

        return Ok(new
        {
            message = "This is a protected endpoint - valid certificate required",
            clientInfo = new
            {
                subject = clientCert.Subject,
                issuer = clientCert.Issuer,
                thumbprint = clientCert.Thumbprint,
                notBefore = clientCert.NotBefore,
                notAfter = clientCert.NotAfter
            },
            claims = User.Claims.Select(c => new { c.Type, c.Value }),
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Endpoint to validate a certificate and return detailed validation results.
    /// </summary>
    [HttpGet("validate")]
    public IActionResult ValidateCertificate()
    {
        var clientCert = HttpContext.Connection.ClientCertificate;

        if (clientCert == null)
        {
            return BadRequest(new
            {
                message = "No client certificate provided",
                tip = "Ensure you're sending a client certificate with the request"
            });
        }

        var validationResult = _certValidationService.ValidateWithDetails(clientCert);

        return Ok(new
        {
            isValid = validationResult.IsValid,
            certificate = new
            {
                subject = validationResult.SubjectName,
                issuer = validationResult.IssuerName,
                notBefore = validationResult.NotBefore,
                notAfter = validationResult.NotAfter,
                thumbprint = clientCert.Thumbprint
            },
            validation = new
            {
                chainIsValid = validationResult.ChainIsValid,
                errors = validationResult.Errors,
                warnings = validationResult.Warnings,
                chainStatus = validationResult.ChainStatus
            },
            timestamp = DateTime.UtcNow
        });
    }

    /// <summary>
    /// Endpoint demonstrating role-based authorization with certificates.
    /// In a real application, you would extract roles from certificate attributes.
    /// </summary>
    [Authorize(AuthenticationSchemes = "Certificate")]
    [HttpGet("admin")]
    public IActionResult GetAdminData()
    {
        var clientCert = HttpContext.Connection.ClientCertificate;

        // In a real scenario, you might check certificate attributes for roles
        // For example: OU (Organizational Unit) or custom certificate extensions
        var organizationalUnit = GetOrganizationalUnit(clientCert);

        if (organizationalUnit != "Admin")
        {
            return Forbid();
        }

        return Ok(new
        {
            message = "This is an admin endpoint - requires admin certificate",
            clientInfo = new
            {
                subject = clientCert?.Subject,
                organizationalUnit = organizationalUnit
            },
            timestamp = DateTime.UtcNow
        });
    }

    private string GetOrganizationalUnit(X509Certificate2? certificate)
    {
        if (certificate == null) return string.Empty;

        // Parse OU from certificate subject
        // Subject format: CN=..., OU=..., O=..., etc.
        var subject = certificate.Subject;
        var parts = subject.Split(',')
            .Select(p => p.Trim())
            .FirstOrDefault(p => p.StartsWith("OU=", StringComparison.OrdinalIgnoreCase));

        return parts?.Substring(3) ?? string.Empty;
    }
}
