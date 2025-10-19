using System.Security.Cryptography.X509Certificates;

namespace API.Services;

/// <summary>
/// Service for validating client certificates against a trusted certificate chain
/// without requiring system-wide installation of CA certificates.
/// </summary>
public interface ICertificateValidationService
{
    /// <summary>
    /// Validates a client certificate against the configured trusted CA chain.
    /// </summary>
    /// <param name="clientCertificate">The client certificate to validate</param>
    /// <param name="chain">The X509 certificate chain (can be null)</param>
    /// <returns>True if the certificate is valid and trusted; otherwise false</returns>
    bool ValidateCertificate(X509Certificate2 clientCertificate, X509Chain? chain);

    /// <summary>
    /// Gets detailed validation results including any errors or warnings.
    /// </summary>
    /// <param name="clientCertificate">The client certificate to validate</param>
    /// <returns>Validation result with detailed status information</returns>
    CertificateValidationResult ValidateWithDetails(X509Certificate2 clientCertificate);
}

/// <summary>
/// Represents the result of certificate validation with detailed information.
/// </summary>
public class CertificateValidationResult
{
    public bool IsValid { get; set; }
    public List<string> Errors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public string? SubjectName { get; set; }
    public string? IssuerName { get; set; }
    public DateTime? NotBefore { get; set; }
    public DateTime? NotAfter { get; set; }
    public bool ChainIsValid { get; set; }
    public List<string> ChainStatus { get; set; } = new();
}
