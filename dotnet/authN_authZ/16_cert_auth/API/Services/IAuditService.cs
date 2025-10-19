using API.Models;

namespace API.Services;

/// <summary>
/// Service interface for auditing certificate authentication attempts.
/// This demonstrates a typical service layer interface that would be injected into controllers.
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Logs a successful certificate authentication.
    /// </summary>
    Task LogSuccessfulAuthenticationAsync(
        string certificateSubject,
        string certificateThumbprint,
        string? issuerName,
        string? ipAddress,
        string? endpoint);

    /// <summary>
    /// Logs a failed certificate authentication attempt.
    /// </summary>
    Task LogFailedAuthenticationAsync(
        string certificateSubject,
        string certificateThumbprint,
        string? issuerName,
        string failureReason,
        string? ipAddress,
        string? endpoint);

    /// <summary>
    /// Gets audit logs for a specific certificate thumbprint.
    /// </summary>
    Task<List<CertificateAuditLog>> GetAuditLogsByThumbprintAsync(string thumbprint);

    /// <summary>
    /// Gets recent audit logs (last N entries).
    /// </summary>
    Task<List<CertificateAuditLog>> GetRecentAuditLogsAsync(int count = 100);

    /// <summary>
    /// Gets failed authentication attempts within a time window.
    /// Useful for detecting potential security threats.
    /// </summary>
    Task<List<CertificateAuditLog>> GetFailedAttemptsAsync(DateTime since);
}
