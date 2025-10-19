namespace API.Models;

/// <summary>
/// Entity representing an audit log entry for certificate authentication attempts.
/// This demonstrates a real-world entity that would be persisted to a database.
/// </summary>
public class CertificateAuditLog
{
    public int Id { get; set; }

    public required string CertificateSubject { get; set; }

    public required string CertificateThumbprint { get; set; }

    public string? IssuerName { get; set; }

    public DateTime AuthenticationTime { get; set; }

    public bool IsSuccessful { get; set; }

    public string? FailureReason { get; set; }

    public string? IpAddress { get; set; }

    public string? Endpoint { get; set; }

    public DateTime? CertificateNotBefore { get; set; }

    public DateTime? CertificateNotAfter { get; set; }
}
