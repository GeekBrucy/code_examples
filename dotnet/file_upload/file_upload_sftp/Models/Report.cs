namespace file_upload_sftp.Models;

/// <summary>
/// Represents an existing report in the system.
/// In the real app, this already exists in the WebAPI's database.
/// </summary>
public class Report
{
    public int Id { get; set; }
    public required string Title { get; set; }
    public required string Status { get; set; } // Draft, Submitted, Finalised
    public required string JsonContent { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? FinalisedAt { get; set; }

    public List<ReportAttachment> Attachments { get; set; } = [];
    public List<ReportReferral> Referrals { get; set; } = [];
}

/// <summary>
/// Binary attachment stored in DB (mirrors existing system design).
/// </summary>
public class ReportAttachment
{
    public int Id { get; set; }
    public int ReportId { get; set; }
    public required string FileName { get; set; }
    public required string ContentType { get; set; }
    public required byte[] Content { get; set; }

    public Report Report { get; set; } = null!;
}

/// <summary>
/// Links a finalised report to an external user who should receive it.
/// </summary>
public class ReportReferral
{
    public int Id { get; set; }
    public int ReportId { get; set; }
    public int ExternalUserId { get; set; }
    public DateTime ReferredAt { get; set; } = DateTime.UtcNow;

    public Report Report { get; set; } = null!;
    public ExternalUser ExternalUser { get; set; } = null!;
}

/// <summary>
/// An external user who has an SFTP directory.
/// </summary>
public class ExternalUser
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public required string SftpDirectory { get; set; } // e.g. "partnerA"
}
