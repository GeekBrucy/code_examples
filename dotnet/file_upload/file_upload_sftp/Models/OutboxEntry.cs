namespace file_upload_sftp.Models;

public enum DeliveryStatus
{
    Pending,
    InProgress,
    Completed,
    Failed
}

/// <summary>
/// One row per (report, external user) delivery.
/// Stores references only — report data is read from the Report tables at delivery time.
/// </summary>
public class OutboxEntry
{
    public int Id { get; set; }
    public int ReportId { get; set; }
    public int ExternalUserId { get; set; }
    public DeliveryStatus Status { get; set; } = DeliveryStatus.Pending;
    public int Attempts { get; set; }
    public int MaxAttempts { get; set; } = 5;
    public string? LastError { get; set; }
    public DateTime? NextRetryAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }
}
