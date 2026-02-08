namespace file_upload_sftp.Models;

public enum DeliveryStatus
{
    Pending,
    InProgress,
    Completed,
    Failed
}

public class OutboxEntry
{
    public int Id { get; set; }
    public required string RecordId { get; set; }
    public required string PartnerId { get; set; }
    public DeliveryStatus Status { get; set; } = DeliveryStatus.Pending;
    public int Attempts { get; set; }
    public int MaxAttempts { get; set; } = 5;
    public string? LastError { get; set; }
    public DateTime? NextRetryAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }

    public List<OutboxFile> Files { get; set; } = [];
}
