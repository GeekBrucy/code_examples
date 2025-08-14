namespace API.Models;

public class PollingResponse
{
    public bool HasUpdates { get; set; }
    public DateTime LastModified { get; set; }
    public List<UpdateItem> Data { get; set; } = new();
    public int NextPollAfterSeconds { get; set; } = 300; // 5 minutes default
    public string? NextCursor { get; set; } // Cursor for next poll to prevent data loss
}

public class UpdateItem
{
    public string Id { get; set; } = string.Empty;
    public long SequenceNumber { get; set; } // Include sequence for debugging/verification
    public string Type { get; set; } = string.Empty;
    public object Content { get; set; } = new();
    public DateTime Timestamp { get; set; }
    public string Source { get; set; } = string.Empty;
    public int Priority { get; set; }
}