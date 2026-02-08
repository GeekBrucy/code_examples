namespace file_upload_sftp.Models;

public class OutboxFile
{
    public int Id { get; set; }
    public int OutboxEntryId { get; set; }
    public required string FileName { get; set; }
    public required byte[] Content { get; set; }
    public required string ContentType { get; set; }

    public OutboxEntry OutboxEntry { get; set; } = null!;
}
