namespace file_upload_sftp_consumer.Models;

public sealed class SftpFileInfo
{
    public required string Name { get; init; }
    public long Size { get; init; }
    public DateTime LastModified { get; init; }
}
