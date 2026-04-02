namespace Api.Services;

public interface ISftpClient
{
    Task UploadAsync(Stream content, string remotePath, CancellationToken ct = default);
}
