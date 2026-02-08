using file_upload_sftp_consumer.Models;
using file_upload_sftp_consumer.Settings;
using Microsoft.Extensions.Options;
using Renci.SshNet;

namespace file_upload_sftp_consumer.Services;

public interface ISftpBrowserService
{
    IReadOnlyList<string> GetPartnerIds();
    Task<List<SftpFileInfo>> ListFilesAsync(string partnerId, CancellationToken ct = default);
    Task<(MemoryStream Content, string FileName)> DownloadFileAsync(string partnerId, string fileName, CancellationToken ct = default);
}

public sealed class SftpBrowserService : ISftpBrowserService
{
    private readonly SftpHostOptions _host;
    private readonly IReadOnlyDictionary<string, PartnerCredentials> _partners;
    private readonly ILogger<SftpBrowserService> _log;

    public SftpBrowserService(
        IOptions<SftpHostOptions> host,
        IReadOnlyDictionary<string, PartnerCredentials> partners,
        ILogger<SftpBrowserService> log)
    {
        _host = host.Value;
        _partners = partners;
        _log = log;
    }

    public IReadOnlyList<string> GetPartnerIds() => _partners.Keys.ToList();

    public async Task<List<SftpFileInfo>> ListFilesAsync(string partnerId, CancellationToken ct = default)
    {
        var creds = GetCredentials(partnerId);

        return await Task.Run(() =>
        {
            using var client = new SftpClient(_host.Host, _host.Port, creds.Username, creds.Password);
            client.Connect();
            try
            {
                var remotePath = "/outbound";
                if (!client.Exists(remotePath))
                    return new List<SftpFileInfo>();

                return client.ListDirectory(remotePath)
                    .Where(f => !f.IsDirectory && f.Name != "." && f.Name != "..")
                    .Select(f => new SftpFileInfo
                    {
                        Name = f.Name,
                        Size = f.Length,
                        LastModified = f.LastWriteTime
                    })
                    .OrderByDescending(f => f.LastModified)
                    .ToList();
            }
            finally
            {
                if (client.IsConnected) client.Disconnect();
            }
        }, ct);
    }

    public async Task<(MemoryStream Content, string FileName)> DownloadFileAsync(
        string partnerId, string fileName, CancellationToken ct = default)
    {
        var creds = GetCredentials(partnerId);

        // Sanitize filename to prevent path traversal
        var safeName = Path.GetFileName(fileName);
        if (string.IsNullOrWhiteSpace(safeName))
            throw new ArgumentException("Invalid file name.");

        return await Task.Run(() =>
        {
            using var client = new SftpClient(_host.Host, _host.Port, creds.Username, creds.Password);
            client.Connect();
            try
            {
                var remotePath = $"/outbound/{safeName}";
                if (!client.Exists(remotePath))
                    throw new FileNotFoundException($"File not found: {safeName}");

                var ms = new MemoryStream();
                client.DownloadFile(remotePath, ms);
                ms.Position = 0;
                return (ms, safeName);
            }
            finally
            {
                if (client.IsConnected) client.Disconnect();
            }
        }, ct);
    }

    private PartnerCredentials GetCredentials(string partnerId)
    {
        if (!_partners.TryGetValue(partnerId, out var creds))
            throw new ArgumentException($"Unknown partner: {partnerId}");
        return creds;
    }
}
