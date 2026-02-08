using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using file_upload_sftp.Models;
using file_upload_sftp.Settings;
using Microsoft.Extensions.Options;
using Renci.SshNet;

namespace file_upload_sftp.Services;

public interface ISftpDeliveryService
{
    Task DeliverAsync(OutboxEntry entry, CancellationToken ct = default);
}

public sealed class SftpDeliveryService : ISftpDeliveryService
{
    private readonly SftpOptions _sftp;
    private readonly ILogger<SftpDeliveryService> _log;

    public SftpDeliveryService(IOptions<SftpOptions> sftp, ILogger<SftpDeliveryService> log)
    {
        _sftp = sftp.Value;
        _log = log;
    }

    public async Task DeliverAsync(OutboxEntry entry, CancellationToken ct = default)
    {
        await Task.Run(() =>
        {
            using var client = new SftpClient(_sftp.Host, _sftp.Port, _sftp.Username, _sftp.Password);
            client.Connect();
            try
            {
                var remoteDir = $"/outbound/{entry.PartnerId}/{entry.RecordId}";
                EnsureDirectoryExists(client, remoteDir);

                var uploadedPendingFiles = new List<string>();

                // Phase 1: Upload all files with .pending suffix
                foreach (var file in entry.Files)
                {
                    var pendingPath = $"{remoteDir}/{file.FileName}.pending";
                    using var ms = new MemoryStream(file.Content);
                    client.UploadFile(ms, pendingPath, canOverride: true);
                    uploadedPendingFiles.Add(pendingPath);

                    _log.LogInformation(
                        "Uploaded pending file Record={RecordId} Partner={PartnerId} File={FileName} Size={Size}",
                        entry.RecordId, entry.PartnerId, file.FileName, file.Content.Length);
                }

                // Phase 2: Generate and upload manifest with .pending suffix
                var manifest = BuildManifest(entry);
                var manifestPendingPath = $"{remoteDir}/_manifest.json.pending";
                using (var manifestStream = new MemoryStream(Encoding.UTF8.GetBytes(manifest)))
                {
                    client.UploadFile(manifestStream, manifestPendingPath, canOverride: true);
                }
                uploadedPendingFiles.Add(manifestPendingPath);

                // Phase 3: Rename all files to final names (atomic commit)
                foreach (var pendingPath in uploadedPendingFiles)
                {
                    var finalPath = pendingPath[..^".pending".Length]; // strip .pending
                    if (client.Exists(finalPath))
                        client.DeleteFile(finalPath);
                    client.RenameFile(pendingPath, finalPath);
                }

                _log.LogInformation(
                    "Delivery complete Record={RecordId} Partner={PartnerId} FileCount={FileCount}",
                    entry.RecordId, entry.PartnerId, entry.Files.Count);
            }
            catch
            {
                // Best-effort cleanup of .pending files on failure
                CleanupPendingFiles(client, entry);
                throw;
            }
            finally
            {
                if (client.IsConnected) client.Disconnect();
            }
        }, ct);
    }

    private string BuildManifest(OutboxEntry entry)
    {
        var manifest = new
        {
            recordId = entry.RecordId,
            partnerId = entry.PartnerId,
            uploadedAt = DateTime.UtcNow.ToString("o"),
            files = entry.Files.Select(f => new
            {
                name = f.FileName,
                size = f.Content.Length,
                contentType = f.ContentType,
                sha256 = Convert.ToHexString(SHA256.HashData(f.Content)).ToLowerInvariant()
            }).ToList()
        };

        return JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
    }

    private void CleanupPendingFiles(SftpClient client, OutboxEntry entry)
    {
        if (!client.IsConnected) return;

        var remoteDir = $"/outbound/{entry.PartnerId}/{entry.RecordId}";
        try
        {
            if (!client.Exists(remoteDir)) return;

            foreach (var file in client.ListDirectory(remoteDir))
            {
                if (file.Name.EndsWith(".pending"))
                {
                    client.DeleteFile(file.FullName);
                    _log.LogWarning(
                        "Cleaned up pending file Record={RecordId} Partner={PartnerId} File={File}",
                        entry.RecordId, entry.PartnerId, file.Name);
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex,
                "Failed to cleanup pending files Record={RecordId} Partner={PartnerId}",
                entry.RecordId, entry.PartnerId);
        }
    }

    private static void EnsureDirectoryExists(SftpClient client, string remoteDir)
    {
        var parts = remoteDir.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var path = "/";
        foreach (var part in parts)
        {
            path = path == "/" ? "/" + part : path + "/" + part;
            try
            {
                if (!client.Exists(path))
                    client.CreateDirectory(path);
            }
            catch (Renci.SshNet.Common.SshException)
            {
                // Race condition: another process created it between Exists and Create
                if (!client.Exists(path)) throw;
            }
        }
    }
}
