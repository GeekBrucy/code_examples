using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using file_upload_sftp.Data;
using file_upload_sftp.Models;
using file_upload_sftp.Settings;
using Microsoft.EntityFrameworkCore;
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
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<SftpDeliveryService> _log;

    public SftpDeliveryService(
        IOptions<SftpOptions> sftp,
        IServiceScopeFactory scopeFactory,
        ILogger<SftpDeliveryService> log)
    {
        _sftp = sftp.Value;
        _scopeFactory = scopeFactory;
        _log = log;
    }

    public async Task DeliverAsync(OutboxEntry entry, CancellationToken ct = default)
    {
        // Read report + attachments from the existing database
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var report = await db.Reports
            .Include(r => r.Attachments)
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == entry.ReportId, ct)
            ?? throw new InvalidOperationException($"Report {entry.ReportId} not found — may have been deleted.");

        var externalUser = await db.ExternalUsers
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == entry.ExternalUserId, ct)
            ?? throw new InvalidOperationException($"External user {entry.ExternalUserId} not found.");

        var sftpDir = externalUser.SftpDirectory;

        await Task.Run(() =>
        {
            using var client = new SftpClient(_sftp.Host, _sftp.Port, _sftp.Username, _sftp.Password);
            client.Connect();
            try
            {
                var remoteDir = $"/outbound/{sftpDir}/report_{report.Id}";
                EnsureDirectoryExists(client, remoteDir);

                var uploadedPendingFiles = new List<string>();
                var manifestFiles = new List<ManifestFileEntry>();

                // Phase 1: Upload report JSON with .pending suffix
                var reportBytes = Encoding.UTF8.GetBytes(report.JsonContent);
                var reportFileName = $"report_{report.Id}.json";
                var reportPendingPath = $"{remoteDir}/{reportFileName}.pending";
                using (var ms = new MemoryStream(reportBytes))
                {
                    client.UploadFile(ms, reportPendingPath, canOverride: true);
                }
                uploadedPendingFiles.Add(reportPendingPath);
                manifestFiles.Add(new ManifestFileEntry(reportFileName, reportBytes.Length, "application/json",
                    Convert.ToHexString(SHA256.HashData(reportBytes)).ToLowerInvariant()));

                _log.LogInformation(
                    "Uploaded pending report Report={ReportId} User={UserId} SftpDir={SftpDir} File={FileName} Size={Size}",
                    report.Id, entry.ExternalUserId, sftpDir, reportFileName, reportBytes.Length);

                // Phase 2: Upload each attachment with .pending suffix
                foreach (var attachment in report.Attachments)
                {
                    var pendingPath = $"{remoteDir}/{attachment.FileName}.pending";
                    using var ms = new MemoryStream(attachment.Content);
                    client.UploadFile(ms, pendingPath, canOverride: true);
                    uploadedPendingFiles.Add(pendingPath);
                    manifestFiles.Add(new ManifestFileEntry(attachment.FileName, attachment.Content.Length, attachment.ContentType,
                        Convert.ToHexString(SHA256.HashData(attachment.Content)).ToLowerInvariant()));

                    _log.LogInformation(
                        "Uploaded pending attachment Report={ReportId} User={UserId} File={FileName} Size={Size}",
                        report.Id, entry.ExternalUserId, attachment.FileName, attachment.Content.Length);
                }

                // Phase 3: Generate and upload manifest with .pending suffix
                var manifest = BuildManifest(report.Id, sftpDir, manifestFiles);
                var manifestPendingPath = $"{remoteDir}/_manifest.json.pending";
                using (var manifestStream = new MemoryStream(Encoding.UTF8.GetBytes(manifest)))
                {
                    client.UploadFile(manifestStream, manifestPendingPath, canOverride: true);
                }
                uploadedPendingFiles.Add(manifestPendingPath);

                // Phase 4: Rename all .pending files to final names (atomic commit)
                foreach (var pendingPath in uploadedPendingFiles)
                {
                    var finalPath = pendingPath[..^".pending".Length];
                    if (client.Exists(finalPath))
                        client.DeleteFile(finalPath);
                    client.RenameFile(pendingPath, finalPath);
                }

                _log.LogInformation(
                    "Delivery complete Report={ReportId} User={UserId} SftpDir={SftpDir} FileCount={FileCount}",
                    report.Id, entry.ExternalUserId, sftpDir, 1 + report.Attachments.Count);
            }
            catch
            {
                CleanupPendingFiles(client, report.Id, sftpDir);
                throw;
            }
            finally
            {
                if (client.IsConnected) client.Disconnect();
            }
        }, ct);
    }

    internal record ManifestFileEntry(string Name, long Size, string ContentType, string Sha256);

    internal static string BuildManifest(int reportId, string sftpDir, List<ManifestFileEntry> files)
    {
        var manifest = new
        {
            reportId,
            sftpDirectory = sftpDir,
            uploadedAt = DateTime.UtcNow.ToString("o"),
            files = files.Select(f => new
            {
                name = f.Name,
                size = f.Size,
                contentType = f.ContentType,
                sha256 = f.Sha256
            }).ToList()
        };

        return JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
    }

    private void CleanupPendingFiles(SftpClient client, int reportId, string sftpDir)
    {
        if (!client.IsConnected) return;

        var remoteDir = $"/outbound/{sftpDir}/report_{reportId}";
        try
        {
            if (!client.Exists(remoteDir)) return;

            foreach (var file in client.ListDirectory(remoteDir))
            {
                if (file.Name.EndsWith(".pending"))
                {
                    client.DeleteFile(file.FullName);
                    _log.LogWarning(
                        "Cleaned up pending file Report={ReportId} SftpDir={SftpDir} File={File}",
                        reportId, sftpDir, file.Name);
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex,
                "Failed to cleanup pending files Report={ReportId} SftpDir={SftpDir}",
                reportId, sftpDir);
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
                if (!client.Exists(path)) throw;
            }
        }
    }
}
