using file_upload_sftp.Data;
using file_upload_sftp.Dtos;
using file_upload_sftp.Models;
using file_upload_sftp.Settings;
using Microsoft.Extensions.Options;

namespace file_upload_sftp.Services;

public interface IDistributionService
{
    Task<List<int>> EnqueueAsync(DistributionRequest request, CancellationToken ct = default);
}

public sealed class DistributionService : IDistributionService
{
    private readonly OutboxDbContext _db;
    private readonly OutboxOptions _options;
    private readonly ILogger<DistributionService> _log;

    public DistributionService(OutboxDbContext db, IOptions<OutboxOptions> options, ILogger<DistributionService> log)
    {
        _db = db;
        _options = options.Value;
        _log = log;
    }

    public async Task<List<int>> EnqueueAsync(DistributionRequest request, CancellationToken ct = default)
    {
        if (request.PartnerIds.Count == 0)
            throw new ArgumentException("At least one partner is required.");
        if (request.Files.Count == 0)
            throw new ArgumentException("At least one file is required.");

        var entryIds = new List<int>();

        foreach (var partnerId in request.PartnerIds)
        {
            var entry = new OutboxEntry
            {
                RecordId = request.RecordId,
                PartnerId = partnerId,
                MaxAttempts = _options.MaxAttempts,
                NextRetryAt = DateTime.UtcNow,
                Files = request.Files.Select(f => new OutboxFile
                {
                    FileName = Path.GetFileName(f.Name), // sanitize
                    Content = Convert.FromBase64String(f.ContentBase64),
                    ContentType = f.ContentType
                }).ToList()
            };

            _db.OutboxEntries.Add(entry);
            await _db.SaveChangesAsync(ct);
            entryIds.Add(entry.Id);

            _log.LogInformation(
                "Enqueued delivery for Record={RecordId} Partner={PartnerId} Files={FileCount} OutboxId={OutboxId}",
                request.RecordId, partnerId, request.Files.Count, entry.Id);
        }

        return entryIds;
    }
}
