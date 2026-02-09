using file_upload_sftp.Data;
using file_upload_sftp.Models;
using file_upload_sftp.Settings;
using Hangfire;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace file_upload_sftp.Services;

public interface IDistributionService
{
    /// <summary>
    /// Called during finalization: enqueue SFTP delivery for all referred external users.
    /// </summary>
    Task<List<int>> EnqueueForFinalisedReportAsync(int reportId, CancellationToken ct = default);

    /// <summary>
    /// Called for manual refer: enqueue SFTP delivery for specific external users.
    /// </summary>
    Task<List<int>> EnqueueForExternalUsersAsync(int reportId, List<int> externalUserIds, CancellationToken ct = default);
}

public sealed class DistributionService : IDistributionService
{
    private readonly AppDbContext _db;
    private readonly OutboxOptions _options;
    private readonly ILogger<DistributionService> _log;

    public DistributionService(AppDbContext db, IOptions<OutboxOptions> options, ILogger<DistributionService> log)
    {
        _db = db;
        _options = options.Value;
        _log = log;
    }

    public async Task<List<int>> EnqueueForFinalisedReportAsync(int reportId, CancellationToken ct = default)
    {
        var report = await _db.Reports
            .Include(r => r.Referrals)
            .FirstOrDefaultAsync(r => r.Id == reportId, ct)
            ?? throw new ArgumentException($"Report {reportId} not found.");

        if (report.Status != "Finalised")
            throw new InvalidOperationException($"Report {reportId} is '{report.Status}', not 'Finalised'.");

        var externalUserIds = report.Referrals.Select(r => r.ExternalUserId).ToList();
        if (externalUserIds.Count == 0)
        {
            _log.LogInformation("Report {ReportId} has no referrals, skipping SFTP distribution", reportId);
            return [];
        }

        return await EnqueueForExternalUsersAsync(reportId, externalUserIds, ct);
    }

    public async Task<List<int>> EnqueueForExternalUsersAsync(int reportId, List<int> externalUserIds, CancellationToken ct = default)
    {
        var report = await _db.Reports.FindAsync([reportId], ct)
            ?? throw new ArgumentException($"Report {reportId} not found.");

        if (externalUserIds.Count == 0)
            throw new ArgumentException("At least one external user is required.");

        // Verify external users exist
        var users = await _db.ExternalUsers
            .Where(u => externalUserIds.Contains(u.Id))
            .ToListAsync(ct);

        var missingIds = externalUserIds.Except(users.Select(u => u.Id)).ToList();
        if (missingIds.Count > 0)
            throw new ArgumentException($"External users not found: {string.Join(", ", missingIds)}");

        // Check for duplicates: skip users that already have a pending/in-progress/completed delivery for this report
        var existingDeliveries = await _db.OutboxEntries
            .Where(e => e.ReportId == reportId
                        && externalUserIds.Contains(e.ExternalUserId)
                        && e.Status != DeliveryStatus.Failed)
            .Select(e => e.ExternalUserId)
            .ToListAsync(ct);

        var newUserIds = externalUserIds.Except(existingDeliveries).ToList();
        if (newUserIds.Count < externalUserIds.Count)
        {
            var skipped = externalUserIds.Except(newUserIds).ToList();
            _log.LogInformation(
                "Skipping already-enqueued deliveries Report={ReportId} SkippedUsers={SkippedUsers}",
                reportId, string.Join(",", skipped));
        }

        var entryIds = new List<int>();
        foreach (var userId in newUserIds)
        {
            var entry = new OutboxEntry
            {
                ReportId = reportId,
                ExternalUserId = userId,
                MaxAttempts = _options.MaxAttempts,
                NextRetryAt = DateTime.UtcNow
            };

            _db.OutboxEntries.Add(entry);
            await _db.SaveChangesAsync(ct);
            entryIds.Add(entry.Id);

            // Fire-and-forget: kick off delivery immediately (outbox is the safety net if this fails)
            BackgroundJob.Enqueue<OutboxProcessor>(p => p.ProcessSingleEntry(entry.Id));

            var user = users.First(u => u.Id == userId);
            _log.LogInformation(
                "Enqueued delivery Report={ReportId} ExternalUser={UserId} SftpDir={SftpDir} OutboxId={OutboxId}",
                reportId, userId, user.SftpDirectory, entry.Id);
        }

        return entryIds;
    }
}
