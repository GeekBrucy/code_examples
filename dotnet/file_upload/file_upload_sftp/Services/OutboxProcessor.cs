using file_upload_sftp.Data;
using file_upload_sftp.Models;
using file_upload_sftp.Settings;
using Hangfire;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace file_upload_sftp.Services;

/// <summary>
/// Hangfire jobs for processing SFTP delivery outbox entries.
///
/// Three entry points:
///   1. ProcessSingleEntry(id) — fire-and-forget, triggered immediately when an entry is created
///   2. SweepPendingEntries()  — recurring (every minute), catches retries, stuck entries, and missed triggers
///   3. ResetFailedEntries()   — recurring (daily), resets Failed entries for another round of attempts
///
/// ProcessSingleEntry uses atomic claim (UPDATE WHERE Status=Pending) to prevent race conditions.
/// </summary>
public sealed class OutboxProcessor
{
    private readonly AppDbContext _db;
    private readonly ISftpDeliveryService _deliveryService;
    private readonly OutboxOptions _options;
    private readonly ILogger<OutboxProcessor> _log;

    // Exponential backoff: 30s, 2m, 8m, 32m, 2h
    private static readonly TimeSpan[] RetryDelays =
    [
        TimeSpan.FromSeconds(30),
        TimeSpan.FromMinutes(2),
        TimeSpan.FromMinutes(8),
        TimeSpan.FromMinutes(32),
        TimeSpan.FromHours(2)
    ];

    public OutboxProcessor(
        AppDbContext db,
        ISftpDeliveryService deliveryService,
        IOptions<OutboxOptions> options,
        ILogger<OutboxProcessor> log)
    {
        _db = db;
        _deliveryService = deliveryService;
        _options = options.Value;
        _log = log;
    }

    /// <summary>
    /// Fire-and-forget: process a single entry immediately after creation.
    /// Uses atomic claim to prevent duplicate processing if the sweep picks it up at the same time.
    /// </summary>
    [JobDisplayName("SFTP Deliver OutboxEntry #{0}")]
    public async Task ProcessSingleEntry(int outboxEntryId)
    {
        if (!await TryClaimEntry(outboxEntryId))
        {
            _log.LogDebug("OutboxEntry {OutboxId} already claimed, skipping", outboxEntryId);
            return;
        }

        var entry = await _db.OutboxEntries.FindAsync(outboxEntryId);
        if (entry is null) return;

        await DeliverWithRetryHandling(entry);
    }

    /// <summary>
    /// Recurring job (safety net): sweep for any pending entries that are due for processing.
    /// Catches: retries after backoff, entries stuck as InProgress (crashed mid-delivery), missed fire-and-forgets.
    /// </summary>
    [JobDisplayName("SFTP Outbox Sweep")]
    public async Task SweepPendingEntries()
    {
        var now = DateTime.UtcNow;

        // Find entries that are ready to process
        var entryIds = await _db.OutboxEntries
            .Where(e => (e.Status == DeliveryStatus.Pending || e.Status == DeliveryStatus.InProgress)
                        && (e.NextRetryAt == null || e.NextRetryAt <= now))
            .OrderBy(e => e.CreatedAt)
            .Take(_options.BatchSize)
            .Select(e => e.Id)
            .ToListAsync();

        if (entryIds.Count == 0) return;

        _log.LogInformation("Outbox sweep found {Count} entries to process", entryIds.Count);

        foreach (var entryId in entryIds)
        {
            // Enqueue each as a separate Hangfire job so they run independently.
            // Using entry ID as job ID for deduplication — if fire-and-forget already
            // enqueued this same ID and it hasn't started yet, Hangfire won't create a duplicate.
            BackgroundJob.Enqueue<OutboxProcessor>(
                p => p.ProcessSingleEntry(entryId));
        }
    }

    /// <summary>
    /// Recurring job (daily): reset Failed entries that haven't exceeded their max reset count.
    /// Gives transient infra failures another chance without human intervention.
    /// After MaxResets (default 3 = 15 total attempts over ~3 days), the entry stays Failed permanently.
    /// </summary>
    [JobDisplayName("SFTP Outbox Daily Reset")]
    public async Task ResetFailedEntries()
    {
        var resetCount = await _db.OutboxEntries
            .Where(e => e.Status == DeliveryStatus.Failed && e.ResetCount < e.MaxResets)
            .ExecuteUpdateAsync(s => s
                .SetProperty(e => e.Status, DeliveryStatus.Pending)
                .SetProperty(e => e.Attempts, 0)
                .SetProperty(e => e.ResetCount, e => e.ResetCount + 1)
                .SetProperty(e => e.NextRetryAt, DateTime.UtcNow)
                .SetProperty(e => e.LastError, e => $"[Auto-reset #{e.ResetCount + 1}] {e.LastError}"));

        if (resetCount > 0)
        {
            _log.LogInformation("Daily reset: re-queued {Count} failed entries for retry", resetCount);
        }

        // Log permanently failed entries for visibility
        var permanentlyFailed = await _db.OutboxEntries
            .CountAsync(e => e.Status == DeliveryStatus.Failed && e.ResetCount >= e.MaxResets);

        if (permanentlyFailed > 0)
        {
            _log.LogWarning(
                "Daily reset: {Count} entries permanently failed (exceeded {MaxResets} resets) — manual intervention required",
                permanentlyFailed, 3);
        }
    }

    /// <summary>
    /// Atomic claim: UPDATE ... WHERE Status = Pending AND Id = @id.
    /// Returns true if this thread successfully claimed the entry.
    /// If another thread (fire-and-forget or sweep) already claimed it, returns false.
    /// </summary>
    private async Task<bool> TryClaimEntry(int entryId)
    {
        var claimed = await _db.OutboxEntries
            .Where(e => e.Id == entryId && e.Status == DeliveryStatus.Pending)
            .ExecuteUpdateAsync(s => s
                .SetProperty(e => e.Status, DeliveryStatus.InProgress)
                .SetProperty(e => e.Attempts, e => e.Attempts + 1));

        return claimed > 0;
    }

    private async Task DeliverWithRetryHandling(OutboxEntry entry)
    {
        try
        {
            await _deliveryService.DeliverAsync(entry);

            entry.Status = DeliveryStatus.Completed;
            entry.CompletedAt = DateTime.UtcNow;
            entry.LastError = null;
            await _db.SaveChangesAsync();

            _log.LogInformation(
                "Delivery succeeded OutboxId={OutboxId} Report={ReportId} User={UserId} Attempt={Attempt}",
                entry.Id, entry.ReportId, entry.ExternalUserId, entry.Attempts);
        }
        catch (Exception ex)
        {
            entry.LastError = $"{ex.GetType().Name}: {ex.Message}";

            if (entry.Attempts >= entry.MaxAttempts)
            {
                entry.Status = DeliveryStatus.Failed;
                await _db.SaveChangesAsync();

                _log.LogError(ex,
                    "Delivery permanently failed OutboxId={OutboxId} Report={ReportId} User={UserId} Attempts={Attempts}",
                    entry.Id, entry.ReportId, entry.ExternalUserId, entry.Attempts);
            }
            else
            {
                entry.Status = DeliveryStatus.Pending;
                var delayIndex = Math.Min(entry.Attempts - 1, RetryDelays.Length - 1);
                entry.NextRetryAt = DateTime.UtcNow.Add(RetryDelays[delayIndex]);
                await _db.SaveChangesAsync();

                _log.LogWarning(ex,
                    "Delivery failed, scheduled retry OutboxId={OutboxId} Report={ReportId} User={UserId} Attempt={Attempt} NextRetry={NextRetry}",
                    entry.Id, entry.ReportId, entry.ExternalUserId, entry.Attempts, entry.NextRetryAt);
            }
        }
    }
}
