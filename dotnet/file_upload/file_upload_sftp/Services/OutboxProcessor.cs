using file_upload_sftp.Data;
using file_upload_sftp.Models;
using file_upload_sftp.Settings;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace file_upload_sftp.Services;

public sealed class OutboxProcessor : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
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
        IServiceScopeFactory scopeFactory,
        IOptions<OutboxOptions> options,
        ILogger<OutboxProcessor> log)
    {
        _scopeFactory = scopeFactory;
        _options = options.Value;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("OutboxProcessor started. Polling every {Interval}s", _options.PollingIntervalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessPendingEntries(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogError(ex, "OutboxProcessor encountered an unexpected error");
            }

            await Task.Delay(TimeSpan.FromSeconds(_options.PollingIntervalSeconds), stoppingToken);
        }
    }

    private async Task ProcessPendingEntries(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OutboxDbContext>();
        var deliveryService = scope.ServiceProvider.GetRequiredService<ISftpDeliveryService>();

        var now = DateTime.UtcNow;
        var entries = await db.OutboxEntries
            .Include(e => e.Files)
            .Where(e => (e.Status == DeliveryStatus.Pending || e.Status == DeliveryStatus.InProgress)
                        && (e.NextRetryAt == null || e.NextRetryAt <= now))
            .OrderBy(e => e.CreatedAt)
            .Take(_options.BatchSize)
            .ToListAsync(ct);

        if (entries.Count == 0) return;

        _log.LogInformation("OutboxProcessor picked up {Count} entries to process", entries.Count);

        foreach (var entry in entries)
        {
            if (ct.IsCancellationRequested) break;

            entry.Status = DeliveryStatus.InProgress;
            entry.Attempts++;
            await db.SaveChangesAsync(ct);

            try
            {
                await deliveryService.DeliverAsync(entry, ct);

                entry.Status = DeliveryStatus.Completed;
                entry.CompletedAt = DateTime.UtcNow;
                entry.LastError = null;

                _log.LogInformation(
                    "Delivery succeeded OutboxId={OutboxId} Record={RecordId} Partner={PartnerId} Attempt={Attempt}",
                    entry.Id, entry.RecordId, entry.PartnerId, entry.Attempts);
            }
            catch (OperationCanceledException)
            {
                // Shutting down — leave as InProgress so it gets picked up on restart
                entry.Status = DeliveryStatus.Pending;
                entry.Attempts--;
                throw;
            }
            catch (Exception ex)
            {
                entry.LastError = $"{ex.GetType().Name}: {ex.Message}";

                if (entry.Attempts >= entry.MaxAttempts)
                {
                    entry.Status = DeliveryStatus.Failed;
                    _log.LogError(ex,
                        "Delivery permanently failed OutboxId={OutboxId} Record={RecordId} Partner={PartnerId} Attempts={Attempts}",
                        entry.Id, entry.RecordId, entry.PartnerId, entry.Attempts);
                }
                else
                {
                    entry.Status = DeliveryStatus.Pending;
                    var delayIndex = Math.Min(entry.Attempts - 1, RetryDelays.Length - 1);
                    entry.NextRetryAt = DateTime.UtcNow.Add(RetryDelays[delayIndex]);

                    _log.LogWarning(ex,
                        "Delivery failed, will retry OutboxId={OutboxId} Record={RecordId} Partner={PartnerId} Attempt={Attempt} NextRetry={NextRetry}",
                        entry.Id, entry.RecordId, entry.PartnerId, entry.Attempts, entry.NextRetryAt);
                }
            }

            await db.SaveChangesAsync(ct);
        }
    }
}
