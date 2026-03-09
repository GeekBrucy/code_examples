using Hangfire;
using Hangfire.Storage;

namespace api.hangfire.Jobs;

/// <summary>
/// The unit of work that gets fanned out.
///
/// Duplicate-processing prevention:
///   Before doing any work, the job acquires a distributed lock keyed on the entity ID.
///   The lock lives in SQL Server (same DB as Hangfire), so it works across multiple app instances.
///
///   If a second job for the same entity tries to run while the first is still active,
///   AcquireDistributedLock throws DistributedLockTimeoutException (timeout = 0).
///   Hangfire catches the exception, marks the job as Failed, and retries it later
///   with exponential backoff — so the duplicate waits until the first job finishes.
/// </summary>
public class WorkerJob
{
    private static readonly Random _random = new();
    private readonly ILogger<WorkerJob> _logger;
    private readonly JobStorage _jobStorage;

    public WorkerJob(ILogger<WorkerJob> logger, JobStorage jobStorage)
    {
        _logger = logger;
        _jobStorage = jobStorage;
    }

    public async Task ProcessAsync(OrderEntity entity, string batchId)
    {
        // Lock key is scoped to the entity type + ID.
        // Any concurrent job for the same entity will fail to acquire and be retried.
        var lockKey = $"entity-lock:order:{entity.Id}";

        using var connection = _jobStorage.GetConnection();

        // TimeSpan.Zero = don't wait at all; fail immediately if already locked.
        // This is intentional — we want the duplicate to retry later, not block a worker thread.
        using var _ = connection.AcquireDistributedLock(lockKey, timeout: TimeSpan.Zero);

        // --- Safe zone: only one job per entity ID reaches this point ---

        var delay = _random.Next(100, 800);

        _logger.LogInformation(
            "[Batch {BatchId}] Processing Order {EntityId} (simulating {Delay}ms of work)",
            batchId, entity.Id, delay);

        await Task.Delay(delay);

        _logger.LogInformation(
            "[Batch {BatchId}] Finished Order {EntityId}",
            batchId, entity.Id);
    }
}

/// <summary>
/// The entity passed into the job. Hangfire serializes this to JSON in SQL Server.
/// Keep it a simple data bag — no circular refs, no navigation properties.
/// </summary>
public record OrderEntity(int Id, string CustomerName, decimal Amount);
