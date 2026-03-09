namespace api.hangfire.Jobs;

/// <summary>
/// The unit of work that gets fanned out.
/// Hangfire serializes this method call to SQL Server and executes it on a free worker thread.
/// Built-in retry: if ProcessAsync throws, Hangfire retries with exponential backoff.
/// </summary>
public class WorkerJob
{
    private static readonly Random _random = new();
    private readonly ILogger<WorkerJob> _logger;

    public WorkerJob(ILogger<WorkerJob> logger)
    {
        _logger = logger;
    }

    public async Task ProcessAsync(int workerId, string batchId)
    {
        var delay = _random.Next(100, 800);

        _logger.LogInformation("[Batch {BatchId}] Worker {WorkerId} started (will take ~{Delay}ms)",
            batchId, workerId, delay);

        await Task.Delay(delay);

        _logger.LogInformation("[Batch {BatchId}] Worker {WorkerId} finished", batchId, workerId);
    }
}
