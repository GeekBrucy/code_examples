namespace api.Services;

/// <summary>
/// Simulates a downstream service (e.g., an external API call).
/// Each worker takes a random delay to demonstrate parallel execution.
/// </summary>
public class WorkerService : IWorkerService
{
    private static readonly Random _random = new();

    public async Task<WorkerResult> ProcessAsync(int workerId, CancellationToken cancellationToken = default)
    {
        var started = DateTime.UtcNow;

        // Simulate variable-latency downstream work (100–800 ms)
        var delay = _random.Next(100, 800);
        await Task.Delay(delay, cancellationToken);
        var duration = DateTime.UtcNow - started;
        return new WorkerResult(workerId, $"Worker {workerId} finished in {delay}ms", duration);
    }
}
