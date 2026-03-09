namespace api.Services;

public interface IWorkerService
{
    Task<WorkerResult> ProcessAsync(int workerId, CancellationToken cancellationToken = default);
}

public record WorkerResult(int WorkerId, string Output, TimeSpan Duration);
