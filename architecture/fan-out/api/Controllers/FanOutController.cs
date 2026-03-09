using api.Services;
using Microsoft.AspNetCore.Mvc;

namespace api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class FanOutController : ControllerBase
{
    private readonly IWorkerService _workerService;
    private readonly ILogger<FanOutController> _logger;

    public FanOutController(IWorkerService workerService, ILogger<FanOutController> logger)
    {
        _workerService = workerService;
        _logger = logger;
    }

    /// <summary>
    /// Fan-out: fire all worker tasks in parallel, then fan-in by awaiting all results.
    /// Total time ≈ slowest single worker, not the sum of all workers.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> FanOut([FromBody] FanOutRequest request, CancellationToken cancellationToken)
    {
        if (request.WorkerIds.Count == 0)
            return BadRequest("Provide at least one worker ID.");

        var overallStart = DateTime.UtcNow;

        _logger.LogInformation("Fanning out to {Count} workers: {Ids}",
            request.WorkerIds.Count, string.Join(", ", request.WorkerIds));

        // Fan-out: start all tasks simultaneously
        var tasks = request.WorkerIds
            .Select(id => _workerService.ProcessAsync(id, cancellationToken))
            .ToList();

        // Fan-in: await all completions
        var results = await Task.WhenAll(tasks);

        var totalDuration = DateTime.UtcNow - overallStart;

        _logger.LogInformation("All workers completed in {Total}ms (sum would have been {Sum}ms)",
            (int)totalDuration.TotalMilliseconds,
            results.Sum(r => (int)r.Duration.TotalMilliseconds));

        return Ok(new FanOutResponse(
            Results: results,
            TotalDurationMs: (int)totalDuration.TotalMilliseconds,
            SumOfIndividualMs: results.Sum(r => (int)r.Duration.TotalMilliseconds)
        ));
    }

    /// <summary>
    /// Fan-out variant: return as soon as the FIRST worker finishes (Task.WhenAny).
    /// Useful for "race" patterns where you only need one result.
    /// </summary>
    [HttpPost("first")]
    public async Task<IActionResult> FanOutFirst([FromBody] FanOutRequest request, CancellationToken cancellationToken)
    {
        if (request.WorkerIds.Count == 0)
            return BadRequest("Provide at least one worker ID.");

        var tasks = request.WorkerIds
            .Select(id => _workerService.ProcessAsync(id, cancellationToken))
            .ToList();

        // Return as soon as the fastest worker finishes
        var firstTask = await Task.WhenAny(tasks);
        var result = await firstTask;

        return Ok(new { First = result, Message = "Returned on first completion; other workers may still be running." });
    }
}

public record FanOutRequest(List<int> WorkerIds);

public record FanOutResponse(
    WorkerResult[] Results,
    int TotalDurationMs,
    int SumOfIndividualMs
);
