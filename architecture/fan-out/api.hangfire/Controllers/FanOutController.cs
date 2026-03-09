using api.hangfire.Jobs;
using Hangfire;
using Hangfire.Storage;
using Hangfire.Storage.Monitoring;
using Microsoft.AspNetCore.Mvc;

namespace api.hangfire.Controllers;

[ApiController]
[Route("api/[controller]")]
public class FanOutController : ControllerBase
{
    private readonly IBackgroundJobClient _jobClient;
    private readonly JobStorage _jobStorage;

    public FanOutController(IBackgroundJobClient jobClient, JobStorage jobStorage)
    {
        _jobClient = jobClient;
        _jobStorage = jobStorage;
    }

    /// <summary>
    /// Fan-out: enqueue N independent jobs at once.
    /// Hangfire's worker threads pick them up and run them in parallel immediately.
    ///
    /// Key differences from Channel fan-out:
    ///   - Jobs are persisted to SQL Server → survive app restarts
    ///   - Failed jobs are retried automatically (configurable backoff)
    ///   - Each job is visible in the /hangfire dashboard
    ///   - No fan-in: caller gets back job IDs, not results (fire-and-forget)
    /// </summary>
    [HttpPost]
    public IActionResult FanOut([FromBody] FanOutRequest request)
    {
        if (request.WorkerIds.Count == 0)
            return BadRequest("Provide at least one worker ID.");

        // A shared ID to correlate all jobs in this batch (visible in logs)
        var batchId = Guid.NewGuid().ToString("N")[..8];

        // Fan-out: enqueue all jobs at once — they run in parallel on available worker threads
        var jobIds = request.WorkerIds
            .Select(workerId => _jobClient.Enqueue<WorkerJob>(job => job.ProcessAsync(workerId, batchId)))
            .ToList();

        // Response is immediate — jobs are queued, not yet finished
        return Accepted(new FanOutResponse(
            BatchId: batchId,
            JobIds: jobIds,
            Message: $"Fanned out {jobIds.Count} jobs. Track them at /hangfire or poll GET /api/fanout/status/{{jobId}}."
        ));
    }

    /// <summary>
    /// Check the state of a single job by its Hangfire job ID.
    /// States: Enqueued → Processing → Succeeded | Failed
    /// </summary>
    [HttpGet("status/{jobId}")]
    public IActionResult GetStatus(string jobId)
    {
        var monitoringApi = _jobStorage.GetMonitoringApi();
        var details = monitoringApi.JobDetails(jobId);
        if (details is null)
            return NotFound();

        return Ok(new
        {
            JobId = jobId,
            State = details.History.FirstOrDefault()?.StateName,
            History = details.History.Select(h => new { h.StateName, h.CreatedAt })
        });
    }
}

public record FanOutRequest(List<int> WorkerIds);

public record FanOutResponse(string BatchId, List<string> JobIds, string Message);
