using api.hangfire.Jobs;
using Hangfire;
using Hangfire.Storage;
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
        if (request.Orders.Count == 0)
            return BadRequest("Provide at least one order.");

        // A shared ID to correlate all jobs in this batch (visible in logs)
        var batchId = Guid.NewGuid().ToString("N")[..8];

        // Fan-out: enqueue all jobs at once — they run in parallel on available worker threads.
        // Hangfire serializes each OrderEntity to JSON in SQL Server.
        var jobIds = request.Orders
            .Select(order => _jobClient.Enqueue<WorkerJob>(job => job.ProcessAsync(order, batchId)))
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

    /// <summary>
    /// Multi-stage pipeline per entity:
    ///   WorkflowJob  →  Stage1 (ContinueJobWith)  →  Stage2 (ContinueJobWith)
    ///                          ↓ fans out
    ///                   SftpUploadJob × N  →  last one enqueues Stage3CleanupJob
    ///
    /// Duplicate protection: WorkflowJob holds a distributed lock for the entity.
    /// If the same entityId is submitted again while the pipeline is running,
    /// the new WorkflowJob fails to acquire the lock and is retried later.
    /// </summary>
    [HttpPost("pipeline")]
    public IActionResult Pipeline([FromBody] PipelineRequest request)
    {
        var jobIds = request.EntityIds
            .Select(entityId => new
            {
                EntityId = entityId,
                WorkflowJobId = _jobClient.Enqueue<WorkflowJob>(job => job.StartAsync(entityId))
            })
            .ToList();

        return Accepted(new
        {
            Message = $"Pipeline started for {jobIds.Count} entities. Track progress at /hangfire.",
            Jobs = jobIds
        });
    }
}

public record FanOutRequest(List<OrderEntity> Orders);

public record FanOutResponse(string BatchId, List<string> JobIds, string Message);

public record PipelineRequest(List<int> EntityIds);
