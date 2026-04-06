using Hangfire;
using Hangfire.States;
using Hangfire.Storage;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers;

/// <summary>
/// Admin-only endpoint for re-enqueueing failed jobs.
/// The job ID comes from the failure notification email.
/// Secure this with authentication/authorization in production.
/// </summary>
[ApiController]
[Route("admin/jobs")]
public class AdminJobsController : ControllerBase
{
    private readonly IBackgroundJobClient _jobClient;
    private readonly JobStorage _jobStorage;

    public AdminJobsController(IBackgroundJobClient jobClient, JobStorage jobStorage)
    {
        _jobClient = jobClient;
        _jobStorage = jobStorage;
    }

    // POST /admin/jobs/{jobId}/requeue
    // Admin receives the jobId in the failure email, fixes the root cause, then calls this.
    [HttpPost("{jobId}/requeue")]
    public IActionResult Requeue(string jobId)
    {
        using var connection = _jobStorage.GetConnection();
        var jobData = connection.GetJobData(jobId);

        if (jobData is null)
            return NotFound(new { error = $"Job {jobId} not found." });

        if (jobData.State != FailedState.StateName)
            return Conflict(new { error = $"Job {jobId} is in '{jobData.State}' state, not Failed." });

        _jobClient.Requeue(jobId);

        return Accepted(new { jobId, message = "Job re-enqueued." });
    }
}
