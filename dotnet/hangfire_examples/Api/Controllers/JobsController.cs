using Api.Jobs;
using Hangfire;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers;

[ApiController]
[Route("[controller]")]
public class JobsController : ControllerBase
{
    private readonly IBackgroundJobClient _jobClient;

    public JobsController(IBackgroundJobClient jobClient)
    {
        _jobClient = jobClient;
    }

    // POST /jobs/sample?payload=hello
    [HttpPost("sample")]
    public IActionResult EnqueueSampleJob([FromQuery] string payload = "default-payload")
    {
        var jobId = _jobClient.Enqueue<SampleJob>(job => job.Execute(payload));
        return Accepted(new { jobId, message = "Job enqueued. It will retry up to 5 times on failure." });
    }
}
