using Api.Filters;
using Hangfire;

namespace Api.Jobs;

[AutomaticRetry(Attempts = 5, OnAttemptsExceeded = AttemptsExceededAction.Fail)]
[NotifyOnFailure]   // opt in: send failure email after all retries are exhausted
public class SampleJob
{
    private readonly ILogger<SampleJob> _logger;

    public SampleJob(ILogger<SampleJob> logger)
    {
        _logger = logger;
    }

    public void Execute(string payload)
    {
        _logger.LogInformation("SampleJob executing with payload: {Payload}", payload);

        // Simulate a failure so the retry / failure flow can be observed.
        throw new InvalidOperationException($"SampleJob intentionally failed. Payload was: {payload}");
    }
}
