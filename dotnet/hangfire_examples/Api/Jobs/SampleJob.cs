using Hangfire;

namespace Api.Jobs;

// Hangfire will retry up to 5 times with exponential back-off.
// After the 5th failure the job transitions to FailedState,
// which is where NotifyOnFailureFilter kicks in.
[AutomaticRetry(Attempts = 5, OnAttemptsExceeded = AttemptsExceededAction.Fail)]
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
