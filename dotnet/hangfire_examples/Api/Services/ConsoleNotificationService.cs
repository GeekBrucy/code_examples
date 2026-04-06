using Api.Settings;
using Microsoft.Extensions.Options;

namespace Api.Services;

public class ConsoleNotificationService : INotificationService
{
    private readonly EmailSettings _settings;

    public ConsoleNotificationService(IOptions<EmailSettings> options)
    {
        _settings = options.Value;
    }

    public void SendJobFailureEmail(string jobId, string jobName, Exception exception)
    {
        Console.WriteLine("============ JOB FAILURE EMAIL ============");
        Console.WriteLine($"From:    {_settings.FromAddress}");
        Console.WriteLine($"To:      {_settings.ToAddress}");
        Console.WriteLine($"SMTP:    {_settings.SmtpHost}");
        Console.WriteLine($"Subject: Background job failed — {jobName} (ID: {jobId})");
        Console.WriteLine($"Body:    {exception.Message}");
        Console.WriteLine($"Retry:   POST /admin/jobs/{jobId}/requeue");
        Console.WriteLine("===========================================");
    }
}
