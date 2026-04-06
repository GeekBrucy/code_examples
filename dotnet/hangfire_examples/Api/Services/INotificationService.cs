namespace Api.Services;

public interface INotificationService
{
    void SendJobFailureEmail(string jobId, string jobName, Exception exception);
}
