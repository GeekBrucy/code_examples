using Api.Services;
using Hangfire.Common;
using Hangfire.States;
using Hangfire.Storage;

namespace Api.Filters;

// Global Hangfire filter — fires whenever a job transitions to FailedState.
// Uses IServiceScopeFactory so it can resolve scoped services (INotificationService).
public class NotifyOnFailureFilter : JobFilterAttribute, IApplyStateFilter
{
    private readonly IServiceScopeFactory _scopeFactory;

    public NotifyOnFailureFilter(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public void OnStateApplied(ApplyStateContext context, IWriteOnlyTransaction transaction)
    {
        if (context.NewState is not FailedState failedState)
            return;

        using var scope = _scopeFactory.CreateScope();
        var notificationService = scope.ServiceProvider.GetRequiredService<INotificationService>();

        var jobName = context.BackgroundJob.Job.Type.Name + "." + context.BackgroundJob.Job.Method.Name;
        notificationService.SendJobFailureEmail(context.BackgroundJob.Id, jobName, failedState.Exception);
    }

    public void OnStateUnapplied(ApplyStateContext context, IWriteOnlyTransaction transaction) { }
}
