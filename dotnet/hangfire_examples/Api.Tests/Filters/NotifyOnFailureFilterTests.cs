using Api.Filters;
using Api.Jobs;
using Api.Services;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Hangfire.Storage;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Api.Tests.Filters;

public class NotifyOnFailureFilterTests
{
    private readonly Mock<INotificationService> _notificationMock = new();
    private readonly Mock<IServiceScopeFactory> _scopeFactoryMock = new();

    public NotifyOnFailureFilterTests()
    {
        // Wire up the DI scope so the filter can resolve INotificationService.
        var scopeMock = new Mock<IServiceScope>();
        var providerMock = new Mock<IServiceProvider>();

        providerMock
            .Setup(p => p.GetService(typeof(INotificationService)))
            .Returns(_notificationMock.Object);

        scopeMock.Setup(s => s.ServiceProvider).Returns(providerMock.Object);
        _scopeFactoryMock.Setup(f => f.CreateScope()).Returns(scopeMock.Object);
    }

    [Fact]
    public void OnStateApplied_JobHasNotifyAttribute_SendsEmail()
    {
        var filter = new NotifyOnFailureFilter(_scopeFactoryMock.Object);
        var context = BuildContext<SampleJob>(new FailedState(new Exception("boom")), "payload");

        filter.OnStateApplied(context, Mock.Of<IWriteOnlyTransaction>());

        _notificationMock.Verify(
            n => n.SendJobFailureEmail(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Exception>()),
            Times.Once);
    }

    [Fact]
    public void OnStateApplied_JobMissingNotifyAttribute_DoesNotSendEmail()
    {
        var filter = new NotifyOnFailureFilter(_scopeFactoryMock.Object);
        // UntaggedJob has no [NotifyOnFailure] attribute.
        var context = BuildContext<UntaggedJob>(new FailedState(new Exception("boom")));

        filter.OnStateApplied(context, Mock.Of<IWriteOnlyTransaction>());

        _notificationMock.Verify(
            n => n.SendJobFailureEmail(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Exception>()),
            Times.Never);
    }

    [Fact]
    public void OnStateApplied_NonFailedState_DoesNotSendEmail()
    {
        var filter = new NotifyOnFailureFilter(_scopeFactoryMock.Object);
        var context = BuildContext<SampleJob>(new SucceededState(null, 0, 0), "payload");

        filter.OnStateApplied(context, Mock.Of<IWriteOnlyTransaction>());

        _notificationMock.Verify(
            n => n.SendJobFailureEmail(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Exception>()),
            Times.Never);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ApplyStateContext BuildContext<TJob>(IState newState, params object[] args) where TJob : class
    {
        var method = typeof(TJob).GetMethod("Execute")!;
        var job = new Job(typeof(TJob), method, args);
        var backgroundJob = new BackgroundJob("job-123", job, DateTime.UtcNow);

        return new ApplyStateContext(
            Mock.Of<JobStorage>(),
            Mock.Of<IStorageConnection>(),
            Mock.Of<IWriteOnlyTransaction>(),
            backgroundJob,
            newState,
            null);  // previousStateName
    }

    // Stand-in job that deliberately has no [NotifyOnFailure] attribute.
    private class UntaggedJob
    {
        public void Execute() { }
    }
}
