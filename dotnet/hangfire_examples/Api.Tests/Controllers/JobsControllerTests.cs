using Api.Controllers;
using Api.Jobs;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.AspNetCore.Mvc;
using Moq;

namespace Api.Tests.Controllers;

public class JobsControllerTests
{
    private readonly Mock<IBackgroundJobClient> _jobClientMock = new();

    [Fact]
    public void EnqueueSampleJob_ReturnsAccepted()
    {
        _jobClientMock
            .Setup(c => c.Create(It.IsAny<Job>(), It.IsAny<IState>()))
            .Returns("job-abc");

        var controller = new JobsController(_jobClientMock.Object);

        var result = controller.EnqueueSampleJob("hello");

        Assert.IsType<AcceptedResult>(result);
    }

    [Fact]
    public void EnqueueSampleJob_EnqueuesOnce()
    {
        _jobClientMock
            .Setup(c => c.Create(It.IsAny<Job>(), It.IsAny<IState>()))
            .Returns("job-abc");

        var controller = new JobsController(_jobClientMock.Object);

        controller.EnqueueSampleJob("hello");

        // Verify Hangfire's underlying Create was called exactly once (Enqueue calls Create internally).
        _jobClientMock.Verify(c => c.Create(It.IsAny<Job>(), It.IsAny<IState>()), Times.Once);
    }
}
