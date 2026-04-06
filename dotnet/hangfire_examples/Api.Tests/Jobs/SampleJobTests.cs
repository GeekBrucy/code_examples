using Api.Jobs;
using Microsoft.Extensions.Logging;
using Moq;

namespace Api.Tests.Jobs;

// The job class is plain C#. Test it by calling Execute() directly — no Hangfire needed.
public class SampleJobTests
{
    private readonly Mock<ILogger<SampleJob>> _loggerMock = new();

    [Fact]
    public void Execute_ThrowsException()
    {
        var job = new SampleJob(_loggerMock.Object);

        var act = () => job.Execute("test-payload");

        Assert.Throws<InvalidOperationException>(act);
    }

    [Fact]
    public void Execute_ExceptionMessage_ContainsPayload()
    {
        var job = new SampleJob(_loggerMock.Object);

        var ex = Assert.Throws<InvalidOperationException>(() => job.Execute("my-payload"));

        Assert.Contains("my-payload", ex.Message);
    }
}
