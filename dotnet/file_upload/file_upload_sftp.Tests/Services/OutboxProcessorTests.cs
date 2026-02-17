using file_upload_sftp.Models;
using file_upload_sftp.Services;
using file_upload_sftp.Settings;
using file_upload_sftp.Tests.Helpers;
using Hangfire;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace file_upload_sftp.Tests.Services;

public sealed class OutboxProcessorTests : IDisposable
{
    private readonly TestDbContextFactory _factory;
    private readonly Mock<ISftpDeliveryService> _delivery = new();
    private readonly Mock<IBackgroundJobClient> _jobClient = new();
    private readonly IOptions<OutboxOptions> _options = Options.Create(new OutboxOptions { BatchSize = 20 });
    private readonly Mock<ILogger<OutboxProcessor>> _log = new();

    public OutboxProcessorTests()
    {
        _factory = new TestDbContextFactory();
    }

    public void Dispose() => _factory.Dispose();

    private OutboxProcessor CreateProcessor() =>
        new(_factory.CreateContext(), _delivery.Object, _jobClient.Object, _options, _log.Object);

    private async Task<int> SeedEntry(
        DeliveryStatus status = DeliveryStatus.Pending,
        int attempts = 0,
        int maxAttempts = 5,
        DateTime? nextRetryAt = null,
        int resetCount = 0,
        int maxResets = 3)
    {
        using var db = _factory.CreateContext();
        var entry = new OutboxEntry
        {
            ReportId = 1,
            ExternalUserId = 1,
            Status = status,
            Attempts = attempts,
            MaxAttempts = maxAttempts,
            NextRetryAt = nextRetryAt,
            ResetCount = resetCount,
            MaxResets = maxResets
        };
        db.OutboxEntries.Add(entry);
        await db.SaveChangesAsync();
        return entry.Id;
    }

    // --- ProcessSingleEntry: atomic claim ---

    [Fact]
    public async Task ProcessSingleEntry_ClaimsAndDelivers()
    {
        var id = await SeedEntry();
        var processor = CreateProcessor();

        await processor.ProcessSingleEntry(id);

        _delivery.Verify(d => d.DeliverAsync(It.IsAny<OutboxEntry>(), default), Times.Once);

        using var db = _factory.CreateContext();
        var entry = db.OutboxEntries.Find(id)!;
        Assert.Equal(DeliveryStatus.Completed, entry.Status);
        Assert.NotNull(entry.CompletedAt);
        Assert.Equal(1, entry.Attempts);
    }

    [Fact]
    public async Task ProcessSingleEntry_SkipsIfAlreadyClaimed()
    {
        var id = await SeedEntry(status: DeliveryStatus.InProgress);
        var processor = CreateProcessor();

        await processor.ProcessSingleEntry(id);

        _delivery.Verify(d => d.DeliverAsync(It.IsAny<OutboxEntry>(), default), Times.Never);
    }

    [Fact]
    public async Task ProcessSingleEntry_SkipsIfAlreadyCompleted()
    {
        var id = await SeedEntry(status: DeliveryStatus.Completed);
        var processor = CreateProcessor();

        await processor.ProcessSingleEntry(id);

        _delivery.Verify(d => d.DeliverAsync(It.IsAny<OutboxEntry>(), default), Times.Never);
    }

    // --- ProcessSingleEntry: failure handling ---

    [Fact]
    public async Task ProcessSingleEntry_SchedulesRetryOnFailure()
    {
        var id = await SeedEntry(); // attempts=0, maxAttempts=5
        _delivery
            .Setup(d => d.DeliverAsync(It.IsAny<OutboxEntry>(), default))
            .ThrowsAsync(new IOException("Connection refused"));

        var processor = CreateProcessor();
        await processor.ProcessSingleEntry(id);

        using var db = _factory.CreateContext();
        var entry = db.OutboxEntries.Find(id)!;
        Assert.Equal(DeliveryStatus.Pending, entry.Status); // back to Pending for retry
        Assert.Equal(1, entry.Attempts); // claimed incremented it to 1
        Assert.NotNull(entry.NextRetryAt);
        Assert.Contains("IOException", entry.LastError);
    }

    [Fact]
    public async Task ProcessSingleEntry_MarksFailedAfterMaxAttempts()
    {
        // Entry already at 4 attempts (claim will bump to 5 = maxAttempts)
        var id = await SeedEntry(attempts: 4, maxAttempts: 5);
        _delivery
            .Setup(d => d.DeliverAsync(It.IsAny<OutboxEntry>(), default))
            .ThrowsAsync(new IOException("Connection refused"));

        var processor = CreateProcessor();
        await processor.ProcessSingleEntry(id);

        using var db = _factory.CreateContext();
        var entry = db.OutboxEntries.Find(id)!;
        Assert.Equal(DeliveryStatus.Failed, entry.Status);
        Assert.Equal(5, entry.Attempts);
    }

    // --- SweepPendingEntries ---

    [Fact]
    public async Task Sweep_FindsEntriesWithElapsedNextRetryAt()
    {
        // Entry due for retry (NextRetryAt in the past)
        await SeedEntry(nextRetryAt: DateTime.UtcNow.AddMinutes(-1));

        var processor = CreateProcessor();
        await processor.SweepPendingEntries();

        _jobClient.Verify(
            c => c.Create(It.IsAny<Hangfire.Common.Job>(), It.IsAny<Hangfire.States.IState>()),
            Times.Once);
    }

    [Fact]
    public async Task Sweep_IgnoresEntriesWithFutureNextRetryAt()
    {
        // Entry not yet due (NextRetryAt in the future)
        await SeedEntry(nextRetryAt: DateTime.UtcNow.AddMinutes(30));

        var processor = CreateProcessor();
        await processor.SweepPendingEntries();

        _jobClient.Verify(
            c => c.Create(It.IsAny<Hangfire.Common.Job>(), It.IsAny<Hangfire.States.IState>()),
            Times.Never);
    }

    [Fact]
    public async Task Sweep_IgnoresCompletedEntries()
    {
        await SeedEntry(status: DeliveryStatus.Completed);

        var processor = CreateProcessor();
        await processor.SweepPendingEntries();

        _jobClient.Verify(
            c => c.Create(It.IsAny<Hangfire.Common.Job>(), It.IsAny<Hangfire.States.IState>()),
            Times.Never);
    }

    // --- ResetFailedEntries ---

    [Fact]
    public async Task ResetFailed_ResetsEntriesBelowMaxResets()
    {
        var id = await SeedEntry(
            status: DeliveryStatus.Failed,
            attempts: 5,
            resetCount: 1,
            maxResets: 3);

        var processor = CreateProcessor();
        await processor.ResetFailedEntries();

        using var db = _factory.CreateContext();
        var entry = db.OutboxEntries.Find(id)!;
        Assert.Equal(DeliveryStatus.Pending, entry.Status);
        Assert.Equal(0, entry.Attempts); // reset
        Assert.Equal(2, entry.ResetCount); // incremented
    }

    [Fact]
    public async Task ResetFailed_LeavesPermanentlyFailedEntriesAlone()
    {
        var id = await SeedEntry(
            status: DeliveryStatus.Failed,
            attempts: 5,
            resetCount: 3,
            maxResets: 3);

        var processor = CreateProcessor();
        await processor.ResetFailedEntries();

        using var db = _factory.CreateContext();
        var entry = db.OutboxEntries.Find(id)!;
        Assert.Equal(DeliveryStatus.Failed, entry.Status); // unchanged
        Assert.Equal(3, entry.ResetCount); // unchanged
    }

    [Fact]
    public async Task ResetFailed_PrependsResetMarkerToLastError()
    {
        using (var db = _factory.CreateContext())
        {
            db.OutboxEntries.Add(new OutboxEntry
            {
                ReportId = 1,
                ExternalUserId = 1,
                Status = DeliveryStatus.Failed,
                Attempts = 5,
                ResetCount = 0,
                MaxResets = 3,
                LastError = "IOException: Connection refused"
            });
            await db.SaveChangesAsync();
        }

        var processor = CreateProcessor();
        await processor.ResetFailedEntries();

        using var db2 = _factory.CreateContext();
        var entry = db2.OutboxEntries.First();
        Assert.StartsWith("[Auto-reset]", entry.LastError!);
        Assert.Contains("IOException: Connection refused", entry.LastError!);
    }
}
