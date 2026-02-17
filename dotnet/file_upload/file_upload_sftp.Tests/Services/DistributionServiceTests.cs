using file_upload_sftp.Models;
using file_upload_sftp.Services;
using file_upload_sftp.Settings;
using file_upload_sftp.Tests.Helpers;
using Hangfire;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace file_upload_sftp.Tests.Services;

public sealed class DistributionServiceTests : IDisposable
{
    private readonly TestDbContextFactory _factory;
    private readonly Mock<IBackgroundJobClient> _jobClient = new();
    private readonly IOptions<OutboxOptions> _options = Options.Create(new OutboxOptions { MaxAttempts = 5 });
    private readonly Mock<ILogger<DistributionService>> _log = new();

    public DistributionServiceTests()
    {
        _factory = new TestDbContextFactory();
    }

    public void Dispose() => _factory.Dispose();

    private DistributionService CreateService() =>
        new(_factory.CreateContext(), _jobClient.Object, _options, _log.Object);

    private async Task SeedUsersAndReport(string status = "Finalised", bool withReferrals = true)
    {
        using var db = _factory.CreateContext();

        var partnerA = new ExternalUser { Name = "Partner A", SftpDirectory = "partnerA" };
        var partnerB = new ExternalUser { Name = "Partner B", SftpDirectory = "partnerB" };
        db.ExternalUsers.AddRange(partnerA, partnerB);
        await db.SaveChangesAsync();

        var report = new Report
        {
            Title = "Test Report",
            Status = status,
            JsonContent = """{"test": true}""",
            Referrals = withReferrals
                ? [new ReportReferral { ExternalUserId = partnerA.Id }, new ReportReferral { ExternalUserId = partnerB.Id }]
                : []
        };
        db.Reports.Add(report);
        await db.SaveChangesAsync();
    }

    // --- EnqueueForFinalisedReportAsync ---

    [Fact]
    public async Task EnqueueForFinalisedReport_CreatesEntryPerReferredUser()
    {
        await SeedUsersAndReport();
        var svc = CreateService();

        var ids = await svc.EnqueueForFinalisedReportAsync(1);

        Assert.Equal(2, ids.Count);

        using var db = _factory.CreateContext();
        var entries = db.OutboxEntries.ToList();
        Assert.Equal(2, entries.Count);
        Assert.All(entries, e =>
        {
            Assert.Equal(1, e.ReportId);
            Assert.Equal(DeliveryStatus.Pending, e.Status);
            Assert.Equal(5, e.MaxAttempts);
        });
    }

    [Fact]
    public async Task EnqueueForFinalisedReport_ThrowsIfReportNotFound()
    {
        await SeedUsersAndReport();
        var svc = CreateService();

        await Assert.ThrowsAsync<ArgumentException>(() => svc.EnqueueForFinalisedReportAsync(999));
    }

    [Fact]
    public async Task EnqueueForFinalisedReport_ThrowsIfNotFinalised()
    {
        await SeedUsersAndReport(status: "Submitted");
        var svc = CreateService();

        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.EnqueueForFinalisedReportAsync(1));
    }

    [Fact]
    public async Task EnqueueForFinalisedReport_ReturnsEmptyWhenNoReferrals()
    {
        await SeedUsersAndReport(withReferrals: false);
        var svc = CreateService();

        var ids = await svc.EnqueueForFinalisedReportAsync(1);

        Assert.Empty(ids);
    }

    [Fact]
    public async Task EnqueueForFinalisedReport_EnqueuesHangfireJobPerEntry()
    {
        await SeedUsersAndReport();
        var svc = CreateService();

        await svc.EnqueueForFinalisedReportAsync(1);

        _jobClient.Verify(
            c => c.Create(It.IsAny<Hangfire.Common.Job>(), It.IsAny<Hangfire.States.IState>()),
            Times.Exactly(2));
    }

    // --- EnqueueForExternalUsersAsync ---

    [Fact]
    public async Task EnqueueForExternalUsers_ThrowsIfUserNotFound()
    {
        await SeedUsersAndReport();
        var svc = CreateService();

        await Assert.ThrowsAsync<ArgumentException>(
            () => svc.EnqueueForExternalUsersAsync(1, [999]));
    }

    [Fact]
    public async Task EnqueueForExternalUsers_DeduplicatesExistingNonFailedDeliveries()
    {
        await SeedUsersAndReport();

        // Pre-create a Pending delivery for partner A (userId=1)
        using (var db = _factory.CreateContext())
        {
            db.OutboxEntries.Add(new OutboxEntry { ReportId = 1, ExternalUserId = 1 });
            await db.SaveChangesAsync();
        }

        var svc = CreateService();
        var ids = await svc.EnqueueForExternalUsersAsync(1, [1, 2]);

        // Only partner B (userId=2) should get a new entry
        Assert.Single(ids);

        using var db2 = _factory.CreateContext();
        Assert.Equal(2, db2.OutboxEntries.Count()); // 1 pre-existing + 1 new
    }

    [Fact]
    public async Task EnqueueForExternalUsers_ReEnqueuesForFailedDeliveries()
    {
        await SeedUsersAndReport();

        // Pre-create a Failed delivery for partner A
        using (var db = _factory.CreateContext())
        {
            db.OutboxEntries.Add(new OutboxEntry
            {
                ReportId = 1,
                ExternalUserId = 1,
                Status = DeliveryStatus.Failed
            });
            await db.SaveChangesAsync();
        }

        var svc = CreateService();
        var ids = await svc.EnqueueForExternalUsersAsync(1, [1]);

        // Should create a new entry since the existing one is Failed
        Assert.Single(ids);

        using var db2 = _factory.CreateContext();
        Assert.Equal(2, db2.OutboxEntries.Count()); // 1 failed + 1 new pending
    }
}
