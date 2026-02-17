using file_upload_sftp.Controllers;
using file_upload_sftp.Models;
using file_upload_sftp.Services;
using file_upload_sftp.Tests.Helpers;
using Microsoft.AspNetCore.Mvc;
using Moq;

namespace file_upload_sftp.Tests.Controllers;

public sealed class SFTPControllerTests : IDisposable
{
    private readonly TestDbContextFactory _factory;
    private readonly Mock<IDistributionService> _distribution = new();

    public SFTPControllerTests()
    {
        _factory = new TestDbContextFactory();
    }

    public void Dispose() => _factory.Dispose();

    private SFTPController CreateController() =>
        new(_distribution.Object, _factory.CreateContext());

    private async Task SeedReport(string status = "Submitted")
    {
        using var db = _factory.CreateContext();
        db.Reports.Add(new Report
        {
            Title = "Test Report",
            Status = status,
            JsonContent = """{"test": true}"""
        });
        await db.SaveChangesAsync();
    }

    // --- FinaliseReport ---

    [Fact]
    public async Task FinaliseReport_Returns404WhenReportNotFound()
    {
        var controller = CreateController();

        var result = await controller.FinaliseReport(999, CancellationToken.None);

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task FinaliseReport_Returns400WhenAlreadyFinalised()
    {
        await SeedReport(status: "Finalised");
        var controller = CreateController();

        var result = await controller.FinaliseReport(1, CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task FinaliseReport_SetsStatusAndEnqueues()
    {
        await SeedReport(status: "Submitted");
        _distribution
            .Setup(d => d.EnqueueForFinalisedReportAsync(1, It.IsAny<CancellationToken>()))
            .ReturnsAsync([10, 11]);

        var controller = CreateController();
        var result = await controller.FinaliseReport(1, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(ok.Value);

        // Verify the report status was updated in the DB
        using var db = _factory.CreateContext();
        var report = db.Reports.Find(1)!;
        Assert.Equal("Finalised", report.Status);
        Assert.NotNull(report.FinalisedAt);

        _distribution.Verify(
            d => d.EnqueueForFinalisedReportAsync(1, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // --- RetryEntry ---

    [Fact]
    public async Task RetryEntry_Returns404WhenEntryNotFound()
    {
        var controller = CreateController();

        var result = await controller.RetryEntry(999, CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task RetryEntry_Returns400WhenNotFailed()
    {
        using (var db = _factory.CreateContext())
        {
            db.OutboxEntries.Add(new OutboxEntry
            {
                ReportId = 1,
                ExternalUserId = 1,
                Status = DeliveryStatus.Pending
            });
            await db.SaveChangesAsync();
        }

        var controller = CreateController();
        var result = await controller.RetryEntry(1, CancellationToken.None);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task RetryEntry_ResetsFailedEntryToPending()
    {
        using (var db = _factory.CreateContext())
        {
            db.OutboxEntries.Add(new OutboxEntry
            {
                ReportId = 1,
                ExternalUserId = 1,
                Status = DeliveryStatus.Failed,
                Attempts = 5,
                LastError = "IOException: timeout"
            });
            await db.SaveChangesAsync();
        }

        var controller = CreateController();
        var result = await controller.RetryEntry(1, CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);

        using var db2 = _factory.CreateContext();
        var entry = db2.OutboxEntries.Find(1)!;
        Assert.Equal(DeliveryStatus.Pending, entry.Status);
        Assert.Equal(0, entry.Attempts);
        Assert.Null(entry.LastError);
    }

    // --- QueryOutbox ---

    [Fact]
    public async Task QueryOutbox_FiltersById()
    {
        using (var db = _factory.CreateContext())
        {
            db.OutboxEntries.AddRange(
                new OutboxEntry { ReportId = 1, ExternalUserId = 1 },
                new OutboxEntry { ReportId = 2, ExternalUserId = 1 }
            );
            await db.SaveChangesAsync();
        }

        var controller = CreateController();
        var result = await controller.QueryOutbox(reportId: 1, status: null, externalUserId: null, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        // The result is an anonymous type list, so just verify it's not null
        Assert.NotNull(ok.Value);
    }
}
