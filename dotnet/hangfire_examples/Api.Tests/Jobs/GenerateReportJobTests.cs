using Api.Jobs;
using Api.Models;
using Api.Repositories;
using Api.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace Api.Tests.Jobs;

public class GenerateReportJobTests
{
    private readonly Mock<IReportRepository> _reportRepoMock = new();
    private readonly Mock<IUserRepository> _userRepoMock = new();
    private readonly Mock<ISftpClient> _sftpMock = new();
    private readonly Mock<ILogger<GenerateReportJob>> _loggerMock = new();

    // Use the real implementations — they are pure with no side effects.
    private readonly ReportTransformer _transformer = new();
    private readonly ReportZipBuilder _zipBuilder = new();

    private GenerateReportJob CreateJob() => new(
        _reportRepoMock.Object,
        _userRepoMock.Object,
        _transformer,
        _zipBuilder,
        _sftpMock.Object,
        _loggerMock.Object);

    // ── Happy path ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ExecuteAsync_UploadsZipToCorrectRemotePath()
    {
        SetupDefaults(reportId: 7);

        await CreateJob().ExecuteAsync(7, [1]);

        _sftpMock.Verify(
            s => s.UploadAsync(It.IsAny<Stream>(), "reports/7.zip", It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_UploadsNonEmptyStream()
    {
        SetupDefaults(reportId: 1);
        MemoryStream? captured = null;
        _sftpMock
            .Setup(s => s.UploadAsync(It.IsAny<Stream>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<Stream, string, CancellationToken>((stream, _, _) =>
            {
                // Copy while the stream is still alive — the job disposes it after upload.
                captured = new MemoryStream();
                stream.CopyTo(captured);
            })
            .Returns(Task.CompletedTask);

        await CreateJob().ExecuteAsync(1, [10]);

        Assert.NotNull(captured);
        Assert.True(captured!.Length > 0);
    }

    [Fact]
    public async Task ExecuteAsync_FetchesUsersMatchingProvidedIds()
    {
        SetupDefaults(reportId: 1);

        await CreateJob().ExecuteAsync(1, [10, 20]);

        _userRepoMock.Verify(
            r => r.GetByIdsAsync(
                It.Is<IEnumerable<int>>(ids => ids.SequenceEqual(new[] { 10, 20 })),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ── Retry: exceptions must propagate so Hangfire can retry ────────────────
    //
    // If any of these throw, ExecuteAsync must NOT catch and swallow the exception.
    // Swallowing = Hangfire thinks the job succeeded = no retry.

    [Fact]
    public async Task ExecuteAsync_WhenReportRepoThrows_ExceptionPropagates()
    {
        _reportRepoMock
            .Setup(r => r.GetByIdAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("DB unavailable"));

        await Assert.ThrowsAsync<Exception>(() => CreateJob().ExecuteAsync(1, [10]));
    }

    [Fact]
    public async Task ExecuteAsync_WhenUserRepoThrows_ExceptionPropagates()
    {
        _reportRepoMock
            .Setup(r => r.GetByIdAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Report(1, "title", "body", []));
        _userRepoMock
            .Setup(r => r.GetByIdsAsync(It.IsAny<IEnumerable<int>>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("User service timeout"));

        await Assert.ThrowsAsync<Exception>(() => CreateJob().ExecuteAsync(1, [10]));
    }

    [Fact]
    public async Task ExecuteAsync_WhenSftpThrows_ExceptionPropagates()
    {
        SetupDefaults(reportId: 1);
        _sftpMock
            .Setup(s => s.UploadAsync(It.IsAny<Stream>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("SFTP connection refused"));

        await Assert.ThrowsAsync<Exception>(() => CreateJob().ExecuteAsync(1, [10]));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void SetupDefaults(int reportId)
    {
        _reportRepoMock
            .Setup(r => r.GetByIdAsync(reportId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Report(reportId, "title", "body", []));

        _userRepoMock
            .Setup(r => r.GetByIdsAsync(It.IsAny<IEnumerable<int>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync([new User(10, "Alice", "alice@example.com")]);

        _sftpMock
            .Setup(s => s.UploadAsync(It.IsAny<Stream>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
    }
}
