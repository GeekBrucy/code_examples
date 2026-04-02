using Api.Filters;
using Api.Repositories;
using Api.Services;
using Hangfire;

namespace Api.Jobs;

[AutomaticRetry(Attempts = 5, OnAttemptsExceeded = AttemptsExceededAction.Fail)]
[NotifyOnFailure]
public class GenerateReportJob
{
    private readonly IReportRepository _reportRepo;
    private readonly IUserRepository _userRepo;
    private readonly ReportTransformer _transformer;
    private readonly ReportZipBuilder _zipBuilder;
    private readonly ISftpClient _sftpClient;
    private readonly ILogger<GenerateReportJob> _logger;

    public GenerateReportJob(
        IReportRepository reportRepo,
        IUserRepository userRepo,
        ReportTransformer transformer,
        ReportZipBuilder zipBuilder,
        ISftpClient sftpClient,
        ILogger<GenerateReportJob> logger)
    {
        _reportRepo = reportRepo;
        _userRepo = userRepo;
        _transformer = transformer;
        _zipBuilder = zipBuilder;
        _sftpClient = sftpClient;
        _logger = logger;
    }

    public async Task ExecuteAsync(int reportId, int[] userIds)
    {
        _logger.LogInformation("GenerateReportJob starting for report {ReportId}", reportId);

        var report = await _reportRepo.GetByIdAsync(reportId);
        var users = await _userRepo.GetByIdsAsync(userIds);

        var viewModel = _transformer.Transform(report, users);

        using var zipStream = _zipBuilder.Build(viewModel, report.Attachments);

        var remotePath = $"reports/{reportId}.zip";
        await _sftpClient.UploadAsync(zipStream, remotePath);

        _logger.LogInformation("GenerateReportJob complete. Uploaded to {RemotePath}", remotePath);
    }
}
