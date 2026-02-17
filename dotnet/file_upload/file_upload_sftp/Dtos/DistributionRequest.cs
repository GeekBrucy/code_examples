namespace file_upload_sftp.Dtos;

/// <summary>
/// Manual refer: explicitly distribute a report to additional external users.
/// </summary>
public sealed record ManualReferRequest(
    int ReportId,
    List<int> ExternalUserIds
);
