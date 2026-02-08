namespace file_upload_sftp.Settings;

public sealed class OutboxOptions
{
    public int PollingIntervalSeconds { get; init; } = 10;
    public int MaxAttempts { get; init; } = 5;
    public int BatchSize { get; init; } = 20;
}
