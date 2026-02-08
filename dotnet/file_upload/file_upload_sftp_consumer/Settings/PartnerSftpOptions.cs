namespace file_upload_sftp_consumer.Settings;

public sealed class SftpHostOptions
{
    public required string Host { get; init; }
    public int Port { get; init; } = 22;
}

public sealed class PartnerCredentials
{
    public required string Username { get; init; }
    public required string Password { get; init; }
}
