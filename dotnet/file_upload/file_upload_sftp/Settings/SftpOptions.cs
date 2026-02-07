namespace file_upload_sftp.Settings
{
    public sealed class SftpOptions
    {
        public required string Host { get; init; }
        public int Port { get; init; } = 22;
        public required string Username { get; init; }
        public required string Password { get; init; }
    }
}