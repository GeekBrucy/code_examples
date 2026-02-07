namespace file_upload_sftp.Dtos
{
    public sealed record SftpUploadRequest(
        string RemoteDirectory,   // e.g. "/outbound/partnerA"
        string FileName,          // e.g. "event_....json"
        string JsonContent        // serialized payload
    );
}