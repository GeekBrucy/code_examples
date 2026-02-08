namespace file_upload_sftp.Dtos;

public sealed record DistributionRequest(
    string RecordId,
    List<string> PartnerIds,
    List<FilePayload> Files
);

public sealed record FilePayload(
    string Name,
    string ContentBase64,
    string ContentType
);
