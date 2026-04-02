namespace Api.Models;

public record Report(
    int Id,
    string Title,
    string Content,
    IReadOnlyList<ReportAttachment> Attachments);

public record ReportAttachment(string FileName, byte[] Content);
