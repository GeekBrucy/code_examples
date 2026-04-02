namespace Api.Models;

public record ReportViewModel(
    int ReportId,
    string Title,
    string Content,
    IReadOnlyList<UserSummary> Users);

public record UserSummary(int UserId, string Name);
