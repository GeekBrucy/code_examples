using Api.Models;

namespace Api.Services;

// Pure transformation — no I/O, no side effects. No interface needed.
public class ReportTransformer
{
    public ReportViewModel Transform(Report report, IReadOnlyList<User> users)
    {
        var userSummaries = users
            .Select(u => new UserSummary(u.Id, u.Name))
            .ToList();

        return new ReportViewModel(report.Id, report.Title, report.Content, userSummaries);
    }
}
