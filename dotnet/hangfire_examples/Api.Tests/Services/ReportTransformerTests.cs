using Api.Models;
using Api.Services;

namespace Api.Tests.Services;

public class ReportTransformerTests
{
    private readonly ReportTransformer _transformer = new();

    [Fact]
    public void Transform_MapsReportFields()
    {
        var report = new Report(1, "Q1 Report", "content", []);
        var users = Array.Empty<User>();

        var result = _transformer.Transform(report, users);

        Assert.Equal(1, result.ReportId);
        Assert.Equal("Q1 Report", result.Title);
        Assert.Equal("content", result.Content);
    }

    [Fact]
    public void Transform_MapsEachUserToSummary()
    {
        var report = new Report(1, "title", "body", []);
        var users = new User[]
        {
            new(10, "Alice", "alice@example.com"),
            new(20, "Bob",   "bob@example.com"),
        };

        var result = _transformer.Transform(report, users);

        Assert.Equal(2, result.Users.Count);
        Assert.Contains(result.Users, u => u.UserId == 10 && u.Name == "Alice");
        Assert.Contains(result.Users, u => u.UserId == 20 && u.Name == "Bob");
    }

    [Fact]
    public void Transform_WithNoUsers_ReturnsEmptyUserList()
    {
        var report = new Report(1, "title", "body", []);

        var result = _transformer.Transform(report, []);

        Assert.Empty(result.Users);
    }
}
