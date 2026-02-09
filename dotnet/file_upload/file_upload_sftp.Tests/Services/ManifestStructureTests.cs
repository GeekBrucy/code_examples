using System.Text.Json;
using file_upload_sftp.Services;

namespace file_upload_sftp.Tests.Services;

/// <summary>
/// Validates that BuildManifest produces JSON conforming to the agreed contract.
/// External consumers (partners) parse this structure — breaking changes are silent failures.
/// </summary>
public sealed class ManifestStructureTests
{
    private static readonly List<SftpDeliveryService.ManifestFileEntry> SampleFiles =
    [
        new("report_1.json", 4523, "application/json", "abc123def456"),
        new("evidence.pdf", 102400, "application/pdf", "789xyz000111")
    ];

    [Fact]
    public void Manifest_HasRequiredTopLevelFields()
    {
        var json = SftpDeliveryService.BuildManifest(42, "partnerA", SampleFiles);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("reportId", out var reportId));
        Assert.Equal(42, reportId.GetInt32());

        Assert.True(root.TryGetProperty("sftpDirectory", out var sftpDir));
        Assert.Equal("partnerA", sftpDir.GetString());

        Assert.True(root.TryGetProperty("uploadedAt", out var uploadedAt));
        // Must be ISO 8601 parseable
        Assert.True(DateTime.TryParse(uploadedAt.GetString(), out _));

        Assert.True(root.TryGetProperty("files", out var files));
        Assert.Equal(JsonValueKind.Array, files.ValueKind);
    }

    [Fact]
    public void Manifest_FilesArrayHasRequiredFields()
    {
        var json = SftpDeliveryService.BuildManifest(1, "partnerA", SampleFiles);
        using var doc = JsonDocument.Parse(json);
        var files = doc.RootElement.GetProperty("files");

        Assert.Equal(2, files.GetArrayLength());

        foreach (var file in files.EnumerateArray())
        {
            Assert.True(file.TryGetProperty("name", out _), "Missing 'name' field");
            Assert.True(file.TryGetProperty("size", out _), "Missing 'size' field");
            Assert.True(file.TryGetProperty("contentType", out _), "Missing 'contentType' field");
            Assert.True(file.TryGetProperty("sha256", out _), "Missing 'sha256' field");
        }
    }

    [Fact]
    public void Manifest_FileValuesMatchInput()
    {
        var json = SftpDeliveryService.BuildManifest(1, "partnerA", SampleFiles);
        using var doc = JsonDocument.Parse(json);
        var firstFile = doc.RootElement.GetProperty("files")[0];

        Assert.Equal("report_1.json", firstFile.GetProperty("name").GetString());
        Assert.Equal(4523, firstFile.GetProperty("size").GetInt64());
        Assert.Equal("application/json", firstFile.GetProperty("contentType").GetString());
        Assert.Equal("abc123def456", firstFile.GetProperty("sha256").GetString());
    }

    [Fact]
    public void Manifest_HasNoUnexpectedTopLevelFields()
    {
        var json = SftpDeliveryService.BuildManifest(1, "partnerA", SampleFiles);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var expectedFields = new HashSet<string> { "reportId", "sftpDirectory", "uploadedAt", "files" };
        var actualFields = root.EnumerateObject().Select(p => p.Name).ToHashSet();

        Assert.Equal(expectedFields, actualFields);
    }

    [Fact]
    public void Manifest_EmptyFilesListProducesEmptyArray()
    {
        var json = SftpDeliveryService.BuildManifest(1, "partnerA", []);
        using var doc = JsonDocument.Parse(json);
        var files = doc.RootElement.GetProperty("files");

        Assert.Equal(0, files.GetArrayLength());
    }
}
