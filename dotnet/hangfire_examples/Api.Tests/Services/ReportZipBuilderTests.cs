using System.IO.Compression;
using System.Text.Json;
using Api.Models;
using Api.Services;

namespace Api.Tests.Services;

public class ReportZipBuilderTests
{
    private readonly ReportZipBuilder _builder = new();

    [Fact]
    public void Build_ZipContainsReportJson()
    {
        var viewModel = new ReportViewModel(1, "title", "body", []);

        using var zip = _builder.Build(viewModel, []);

        var entries = OpenEntries(zip);
        Assert.Contains("report.json", entries.Keys);
    }

    [Fact]
    public void Build_ReportJsonDeserializesCorrectly()
    {
        var viewModel = new ReportViewModel(42, "My Report", "content here", []);

        using var zip = _builder.Build(viewModel, []);

        var entries = OpenEntries(zip);
        var json = entries["report.json"];
        var deserialized = JsonSerializer.Deserialize<ReportViewModel>(json)!;

        Assert.Equal(42, deserialized.ReportId);
        Assert.Equal("My Report", deserialized.Title);
    }

    [Fact]
    public void Build_AttachmentsArePlacedUnderAttachmentsFolder()
    {
        var viewModel = new ReportViewModel(1, "title", "body", []);
        var attachments = new ReportAttachment[]
        {
            new("chart.png", [1, 2, 3]),
            new("data.csv", [4, 5, 6]),
        };

        using var zip = _builder.Build(viewModel, attachments);

        var entries = OpenEntries(zip);
        Assert.Contains("attachments/chart.png", entries.Keys);
        Assert.Contains("attachments/data.csv", entries.Keys);
    }

    [Fact]
    public void Build_AttachmentContentIsPreserved()
    {
        var viewModel = new ReportViewModel(1, "title", "body", []);
        var expectedBytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var attachments = new ReportAttachment[] { new("file.bin", expectedBytes) };

        using var zip = _builder.Build(viewModel, attachments);

        var entries = OpenEntries(zip);
        var rawEntry = ReadRawEntry(zip, "attachments/file.bin");
        Assert.Equal(expectedBytes, rawEntry);
    }

    [Fact]
    public void Build_StreamIsPositionedAtZero()
    {
        var viewModel = new ReportViewModel(1, "title", "body", []);

        using var zip = _builder.Build(viewModel, []);

        Assert.Equal(0, zip.Position);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Dictionary<string, string> OpenEntries(MemoryStream ms)
    {
        ms.Position = 0;
        using var archive = new ZipArchive(ms, ZipArchiveMode.Read, leaveOpen: true);
        return archive.Entries.ToDictionary(
            e => e.FullName,
            e => { using var r = new StreamReader(e.Open()); return r.ReadToEnd(); });
    }

    private static byte[] ReadRawEntry(MemoryStream ms, string entryName)
    {
        ms.Position = 0;
        using var archive = new ZipArchive(ms, ZipArchiveMode.Read, leaveOpen: true);
        var entry = archive.GetEntry(entryName)!;
        using var stream = entry.Open();
        using var buf = new MemoryStream();
        stream.CopyTo(buf);
        return buf.ToArray();
    }
}
