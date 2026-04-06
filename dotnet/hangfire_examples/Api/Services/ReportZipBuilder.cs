using System.IO.Compression;
using System.Text.Json;
using Api.Models;

namespace Api.Services;

// Pure zip construction — no I/O, no side effects. No interface needed.
public class ReportZipBuilder
{
    public MemoryStream Build(ReportViewModel viewModel, IReadOnlyList<ReportAttachment> attachments)
    {
        var ms = new MemoryStream();

        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteJson(archive, viewModel);

            foreach (var attachment in attachments)
                WriteAttachment(archive, attachment);
        }

        ms.Position = 0;
        return ms;
    }

    private static void WriteJson(ZipArchive archive, ReportViewModel viewModel)
    {
        var entry = archive.CreateEntry("report.json");
        using var writer = new StreamWriter(entry.Open());
        writer.Write(JsonSerializer.Serialize(viewModel));
    }

    private static void WriteAttachment(ZipArchive archive, ReportAttachment attachment)
    {
        var entry = archive.CreateEntry($"attachments/{attachment.FileName}");
        using var stream = entry.Open();
        stream.Write(attachment.Content);
    }
}
