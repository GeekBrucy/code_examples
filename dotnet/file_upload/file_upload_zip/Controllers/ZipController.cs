using System.Text;
using file_upload_zip.Services;
using Microsoft.AspNetCore.Mvc;

namespace file_upload_zip.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ZipController : ControllerBase
{
    private readonly SystemIoCompressionZipService _builtInZip;
    private readonly SharpZipLibZipService _sharpZip;

    public ZipController(
        SystemIoCompressionZipService builtInZip,
        SharpZipLibZipService sharpZip)
    {
        _builtInZip = builtInZip;
        _sharpZip = sharpZip;
    }

    /// <summary>
    /// Creates a zip using System.IO.Compression (built-in).
    /// Demonstrates adding both in-memory content and physical files.
    /// </summary>
    [HttpPost("system-io-compression")]
    public async Task<IActionResult> CreateWithBuiltIn(CancellationToken ct)
    {
        var outputPath = Path.Combine(Path.GetTempPath(), "zip_examples", "builtin_output.zip");

        var request = BuildSampleRequest(outputPath);

        await _builtInZip.CreateZipAsync(request, ct);

        return Ok(new { message = "Zip created with System.IO.Compression", path = outputPath });
    }

    /// <summary>
    /// Creates a zip using SharpZipLib (third-party).
    /// Demonstrates adding both in-memory content and physical files.
    /// </summary>
    [HttpPost("sharpziplib")]
    public async Task<IActionResult> CreateWithSharpZipLib(CancellationToken ct)
    {
        var outputPath = Path.Combine(Path.GetTempPath(), "zip_examples", "sharpziplib_output.zip");

        var request = BuildSampleRequest(outputPath);

        await _sharpZip.CreateZipAsync(request, ct);

        return Ok(new { message = "Zip created with SharpZipLib", path = outputPath });
    }

    /// <summary>
    /// Builds a sample ZipRequest that includes:
    /// - Two in-memory entries (a generated CSV and a JSON document)
    /// - One physical file (the project's appsettings.json as a stand-in)
    ///
    /// Note how EntryName controls the filename/path inside the zip,
    /// independent of where the data comes from.
    /// </summary>
    private static ZipRequest BuildSampleRequest(string outputPath)
    {
        // --- In-memory content: pretend we generated a CSV report ---
        var csvContent = "Id,Name,Amount\n1,Alice,100.50\n2,Bob,200.75\n";
        var csvStream = new MemoryStream(Encoding.UTF8.GetBytes(csvContent));

        // --- In-memory content: pretend we serialized a JSON summary ---
        var jsonContent = """{"generated":"2024-01-15","totalRecords":2}""";
        var jsonStream = new MemoryStream(Encoding.UTF8.GetBytes(jsonContent));

        // --- Physical file: use appsettings.json as a sample file on disk ---
        var physicalFilePath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");

        return new ZipRequest
        {
            OutputPath = outputPath,
            MemoryEntries =
            [
                // EntryName sets the filename inside the zip.
                // You can use subdirectories like "reports/monthly-report.csv".
                new MemoryEntry
                {
                    EntryName = "reports/monthly-report.csv",
                    Content = csvStream
                },
                new MemoryEntry
                {
                    EntryName = "metadata/summary.json",
                    Content = jsonStream
                }
            ],
            FileEntries =
            [
                // SourcePath is the actual file on disk.
                // EntryName is the name it will have inside the zip (completely independent).
                new FileEntry
                {
                    SourcePath = physicalFilePath,
                    EntryName = "config/app-settings.json"
                }
            ]
        };
    }
}
