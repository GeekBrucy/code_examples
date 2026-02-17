namespace file_upload_zip.Services;

public interface IZipService
{
    /// <summary>
    /// Creates a zip archive containing both in-memory content and physical files,
    /// then saves it to the specified output path.
    /// </summary>
    Task CreateZipAsync(ZipRequest request, CancellationToken ct = default);
}

public sealed class ZipRequest
{
    /// <summary>Full path where the .zip file will be written.</summary>
    public required string OutputPath { get; init; }

    /// <summary>In-memory content to include (e.g. generated CSV, JSON, etc.).</summary>
    public List<MemoryEntry> MemoryEntries { get; init; } = [];

    /// <summary>Physical files on disk to include.</summary>
    public List<FileEntry> FileEntries { get; init; } = [];
}

/// <summary>Represents in-memory bytes to add into the zip.</summary>
public sealed class MemoryEntry
{
    /// <summary>The filename as it will appear inside the zip (e.g. "reports/summary.csv").</summary>
    public required string EntryName { get; init; }

    /// <summary>The in-memory content.</summary>
    public required MemoryStream Content { get; init; }
}

/// <summary>Represents a physical file on disk to add into the zip.</summary>
public sealed class FileEntry
{
    /// <summary>Full path to the file on disk.</summary>
    public required string SourcePath { get; init; }

    /// <summary>The filename as it will appear inside the zip (e.g. "data/input.txt").
    /// This lets you control the name/path inside the archive independently of the source path.</summary>
    public required string EntryName { get; init; }
}
