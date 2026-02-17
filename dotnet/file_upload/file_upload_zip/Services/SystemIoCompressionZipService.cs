// ============================================================================
// Library: System.IO.Compression (built-in, no NuGet package needed)
//
// - Ships with .NET, zero dependencies.
// - ZipArchive class supports Create, Read, and Update modes.
// - Good for most scenarios; limited control over low-level zip options.
// ============================================================================

using System.IO.Compression;

namespace file_upload_zip.Services;

public sealed class SystemIoCompressionZipService : IZipService
{
    private readonly ILogger<SystemIoCompressionZipService> _log;

    public SystemIoCompressionZipService(ILogger<SystemIoCompressionZipService> log)
    {
        _log = log;
    }

    public async Task CreateZipAsync(ZipRequest request, CancellationToken ct = default)
    {
        var dir = Path.GetDirectoryName(request.OutputPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        // Use a FileStream so the zip is written directly to disk (not buffered entirely in memory).
        await using var fileStream = new FileStream(
            request.OutputPath, FileMode.Create, FileAccess.Write, FileShare.None,
            bufferSize: 4096, useAsync: true);

        // ZipArchive in Create mode — entries are written sequentially and the archive
        // is finalized when the ZipArchive is disposed.
        using var archive = new ZipArchive(fileStream, ZipArchiveMode.Create, leaveOpen: false);

        // --- Add in-memory streams ---
        foreach (var mem in request.MemoryEntries)
        {
            ct.ThrowIfCancellationRequested();

            // CreateEntry lets you set the entry name (path inside the zip).
            // CompressionLevel controls the trade-off between size and speed.
            var entry = archive.CreateEntry(mem.EntryName, CompressionLevel.Optimal);

            using var entryStream = entry.Open();

            // Reset the MemoryStream position in case the caller already wrote to it.
            mem.Content.Position = 0;
            await mem.Content.CopyToAsync(entryStream, ct);

            _log.LogInformation("Added memory entry: {EntryName} ({Bytes} bytes)",
                mem.EntryName, mem.Content.Length);
        }

        // --- Add physical files from disk ---
        foreach (var file in request.FileEntries)
        {
            ct.ThrowIfCancellationRequested();

            if (!File.Exists(file.SourcePath))
                throw new FileNotFoundException($"Source file not found: {file.SourcePath}");

            // CreateEntryFromFile is a convenience method that reads a file from disk
            // and writes it into the archive with the specified entry name.
            archive.CreateEntryFromFile(file.SourcePath, file.EntryName, CompressionLevel.Optimal);

            _log.LogInformation("Added file entry: {SourcePath} -> {EntryName}",
                file.SourcePath, file.EntryName);
        }

        _log.LogInformation("Zip created at {OutputPath}", request.OutputPath);
    }
}
