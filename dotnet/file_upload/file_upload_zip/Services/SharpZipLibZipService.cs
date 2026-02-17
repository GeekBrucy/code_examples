// ============================================================================
// Library: SharpZipLib (NuGet: SharpZipLib)
//
// - Popular open-source library with fine-grained control over compression.
// - Supports ZIP, GZip, Tar, and BZip2.
// - Gives access to low-level zip options: compression method, encryption,
//   password protection, custom extra fields, etc.
// - Use when you need features beyond what System.IO.Compression offers.
// ============================================================================

using ICSharpCode.SharpZipLib.Zip;

namespace file_upload_zip.Services;

public sealed class SharpZipLibZipService : IZipService
{
    private readonly ILogger<SharpZipLibZipService> _log;

    public SharpZipLibZipService(ILogger<SharpZipLibZipService> log)
    {
        _log = log;
    }

    public async Task CreateZipAsync(ZipRequest request, CancellationToken ct = default)
    {
        var dir = Path.GetDirectoryName(request.OutputPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        // ZipOutputStream writes entries sequentially — good for streaming large archives.
        // SharpZipLib's zip classes are synchronous, so we wrap in Task.Run.
        await Task.Run(() =>
        {
            using var fileStream = new FileStream(
                request.OutputPath, FileMode.Create, FileAccess.Write, FileShare.None);

            using var zipStream = new ZipOutputStream(fileStream);

            // Set overall compression level (0 = store, 9 = maximum compression).
            zipStream.SetLevel(6);

            // --- Add in-memory streams ---
            foreach (var mem in request.MemoryEntries)
            {
                ct.ThrowIfCancellationRequested();

                // ZipEntry represents a single file inside the archive.
                // The constructor takes the entry name (path inside the zip).
                var entry = new ZipEntry(mem.EntryName)
                {
                    // DateTime is the last-modified timestamp stored in the zip.
                    DateTime = DateTime.UtcNow,
                    // Size hint helps SharpZipLib optimize — set it when known.
                    Size = mem.Content.Length
                };

                zipStream.PutNextEntry(entry);

                mem.Content.Position = 0;
                mem.Content.CopyTo(zipStream);

                zipStream.CloseEntry();

                _log.LogInformation("Added memory entry: {EntryName} ({Bytes} bytes)",
                    mem.EntryName, mem.Content.Length);
            }

            // --- Add physical files from disk ---
            foreach (var file in request.FileEntries)
            {
                ct.ThrowIfCancellationRequested();

                if (!File.Exists(file.SourcePath))
                    throw new FileNotFoundException($"Source file not found: {file.SourcePath}");

                var fileInfo = new FileInfo(file.SourcePath);
                var entry = new ZipEntry(file.EntryName)
                {
                    DateTime = fileInfo.LastWriteTimeUtc,
                    Size = fileInfo.Length
                };

                zipStream.PutNextEntry(entry);

                using var sourceStream = File.OpenRead(file.SourcePath);
                sourceStream.CopyTo(zipStream);

                zipStream.CloseEntry();

                _log.LogInformation("Added file entry: {SourcePath} -> {EntryName}",
                    file.SourcePath, file.EntryName);
            }

        }, ct);

        _log.LogInformation("Zip created at {OutputPath}", request.OutputPath);
    }
}
