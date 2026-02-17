using System.IO.Compression;
using System.Text;
using file_upload_zip.Services;

namespace file_upload_zip.Tests.Services;

/// <summary>
/// Shared test cases for any IZipService implementation.
/// Each concrete test class only needs to supply the service instance via CreateService().
/// </summary>
public abstract class ZipServiceTestBase : IDisposable
{
    private readonly string _tempDir;

    protected ZipServiceTestBase()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "zip_tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    protected abstract IZipService CreateService();

    private string OutputPath(string name = "test.zip") => Path.Combine(_tempDir, name);

    private string CreatePhysicalFile(string name, string content)
    {
        var path = Path.Combine(_tempDir, name);
        File.WriteAllText(path, content);
        return path;
    }

    // ── Memory entry tests ──────────────────────────────────────────

    [Fact]
    public async Task MemoryEntry_WrittenWithCorrectNameAndContent()
    {
        var csv = "Id,Name\n1,Alice\n";
        var request = new ZipRequest
        {
            OutputPath = OutputPath(),
            MemoryEntries =
            [
                new MemoryEntry
                {
                    EntryName = "data.csv",
                    Content = new MemoryStream(Encoding.UTF8.GetBytes(csv))
                }
            ]
        };

        await CreateService().CreateZipAsync(request);

        using var zip = ZipFile.OpenRead(request.OutputPath);
        var entry = Assert.Single(zip.Entries);
        Assert.Equal("data.csv", entry.FullName);
        Assert.Equal(csv, await ReadEntryAsync(entry));
    }

    [Fact]
    public async Task MemoryEntry_SubdirectoryEntryName_PreservesPath()
    {
        var json = """{"ok":true}""";
        var request = new ZipRequest
        {
            OutputPath = OutputPath(),
            MemoryEntries =
            [
                new MemoryEntry
                {
                    EntryName = "reports/2024/summary.json",
                    Content = new MemoryStream(Encoding.UTF8.GetBytes(json))
                }
            ]
        };

        await CreateService().CreateZipAsync(request);

        using var zip = ZipFile.OpenRead(request.OutputPath);
        var entry = Assert.Single(zip.Entries);
        Assert.Equal("reports/2024/summary.json", entry.FullName);
        Assert.Equal(json, await ReadEntryAsync(entry));
    }

    [Fact]
    public async Task MemoryEntry_MultipleEntries_AllPresent()
    {
        var request = new ZipRequest
        {
            OutputPath = OutputPath(),
            MemoryEntries =
            [
                new MemoryEntry
                {
                    EntryName = "a.txt",
                    Content = new MemoryStream(Encoding.UTF8.GetBytes("aaa"))
                },
                new MemoryEntry
                {
                    EntryName = "b.txt",
                    Content = new MemoryStream(Encoding.UTF8.GetBytes("bbb"))
                }
            ]
        };

        await CreateService().CreateZipAsync(request);

        using var zip = ZipFile.OpenRead(request.OutputPath);
        Assert.Equal(2, zip.Entries.Count);

        var names = zip.Entries.Select(e => e.FullName).OrderBy(n => n).ToList();
        Assert.Equal(["a.txt", "b.txt"], names);
    }

    // ── File entry tests ────────────────────────────────────────────

    [Fact]
    public async Task FileEntry_WrittenWithCorrectNameAndContent()
    {
        var filePath = CreatePhysicalFile("source.txt", "hello world");

        var request = new ZipRequest
        {
            OutputPath = OutputPath(),
            FileEntries =
            [
                new FileEntry
                {
                    SourcePath = filePath,
                    EntryName = "renamed.txt"
                }
            ]
        };

        await CreateService().CreateZipAsync(request);

        using var zip = ZipFile.OpenRead(request.OutputPath);
        var entry = Assert.Single(zip.Entries);
        Assert.Equal("renamed.txt", entry.FullName);
        Assert.Equal("hello world", await ReadEntryAsync(entry));
    }

    [Fact]
    public async Task FileEntry_SubdirectoryEntryName_PreservesPath()
    {
        var filePath = CreatePhysicalFile("flat.txt", "content");

        var request = new ZipRequest
        {
            OutputPath = OutputPath(),
            FileEntries =
            [
                new FileEntry
                {
                    SourcePath = filePath,
                    EntryName = "nested/folder/flat.txt"
                }
            ]
        };

        await CreateService().CreateZipAsync(request);

        using var zip = ZipFile.OpenRead(request.OutputPath);
        var entry = Assert.Single(zip.Entries);
        Assert.Equal("nested/folder/flat.txt", entry.FullName);
    }

    [Fact]
    public async Task FileEntry_MissingSourceFile_ThrowsFileNotFoundException()
    {
        var request = new ZipRequest
        {
            OutputPath = OutputPath(),
            FileEntries =
            [
                new FileEntry
                {
                    SourcePath = Path.Combine(_tempDir, "does_not_exist.txt"),
                    EntryName = "missing.txt"
                }
            ]
        };

        await Assert.ThrowsAsync<FileNotFoundException>(
            () => CreateService().CreateZipAsync(request));
    }

    // ── Mixed entry tests ───────────────────────────────────────────

    [Fact]
    public async Task MixedEntries_BothMemoryAndFileEntriesPresent()
    {
        var filePath = CreatePhysicalFile("on-disk.txt", "disk content");

        var request = new ZipRequest
        {
            OutputPath = OutputPath(),
            MemoryEntries =
            [
                new MemoryEntry
                {
                    EntryName = "memory/generated.csv",
                    Content = new MemoryStream(Encoding.UTF8.GetBytes("col1,col2\n1,2\n"))
                }
            ],
            FileEntries =
            [
                new FileEntry
                {
                    SourcePath = filePath,
                    EntryName = "files/on-disk.txt"
                }
            ]
        };

        await CreateService().CreateZipAsync(request);

        using var zip = ZipFile.OpenRead(request.OutputPath);
        Assert.Equal(2, zip.Entries.Count);

        var names = zip.Entries.Select(e => e.FullName).OrderBy(n => n).ToList();
        Assert.Equal(["files/on-disk.txt", "memory/generated.csv"], names);

        var memEntry = zip.GetEntry("memory/generated.csv")!;
        Assert.Equal("col1,col2\n1,2\n", await ReadEntryAsync(memEntry));

        var fileEntry = zip.GetEntry("files/on-disk.txt")!;
        Assert.Equal("disk content", await ReadEntryAsync(fileEntry));
    }

    [Fact]
    public async Task EmptyRequest_CreatesValidEmptyZip()
    {
        var request = new ZipRequest { OutputPath = OutputPath() };

        await CreateService().CreateZipAsync(request);

        Assert.True(File.Exists(request.OutputPath));
        using var zip = ZipFile.OpenRead(request.OutputPath);
        Assert.Empty(zip.Entries);
    }

    // ── Helper ──────────────────────────────────────────────────────

    private static async Task<string> ReadEntryAsync(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }
}
