using System.Net.Http.Headers;
using System.Text;

namespace PartialDownloadClient;

class Program
{
    private static readonly HttpClient httpClient = new();
    private const string BaseUrl = "http://localhost:5108/api/chunkeddownload";

    static async Task Main(string[] args)
    {
        Console.WriteLine("=== Chunked Download Client Demo ===\n");

        try
        {
            // Console.WriteLine("1. Listing available test files...");
            // await ListFiles();

            // Console.WriteLine("\n2. Testing small file (should download directly)...");
            // await TestDirectDownload(1); // 1KB file

            // Console.WriteLine("\n3. Testing medium file (should download directly)...");
            // await TestDirectDownload(2); // 5MB file

            // Console.WriteLine("\n4. Testing large file (should require chunking)...");
            // await TestLargeFileDownload(3); // 25MB file

            // Console.WriteLine("\n5. Testing huge file with full chunked download...");
            // await TestFullChunkedDownload(4); // 45MB file

            Console.WriteLine("\n6. Testing individual chunk download...");
            // await TestSingleChunk(3, 1); // Second chunk of 25MB file
            await TestSingleChunk(5, 1);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    static async Task ListFiles()
    {
        try
        {
            var response = await httpClient.GetAsync($"{BaseUrl}/list");
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine("Available files:");
                Console.WriteLine(content);
            }
            else
            {
                Console.WriteLine($"Failed to list files: {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error listing files: {ex.Message}");
        }
    }

    static async Task TestDirectDownload(int fileId)
    {
        try
        {
            Console.WriteLine($"Testing direct download for file {fileId}...");

            var response = await httpClient.GetAsync($"{BaseUrl}/download/{fileId}");

            Console.WriteLine($"Status: {response.StatusCode}");
            Console.WriteLine($"Content-Type: {response.Content.Headers.ContentType}");
            Console.WriteLine($"Content-Length: {response.Content.Headers.ContentLength}");

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsByteArrayAsync();
                Console.WriteLine($"✅ Downloaded {content.Length:N0} bytes directly");

                // Save to file with proper extension
                var extension = GetExtensionFromContentType(response.Content.Headers.ContentType?.MediaType);
                var fileName = $"downloaded_file_{fileId}{extension}";
                await File.WriteAllBytesAsync(fileName, content);
                Console.WriteLine($"   Saved as: {fileName}");
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"❌ Error: {errorContent}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in direct download: {ex.Message}");
        }
    }

    static async Task TestLargeFileDownload(int fileId)
    {
        try
        {
            Console.WriteLine($"Testing large file download for file {fileId}...");

            // First try without chunk parameter
            var response = await httpClient.GetAsync($"{BaseUrl}/download/{fileId}");

            Console.WriteLine($"Status: {response.StatusCode}");

            if (response.StatusCode == System.Net.HttpStatusCode.BadRequest)
            {
                var guidance = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"✅ Received chunking guidance: {guidance}");
            }
            else
            {
                Console.WriteLine($"❌ Unexpected response for large file");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error testing large file: {ex.Message}");
        }
    }

    static async Task TestSingleChunk(int fileId, int chunkIndex)
    {
        try
        {
            Console.WriteLine($"Testing chunk {chunkIndex} download for file {fileId}...");

            var response = await httpClient.GetAsync($"{BaseUrl}/download/{fileId}?chunkIndex={chunkIndex}");

            Console.WriteLine($"Status: {response.StatusCode}");
            Console.WriteLine($"Content-Range: {response.Content.Headers.ContentRange}");
            Console.WriteLine($"Content-Length: {response.Content.Headers.ContentLength}");

            // Check custom headers
            if (response.Headers.TryGetValues("X-Chunk-Index", out var chunkIndexValues))
                Console.WriteLine($"X-Chunk-Index: {string.Join(", ", chunkIndexValues)}");

            if (response.Headers.TryGetValues("X-Total-Chunks", out var totalChunksValues))
                Console.WriteLine($"X-Total-Chunks: {string.Join(", ", totalChunksValues)}");

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsByteArrayAsync();
                Console.WriteLine($"✅ Downloaded chunk {chunkIndex}: {content.Length:N0} bytes");

                // Save chunk to file with proper extension
                var extension = GetExtensionFromContentType(response.Content.Headers.ContentType?.MediaType);
                var fileName = $"chunk_{fileId}_{chunkIndex}{extension}";
                await File.WriteAllBytesAsync(fileName, content);
                Console.WriteLine($"   Saved as: {fileName}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error downloading chunk: {ex.Message}");
        }
    }

    static async Task TestFullChunkedDownload(int fileId)
    {
        try
        {
            Console.WriteLine($"Testing full chunked download for file {fileId}...");

            // Get file info first
            var infoResponse = await httpClient.GetAsync($"{BaseUrl}/info/{fileId}");
            if (!infoResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("❌ Could not get file info");
                return;
            }

            var infoContent = await infoResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"File info: {infoContent}");

            // Extract total chunks (simple parsing for demo)
            var totalChunks = ExtractTotalChunks(infoContent);
            if (totalChunks <= 0)
            {
                Console.WriteLine("❌ Could not determine total chunks");
                return;
            }

            Console.WriteLine($"Downloading {totalChunks} chunks...");
            var allChunks = new List<byte[]>();

            for (int i = 0; i < totalChunks; i++)
            {
                var response = await httpClient.GetAsync($"{BaseUrl}/download/{fileId}?chunkIndex={i}");

                if (response.IsSuccessStatusCode)
                {
                    var chunkData = await response.Content.ReadAsByteArrayAsync();
                    allChunks.Add(chunkData);

                    var progress = (i + 1) * 100.0 / totalChunks;
                    Console.WriteLine($"   Chunk {i}: {chunkData.Length:N0} bytes | Progress: {progress:F1}%");
                }
                else
                {
                    Console.WriteLine($"❌ Failed to download chunk {i}: {response.StatusCode}");
                    return;
                }
            }

            // Combine all chunks
            var totalSize = allChunks.Sum(c => c.Length);
            var completeFile = new byte[totalSize];
            var position = 0;

            foreach (var chunk in allChunks)
            {
                Array.Copy(chunk, 0, completeFile, position, chunk.Length);
                position += chunk.Length;
            }

            // Save complete file with proper extension
            var extension = GetOriginalExtension(infoContent, fileId);
            var fileName = $"complete_file_{fileId}{extension}";
            await File.WriteAllBytesAsync(fileName, completeFile);
            Console.WriteLine($"✅ Complete file assembled: {totalSize:N0} bytes");
            Console.WriteLine($"   Saved as: {fileName}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in full chunked download: {ex.Message}");
        }
    }

    static int ExtractTotalChunks(string jsonContent)
    {
        try
        {
            // Simple extraction for demo - in real app use JSON parsing
            var match = System.Text.RegularExpressions.Regex.Match(jsonContent, @"""totalChunks"":\s*(\d+)");
            if (match.Success && int.TryParse(match.Groups[1].Value, out var chunks))
                return chunks;
        }
        catch { }
        return 0;
    }

    static string GetExtensionFromContentType(string? contentType)
    {
        return contentType switch
        {
            "text/plain" => ".txt",
            "image/jpeg" => ".jpg",
            "video/mp4" => ".mp4",
            "application/zip" => ".zip",
            "image/png" => ".png",
            "application/pdf" => ".pdf",
            _ => ".bin"
        };
    }

    static string GetOriginalExtension(string jsonContent, int fileId)
    {
        try
        {
            // Extract original filename from JSON response
            var match = System.Text.RegularExpressions.Regex.Match(jsonContent, @"""fileName"":\s*""([^""]+)""");
            if (match.Success)
            {
                var fileName = match.Groups[1].Value;
                var lastDot = fileName.LastIndexOf('.');
                if (lastDot >= 0)
                    return fileName.Substring(lastDot);
            }

            // Fallback: extract from content type
            var contentTypeMatch = System.Text.RegularExpressions.Regex.Match(jsonContent, @"""contentType"":\s*""([^""]+)""");
            if (contentTypeMatch.Success)
            {
                return GetExtensionFromContentType(contentTypeMatch.Groups[1].Value);
            }
        }
        catch { }
        return ".bin";
    }
}
