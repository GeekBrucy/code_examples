using file_upload.Data;
using file_upload.Models;
using System.Text;

namespace file_upload.Services
{
    public static class TestDataSeeder
    {
        public static async Task SeedTestFiles(ApplicationDbContext context)
        {
            if (context.Files.Any())
            {
                Console.WriteLine("Test files already exist. Skipping seeding.");
                return;
            }

            Console.WriteLine("Seeding test files...");

            var testFiles = new[]
            {
                CreateTestFile("small-text.txt", "text/plain", 1024), // 1KB
                CreateTestFile("medium-image.jpg", "image/jpeg", 5 * 1024 * 1024), // 5MB
                CreateTestFile("large-video.mp4", "video/mp4", 25 * 1024 * 1024), // 25MB
                CreateTestFile("huge-archive.zip", "application/zip", 45 * 1024 * 1024) // 45MB
            };

            foreach (var file in testFiles)
            {
                context.Files.Add(file);
                Console.WriteLine($"Added test file: {file.OriginalName} ({file.Size:N0} bytes)");
            }

            await context.SaveChangesAsync();
            Console.WriteLine("Test file seeding completed!");
        }

        private static FileEntity CreateTestFile(string fileName, string contentType, int sizeInBytes)
        {
            var content = GenerateTestContent(sizeInBytes, fileName);

            return new FileEntity
            {
                FileName = $"test_{fileName}",
                OriginalName = fileName,
                ContentType = contentType,
                Content = content,
                Size = sizeInBytes,
                UploadedAt = DateTime.UtcNow,
                Title = $"Test {fileName}",
                Description = $"Generated test file of {sizeInBytes:N0} bytes for chunked download testing"
            };
        }

        private static byte[] GenerateTestContent(int sizeInBytes, string fileName)
        {
            var content = new byte[sizeInBytes];

            // Create recognizable content based on file type
            if (fileName.EndsWith(".txt"))
            {
                // Text file with repeated content
                var text = $"This is test content for {fileName}. ";
                var textBytes = Encoding.UTF8.GetBytes(text);

                for (int i = 0; i < sizeInBytes; i++)
                {
                    content[i] = textBytes[i % textBytes.Length];
                }
            }
            else if (fileName.EndsWith(".jpg") || fileName.EndsWith(".jpeg"))
            {
                // Mock JPEG header + repeated pattern
                var jpegHeader = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }; // JPEG SOI + APP0
                Array.Copy(jpegHeader, content, Math.Min(jpegHeader.Length, content.Length));

                // Fill rest with pattern
                for (int i = jpegHeader.Length; i < sizeInBytes; i++)
                {
                    content[i] = (byte)(i % 256);
                }
            }
            else if (fileName.EndsWith(".mp4"))
            {
                // Mock MP4 header + repeated pattern
                var mp4Header = Encoding.ASCII.GetBytes("ftypisom");
                Array.Copy(mp4Header, content, Math.Min(mp4Header.Length, content.Length));

                // Fill rest with pattern
                for (int i = mp4Header.Length; i < sizeInBytes; i++)
                {
                    content[i] = (byte)((i * 3) % 256);
                }
            }
            else if (fileName.EndsWith(".zip"))
            {
                // Mock ZIP header + repeated pattern
                var zipHeader = new byte[] { 0x50, 0x4B, 0x03, 0x04 }; // ZIP local file header
                Array.Copy(zipHeader, content, Math.Min(zipHeader.Length, content.Length));

                // Fill rest with pattern
                for (int i = zipHeader.Length; i < sizeInBytes; i++)
                {
                    content[i] = (byte)((i * 7) % 256);
                }
            }
            else
            {
                // Default: fill with incremental pattern
                for (int i = 0; i < sizeInBytes; i++)
                {
                    content[i] = (byte)(i % 256);
                }
            }

            return content;
        }
    }
}