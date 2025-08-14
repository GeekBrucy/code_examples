using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MimeMapping;
using file_upload.Data;
using file_upload.Models;
using System.IO.Compression;
using System.Text.Json;

namespace file_upload.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FileResponseExamplesController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public FileResponseExamplesController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet("file/{id}")]
        public async Task<IActionResult> GetFile(int id, [FromQuery] bool download = false)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null) 
                return NotFound("File not found");

            if (download)
            {
                return File(fileEntity.Content, fileEntity.ContentType, fileEntity.OriginalName);
            }
            else
            {
                return Ok(new
                {
                    Id = fileEntity.Id,
                    FileName = fileEntity.FileName,
                    OriginalName = fileEntity.OriginalName,
                    Size = fileEntity.Size,
                    ContentType = fileEntity.ContentType,
                    Title = fileEntity.Title,
                    Description = fileEntity.Description,
                    UploadedAt = fileEntity.UploadedAt,
                    DownloadUrl = Url.Action("GetFile", new { id = fileEntity.Id, download = true })
                });
            }
        }

        [HttpGet("package/{id}")]
        public async Task<IActionResult> GetFilePackage(int id)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null) 
                return NotFound("File not found");

            var boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
            Response.ContentType = $"multipart/mixed; boundary={boundary}";

            var json = JsonSerializer.Serialize(new
            {
                Id = fileEntity.Id,
                FileName = fileEntity.FileName,
                OriginalName = fileEntity.OriginalName,
                Size = fileEntity.Size,
                ContentType = fileEntity.ContentType,
                UploadedAt = fileEntity.UploadedAt
            });

            using var writer = new StreamWriter(Response.Body);
            
            await writer.WriteAsync($"--{boundary}\r\n");
            await writer.WriteAsync("Content-Type: application/json\r\n\r\n");
            await writer.WriteAsync($"{json}\r\n");
            
            await writer.WriteAsync($"--{boundary}\r\n");
            await writer.WriteAsync($"Content-Type: {fileEntity.ContentType}\r\n");
            await writer.WriteAsync($"Content-Disposition: attachment; filename=\"{fileEntity.OriginalName}\"\r\n\r\n");
            await writer.FlushAsync();
            
            await Response.Body.WriteAsync(fileEntity.Content);
            await writer.WriteAsync($"\r\n--{boundary}--\r\n");

            return new EmptyResult();
        }

        [HttpGet("archive/{id}")]
        public async Task<IActionResult> GetFileArchive(int id)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null) 
                return NotFound("File not found");

            using var zipStream = new MemoryStream();
            using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, true))
            {
                var metadataEntry = archive.CreateEntry("metadata.json");
                using var metadataStream = metadataEntry.Open();
                var metadata = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    Id = fileEntity.Id,
                    FileName = fileEntity.FileName,
                    OriginalName = fileEntity.OriginalName,
                    Size = fileEntity.Size,
                    ContentType = fileEntity.ContentType,
                    Title = fileEntity.Title,
                    Description = fileEntity.Description,
                    UploadedAt = fileEntity.UploadedAt
                });
                await metadataStream.WriteAsync(metadata);

                var fileEntry = archive.CreateEntry(fileEntity.OriginalName);
                using var fileStream = fileEntry.Open();
                await fileStream.WriteAsync(fileEntity.Content);
            }

            return File(zipStream.ToArray(), "application/zip", $"package_{id}.zip");
        }

        [HttpGet("batch")]
        public async Task<IActionResult> GetMultipleFiles([FromQuery] int[] ids, [FromQuery] string format = "json")
        {
            if (ids == null || ids.Length == 0)
                return BadRequest("No file IDs provided");

            var files = await _context.Files
                .Where(f => ids.Contains(f.Id))
                .ToListAsync();

            if (!files.Any())
                return NotFound("No files found");

            switch (format.ToLower())
            {
                case "zip":
                    {
                        using var zipStream = new MemoryStream();
                        using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, true))
                        {
                            var manifestData = files.Select(f => new
                            {
                                f.Id,
                                f.FileName,
                                f.OriginalName,
                                f.Size,
                                f.ContentType,
                                f.UploadedAt
                            }).ToArray();

                            var manifestEntry = archive.CreateEntry("manifest.json");
                            using var manifestStream = manifestEntry.Open();
                            var manifestJson = JsonSerializer.SerializeToUtf8Bytes(manifestData);
                            await manifestStream.WriteAsync(manifestJson);

                            foreach (var file in files)
                            {
                                var fileEntry = archive.CreateEntry($"files/{file.OriginalName}");
                                using var fileStream = fileEntry.Open();
                                await fileStream.WriteAsync(file.Content);
                            }
                        }
                        return File(zipStream.ToArray(), "application/zip", "files_batch.zip");
                    }

                case "json":
                default:
                    return Ok(new
                    {
                        TotalFiles = files.Count,
                        TotalSize = files.Sum(f => f.Size),
                        Files = files.Select(f => new
                        {
                            f.Id,
                            f.FileName,
                            f.OriginalName,
                            f.Size,
                            f.ContentType,
                            f.Title,
                            f.Description,
                            f.UploadedAt,
                            DownloadUrl = Url.Action("GetFile", new { id = f.Id, download = true })
                        })
                    });
            }
        }

        [HttpPost("process/{id}")]
        public async Task<IActionResult> ProcessAndReturnFile(int id, [FromBody] ProcessingOptions options)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null) 
                return NotFound("File not found");

            try
            {
                var processedContent = ProcessFile(fileEntity.Content, options);
                var processingResult = new
                {
                    OriginalFile = new
                    {
                        fileEntity.Id,
                        fileEntity.FileName,
                        fileEntity.OriginalName,
                        OriginalSize = fileEntity.Size
                    },
                    ProcessingOptions = options,
                    ProcessedSize = processedContent.Length,
                    ProcessedAt = DateTime.UtcNow
                };

                if (options.ReturnProcessedFile)
                {
                    var processedFileName = $"processed_{fileEntity.OriginalName}";
                    return File(processedContent, fileEntity.ContentType, processedFileName);
                }
                else
                {
                    return Ok(processingResult);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Error = "Processing failed",
                    Message = ex.Message,
                    FileId = id
                });
            }
        }

        private byte[] ProcessFile(byte[] content, ProcessingOptions options)
        {
            if (options.AddPrefix)
            {
                var prefix = System.Text.Encoding.UTF8.GetBytes("PROCESSED: ");
                return prefix.Concat(content).ToArray();
            }
            return content;
        }
    }

    public class ProcessingOptions
    {
        public bool AddPrefix { get; set; } = false;
        public bool ReturnProcessedFile { get; set; } = false;
        public string? CustomParameter { get; set; }
    }
}