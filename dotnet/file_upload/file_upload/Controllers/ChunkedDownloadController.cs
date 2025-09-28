using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using file_upload.Data;
using file_upload.Models;
using System.Text;

namespace file_upload.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ChunkedDownloadController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private const int MAX_CHUNK_SIZE = 10 * 1024 * 1024; // 10MB gateway limit

        public ChunkedDownloadController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet("list")]
        public async Task<IActionResult> ListFiles()
        {
            var files = await _context.Files
                .Select(f => new
                {
                    f.Id,
                    f.OriginalName,
                    f.ContentType,
                    f.Size,
                    SizeFormatted = FormatBytes(f.Size),
                    TotalChunks = (int)Math.Ceiling((double)f.Size / MAX_CHUNK_SIZE),
                    RequiresChunking = f.Size > MAX_CHUNK_SIZE,
                    DownloadUrl = Url.Action("GetFile", new { id = f.Id }),
                    InfoUrl = Url.Action("GetFileInfo", new { id = f.Id })
                })
                .ToListAsync();

            return Ok(files);
        }

        [HttpGet("info/{id}")]
        public async Task<IActionResult> GetFileInfo(int id)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null)
                return NotFound("File not found");

            var fileSize = fileEntity.Content.Length;
            var totalChunks = (int)Math.Ceiling((double)fileSize / MAX_CHUNK_SIZE);

            return Ok(new
            {
                FileId = fileEntity.Id,
                FileName = fileEntity.OriginalName,
                FileSize = fileSize,
                ContentType = fileEntity.ContentType,
                ChunkSize = MAX_CHUNK_SIZE,
                TotalChunks = totalChunks,
                ChunkUrls = Enumerable.Range(0, totalChunks)
                    .Select(i => new
                    {
                        ChunkIndex = i,
                        Url = Url.Action("GetChunk", new { id, chunkIndex = i })
                    }).ToArray()
            });
        }

        [HttpGet("download/{id}")]
        public async Task<IActionResult> GetFile(int id, [FromQuery] int? chunkIndex = null)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null)
                return NotFound("File not found");

            var fileSize = fileEntity.Content.Length;

            // Always serve small files whole, regardless of chunkIndex parameter
            if (fileSize <= MAX_CHUNK_SIZE)
            {
                Response.Headers.ContentLength = fileSize;
                return File(fileEntity.Content, fileEntity.ContentType, fileEntity.OriginalName);
            }

            // File is large - chunked download required
            if (chunkIndex == null)
            {
                // File too large - provide chunked download guidance
                return BadRequest(new
                {
                    Error = "File too large for direct download",
                    FileSize = fileSize,
                    MaxSize = MAX_CHUNK_SIZE,
                    Message = "Use chunked download by adding ?chunkIndex=0 parameter",
                    TotalChunks = (int)Math.Ceiling((double)fileSize / MAX_CHUNK_SIZE),
                    FirstChunkUrl = Url.Action("GetFile", new { id, chunkIndex = 0 })
                });
            }

            // Chunked download logic
            var totalChunks = (int)Math.Ceiling((double)fileSize / MAX_CHUNK_SIZE);

            if (chunkIndex < 0 || chunkIndex >= totalChunks)
                return BadRequest($"Invalid chunk index. Valid range: 0-{totalChunks - 1}");

            var startByte = chunkIndex.Value * MAX_CHUNK_SIZE;
            var endByte = Math.Min(startByte + MAX_CHUNK_SIZE - 1, fileSize - 1);
            var chunkSize = endByte - startByte + 1;

            // Extract only the needed chunk from database content
            var buffer = new byte[chunkSize];
            Array.Copy(fileEntity.Content, startByte, buffer, 0, chunkSize);

            var metadata = new
            {
                ChunkIndex = chunkIndex.Value,
                ChunkSize = chunkSize,
                TotalChunks = totalChunks,
                StartByte = startByte,
                EndByte = endByte,
                FileSize = fileSize,
                IsLastChunk = chunkIndex.Value == totalChunks - 1,
                NextChunkUrl = chunkIndex.Value < totalChunks - 1
                    ? Url.Action("GetFile", new { id, chunkIndex = chunkIndex.Value + 1 })
                    : null
            };

            // Add metadata headers for client convenience
            Response.Headers["X-Chunk-Metadata"] = Convert.ToBase64String(
                Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(metadata)));
            Response.Headers["X-Total-Chunks"] = totalChunks.ToString();
            Response.Headers["X-Chunk-Index"] = chunkIndex.Value.ToString();
            Response.Headers["X-File-Size"] = fileSize.ToString();

            Response.StatusCode = 206; // Partial Content
            Response.Headers.ContentRange = $"bytes {startByte}-{endByte}/{fileSize}";

            return File(buffer, fileEntity.ContentType);
        }

        private static string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int counter = 0;
            decimal number = bytes;
            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }
            return $"{number:n1} {suffixes[counter]}";
        }
    }
}