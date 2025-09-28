using Microsoft.AspNetCore.Mvc;
using file_upload.Data;
using file_upload.Models;
using System.Text;

namespace file_upload.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PartialDownloadController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public PartialDownloadController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet("range/{id}")]
        public async Task<IActionResult> GetFileWithRangeSupport(int id)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null) 
                return NotFound("File not found");

            var fileLength = fileEntity.Content.Length;
            var rangeHeader = Request.Headers.Range.ToString();

            if (string.IsNullOrEmpty(rangeHeader))
            {
                Response.Headers.AcceptRanges = "bytes";
                Response.Headers.ContentLength = fileLength;
                return File(fileEntity.Content, fileEntity.ContentType, fileEntity.OriginalName);
            }

            var ranges = ParseRangeHeader(rangeHeader, fileLength);
            if (ranges == null || ranges.Count == 0)
            {
                Response.StatusCode = 416;
                Response.Headers.ContentRange = $"bytes */{fileLength}";
                return new EmptyResult();
            }

            if (ranges.Count == 1)
            {
                var range = ranges[0];
                var length = range.End - range.Start + 1;
                var buffer = new byte[length];
                Array.Copy(fileEntity.Content, range.Start, buffer, 0, length);

                Response.StatusCode = 206;
                Response.Headers.ContentRange = $"bytes {range.Start}-{range.End}/{fileLength}";
                Response.Headers.ContentLength = length;
                Response.Headers.AcceptRanges = "bytes";

                return File(buffer, fileEntity.ContentType);
            }

            return await HandleMultipleRanges(fileEntity, ranges, fileLength);
        }

        [HttpGet("chunk/{id}")]
        public async Task<IActionResult> GetFileChunk(int id, [FromQuery] int chunkIndex = 0, [FromQuery] int chunkSize = 1024 * 1024)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null) 
                return NotFound("File not found");

            var fileLength = fileEntity.Content.Length;
            var totalChunks = (int)Math.Ceiling((double)fileLength / chunkSize);

            if (chunkIndex < 0 || chunkIndex >= totalChunks)
                return BadRequest($"Invalid chunk index. File has {totalChunks} chunks (0-{totalChunks - 1})");

            var startByte = chunkIndex * chunkSize;
            var endByte = Math.Min(startByte + chunkSize - 1, fileLength - 1);
            var actualChunkSize = endByte - startByte + 1;

            var buffer = new byte[actualChunkSize];
            Array.Copy(fileEntity.Content, startByte, buffer, 0, actualChunkSize);

            var metadata = new
            {
                ChunkIndex = chunkIndex,
                ChunkSize = actualChunkSize,
                TotalChunks = totalChunks,
                StartByte = startByte,
                EndByte = endByte,
                FileSize = fileLength,
                IsLastChunk = chunkIndex == totalChunks - 1,
                NextChunkUrl = chunkIndex < totalChunks - 1 
                    ? Url.Action("GetFileChunk", new { id, chunkIndex = chunkIndex + 1, chunkSize })
                    : null
            };

            Response.Headers["X-Chunk-Metadata"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(metadata)));
            Response.Headers.ContentRange = $"bytes {startByte}-{endByte}/{fileLength}";
            Response.StatusCode = 206;

            return File(buffer, fileEntity.ContentType);
        }

        [HttpGet("stream/{id}")]
        public async Task<IActionResult> StreamFileInChunks(int id, [FromQuery] int chunkSize = 8192)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null) 
                return NotFound("File not found");

            Response.Headers.ContentLength = fileEntity.Content.Length;
            Response.Headers.AcceptRanges = "bytes";
            Response.Headers.ContentDisposition = $"attachment; filename=\"{fileEntity.OriginalName}\"";

            return new FileStreamResult(new MemoryStream(fileEntity.Content), fileEntity.ContentType)
            {
                FileDownloadName = fileEntity.OriginalName
            };
        }

        [HttpGet("info/{id}")]
        public async Task<IActionResult> GetFileDownloadInfo(int id)
        {
            var fileEntity = await _context.Files.FindAsync(id);
            if (fileEntity == null) 
                return NotFound("File not found");

            var chunkSize = 1024 * 1024;
            var totalChunks = (int)Math.Ceiling((double)fileEntity.Content.Length / chunkSize);

            return Ok(new
            {
                FileId = fileEntity.Id,
                FileName = fileEntity.OriginalName,
                FileSize = fileEntity.Content.Length,
                ContentType = fileEntity.ContentType,
                RecommendedChunkSize = chunkSize,
                TotalChunks = totalChunks,
                SupportsRangeRequests = true,
                DownloadUrls = new
                {
                    FullFile = Url.Action("GetFileWithRangeSupport", new { id }),
                    ChunkedDownload = Url.Action("GetFileChunk", new { id, chunkIndex = 0, chunkSize }),
                    StreamDownload = Url.Action("StreamFileInChunks", new { id, chunkSize = 8192 })
                },
                ChunkUrls = Enumerable.Range(0, Math.Min(totalChunks, 10))
                    .Select(i => new 
                    {
                        ChunkIndex = i,
                        Url = Url.Action("GetFileChunk", new { id, chunkIndex = i, chunkSize })
                    }).ToArray()
            });
        }

        private List<(long Start, long End)>? ParseRangeHeader(string rangeHeader, long fileLength)
        {
            if (!rangeHeader.StartsWith("bytes="))
                return null;

            var ranges = new List<(long Start, long End)>();
            var rangeSpecs = rangeHeader[6..].Split(',');

            foreach (var rangeSpec in rangeSpecs)
            {
                var trimmed = rangeSpec.Trim();
                if (trimmed.StartsWith('-'))
                {
                    if (long.TryParse(trimmed[1..], out var suffixLength))
                    {
                        var start = Math.Max(0, fileLength - suffixLength);
                        ranges.Add((start, fileLength - 1));
                    }
                }
                else if (trimmed.EndsWith('-'))
                {
                    if (long.TryParse(trimmed[..^1], out var start) && start < fileLength)
                    {
                        ranges.Add((start, fileLength - 1));
                    }
                }
                else
                {
                    var parts = trimmed.Split('-');
                    if (parts.Length == 2 && 
                        long.TryParse(parts[0], out var start) && 
                        long.TryParse(parts[1], out var end) &&
                        start <= end && start < fileLength)
                    {
                        ranges.Add((start, Math.Min(end, fileLength - 1)));
                    }
                }
            }

            return ranges;
        }

        private async Task<IActionResult> HandleMultipleRanges(FileEntity fileEntity, List<(long Start, long End)> ranges, long fileLength)
        {
            var boundary = $"----boundary{Guid.NewGuid():N}";
            Response.StatusCode = 206;
            Response.ContentType = $"multipart/byteranges; boundary={boundary}";

            using var memoryStream = new MemoryStream();
            using var writer = new StreamWriter(memoryStream, Encoding.ASCII, leaveOpen: true);

            foreach (var range in ranges)
            {
                var length = range.End - range.Start + 1;
                
                await writer.WriteAsync($"\r\n--{boundary}\r\n");
                await writer.WriteAsync($"Content-Type: {fileEntity.ContentType}\r\n");
                await writer.WriteAsync($"Content-Range: bytes {range.Start}-{range.End}/{fileLength}\r\n\r\n");
                await writer.FlushAsync();

                await memoryStream.WriteAsync(fileEntity.Content, (int)range.Start, (int)length);
            }

            await writer.WriteAsync($"\r\n--{boundary}--\r\n");
            await writer.FlushAsync();

            return File(memoryStream.ToArray(), "multipart/byteranges");
        }
    }
}