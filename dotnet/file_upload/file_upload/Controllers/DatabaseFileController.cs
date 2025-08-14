using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MimeMapping;
using file_upload.Data;
using file_upload.Models;

namespace file_upload.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DatabaseFileController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public DatabaseFileController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpPost("upload")]
        public async Task<IActionResult> UploadFileToDatabase([FromForm] string? title, [FromForm] string? description, [FromForm] IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest("No file uploaded");
            }

            var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".doc", ".docx" };
            var fileExtension = Path.GetExtension(file.FileName).ToLower();

            if (!allowedExtensions.Contains(fileExtension))
            {
                return BadRequest("File type not allowed");
            }

            if (file.Length > 10 * 1024 * 1024) // 10MB limit
            {
                return BadRequest("File size exceeds 10MB limit");
            }

            try
            {
                using var memoryStream = new MemoryStream();
                await file.CopyToAsync(memoryStream);
                
                var fileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(file.FileName);
                var contentType = MimeUtility.GetMimeMapping(file.FileName);

                var fileEntity = new FileEntity
                {
                    FileName = fileName,
                    OriginalName = file.FileName,
                    ContentType = contentType,
                    Content = memoryStream.ToArray(),
                    Size = file.Length,
                    Title = title,
                    Description = description,
                    UploadedAt = DateTime.UtcNow
                };

                _context.Files.Add(fileEntity);
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    Id = fileEntity.Id,
                    FileName = fileEntity.FileName,
                    OriginalName = fileEntity.OriginalName,
                    Size = fileEntity.Size,
                    ContentType = fileEntity.ContentType,
                    UploadedAt = fileEntity.UploadedAt
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error uploading file: {ex.Message}");
            }
        }

        [HttpGet("download/{id}")]
        public async Task<IActionResult> DownloadFileFromDatabase(int id)
        {
            try
            {
                var fileEntity = await _context.Files.FindAsync(id);

                if (fileEntity == null)
                {
                    return NotFound("File not found");
                }

                return File(fileEntity.Content, fileEntity.ContentType, fileEntity.OriginalName);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error downloading file: {ex.Message}");
            }
        }

        [HttpGet("list")]
        public async Task<IActionResult> ListFiles()
        {
            try
            {
                var files = await _context.Files
                    .Select(f => new
                    {
                        f.Id,
                        f.FileName,
                        f.OriginalName,
                        f.Size,
                        f.ContentType,
                        f.Title,
                        f.Description,
                        f.UploadedAt
                    })
                    .OrderByDescending(f => f.UploadedAt)
                    .ToListAsync();

                return Ok(files);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error retrieving files: {ex.Message}");
            }
        }

        [HttpDelete("delete/{id}")]
        public async Task<IActionResult> DeleteFileFromDatabase(int id)
        {
            try
            {
                var fileEntity = await _context.Files.FindAsync(id);

                if (fileEntity == null)
                {
                    return NotFound("File not found");
                }

                _context.Files.Remove(fileEntity);
                await _context.SaveChangesAsync();

                return Ok(new { Message = "File deleted successfully", Id = id });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error deleting file: {ex.Message}");
            }
        }
    }
}