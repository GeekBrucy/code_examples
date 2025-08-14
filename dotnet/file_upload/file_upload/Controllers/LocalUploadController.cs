using Microsoft.AspNetCore.Mvc;
using MimeMapping;

namespace file_upload.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LocalUploadController : ControllerBase
    {
        private readonly IWebHostEnvironment _environment;

        public LocalUploadController(IWebHostEnvironment environment)
        {
            _environment = environment;
        }

        [HttpPost("submit")]
        public async Task<IActionResult> SubmitForm([FromForm] string title, [FromForm] string description, [FromForm] List<string> fileNames)
        {
            if (fileNames == null || !fileNames.Any())
            {
                return BadRequest("No file names provided");
            }

            var tempFolder = Path.Combine(_environment.ContentRootPath, "temp");
            var uploadFolder = Path.Combine(_environment.ContentRootPath, "uploads");

            if (!Directory.Exists(uploadFolder))
            {
                Directory.CreateDirectory(uploadFolder);
            }

            var movedFiles = new List<object>();
            var errors = new List<string>();

            foreach (var fileName in fileNames)
            {
                var tempFilePath = Path.Combine(tempFolder, fileName);

                if (!System.IO.File.Exists(tempFilePath))
                {
                    errors.Add($"File not found in temp folder: {fileName}");
                    continue;
                }

                var finalFilePath = Path.Combine(uploadFolder, fileName);

                try
                {
                    System.IO.File.Move(tempFilePath, finalFilePath);
                    movedFiles.Add(new { FileName = fileName, FinalPath = finalFilePath });
                }
                catch (Exception ex)
                {
                    errors.Add($"Error moving file {fileName}: {ex.Message}");
                }
            }

            if (errors.Any() && !movedFiles.Any())
            {
                return StatusCode(500, string.Join("; ", errors));
            }

            return Ok(new
            {
                Title = title,
                Description = description,
                MovedFiles = movedFiles,
                Errors = errors
            });
        }

        [HttpPost("upload")]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            // return Ok();
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

            var tempFolder = Path.Combine(_environment.ContentRootPath, "temp");
            if (!Directory.Exists(tempFolder))
            {
                Directory.CreateDirectory(tempFolder);
            }

            var fileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(file.FileName);
            var filePath = Path.Combine(tempFolder, fileName);

            try
            {
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }
                // return new OkObjectResult(new
                // {
                //     FileName = fileName,
                //     OriginalName = file.FileName,
                //     Size = file.Length,
                //     Path = filePath
                // });
                return Ok(new
                {
                    FileName = fileName,
                    OriginalName = file.FileName,
                    Size = file.Length,
                    Path = filePath
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error uploading file: {ex.Message}");
            }
        }

        [HttpDelete("delete/{fileName}")]
        public IActionResult DeleteFile(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
            {
                return BadRequest("File name is required");
            }

            var tempFolder = Path.Combine(_environment.ContentRootPath, "temp");
            var filePath = Path.Combine(tempFolder, fileName);

            if (!System.IO.File.Exists(filePath))
            {
                return NotFound("File not found");
            }

            try
            {
                System.IO.File.Delete(filePath);
                return Ok(new { Message = "File deleted successfully", FileName = fileName });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error deleting file: {ex.Message}");
            }
        }

        [HttpGet("download/storage/{fileName}")]
        public IActionResult DownloadFileFromStorage(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
            {
                return BadRequest("File name is required");
            }

            var uploadsFolder = Path.Combine(_environment.ContentRootPath, "uploads");
            var filePath = Path.Combine(uploadsFolder, fileName);

            if (!System.IO.File.Exists(filePath))
            {
                return NotFound("File not found");
            }

            try
            {
                var fileBytes = System.IO.File.ReadAllBytes(filePath);
                var contentType = MimeUtility.GetMimeMapping(fileName);
                var originalFileName = fileName.Contains('_') ? fileName.Substring(fileName.IndexOf('_') + 1) : fileName;
                
                return File(fileBytes, contentType, originalFileName);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error downloading file: {ex.Message}");
            }
        }
    }
}