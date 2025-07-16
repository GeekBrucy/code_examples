using Microsoft.AspNetCore.Mvc;

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
        public async Task<IActionResult> SubmitForm([FromForm] string title, [FromForm] string description, [FromForm] string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
            {
                return BadRequest("No file name provided");
            }

            var tempFolder = Path.Combine(_environment.ContentRootPath, "temp");
            var uploadFolder = Path.Combine(_environment.ContentRootPath, "uploads");
            var tempFilePath = Path.Combine(tempFolder, fileName);

            if (!System.IO.File.Exists(tempFilePath))
            {
                return BadRequest("File not found in temp folder");
            }

            if (!Directory.Exists(uploadFolder))
            {
                Directory.CreateDirectory(uploadFolder);
            }

            var finalFilePath = Path.Combine(uploadFolder, fileName);

            try
            {
                System.IO.File.Move(tempFilePath, finalFilePath);

                return Ok(new
                {
                    Title = title,
                    Description = description,
                    FileName = fileName,
                    FinalPath = finalFilePath
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error moving file: {ex.Message}");
            }
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
    }
}