using System.Text.Json;
using file_upload_sftp.Dtos;
using file_upload_sftp.Services;
using Microsoft.AspNetCore.Mvc;

namespace file_upload_sftp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SFTPController : ControllerBase
    {
        private readonly ISftpService _uploader;

        public SFTPController(ISftpService uploader)
        {
            _uploader = uploader;
        }

        [HttpPost("{partnerId}")]
        public async Task<IActionResult> ExportToPartner(string partnerId, [FromBody] object payload, CancellationToken ct)
        {
            var json = JsonSerializer.Serialize(payload);

            var fileName = $"event_{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}_{Guid.NewGuid():N}.json";
            var remoteDir = $"/outbound/{partnerId}";

            await _uploader.UploadJsonAsync(new SftpUploadRequest(remoteDir, fileName, json), ct);

            return Ok(new { partnerId, fileName });
        }
    }
}