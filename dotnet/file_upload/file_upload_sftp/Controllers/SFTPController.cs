using System.Text.Json;
using file_upload_sftp.Data;
using file_upload_sftp.Dtos;
using file_upload_sftp.Models;
using file_upload_sftp.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace file_upload_sftp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SFTPController : ControllerBase
    {
        private readonly ISftpService _uploader;
        private readonly IDistributionService _distribution;
        private readonly OutboxDbContext _db;

        public SFTPController(ISftpService uploader, IDistributionService distribution, OutboxDbContext db)
        {
            _uploader = uploader;
            _distribution = distribution;
            _db = db;
        }

        // --- Legacy endpoint (kept for backward compat) ---

        [HttpPost("{partnerId}")]
        public async Task<IActionResult> ExportToPartner(string partnerId, [FromBody] object payload, CancellationToken ct)
        {
            var json = JsonSerializer.Serialize(payload);

            var fileName = $"event_{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}_{Guid.NewGuid():N}.json";
            var remoteDir = $"/outbound/{partnerId}";

            await _uploader.UploadJsonAsync(new SftpUploadRequest(remoteDir, fileName, json), ct);

            return Ok(new { partnerId, fileName });
        }

        // --- New: Reliable distribution with outbox ---

        [HttpPost("distribute")]
        public async Task<IActionResult> Distribute([FromBody] DistributionRequest request, CancellationToken ct)
        {
            var entryIds = await _distribution.EnqueueAsync(request, ct);

            return Accepted(new
            {
                message = "Distribution enqueued",
                recordId = request.RecordId,
                partnerIds = request.PartnerIds,
                outboxEntryIds = entryIds
            });
        }

        // --- Audit endpoints ---

        [HttpGet("outbox")]
        public async Task<IActionResult> QueryOutbox(
            [FromQuery] string? recordId,
            [FromQuery] string? status,
            [FromQuery] string? partnerId,
            CancellationToken ct)
        {
            var query = _db.OutboxEntries.AsNoTracking().AsQueryable();

            if (!string.IsNullOrEmpty(recordId))
                query = query.Where(e => e.RecordId == recordId);

            if (!string.IsNullOrEmpty(partnerId))
                query = query.Where(e => e.PartnerId == partnerId);

            if (Enum.TryParse<DeliveryStatus>(status, ignoreCase: true, out var parsedStatus))
                query = query.Where(e => e.Status == parsedStatus);

            var entries = await query
                .OrderByDescending(e => e.CreatedAt)
                .Take(100)
                .Select(e => new
                {
                    e.Id,
                    e.RecordId,
                    e.PartnerId,
                    Status = e.Status.ToString(),
                    e.Attempts,
                    e.MaxAttempts,
                    e.LastError,
                    e.NextRetryAt,
                    e.CreatedAt,
                    e.CompletedAt,
                    FileCount = e.Files.Count
                })
                .ToListAsync(ct);

            return Ok(entries);
        }

        [HttpPost("outbox/{id:int}/retry")]
        public async Task<IActionResult> RetryEntry(int id, CancellationToken ct)
        {
            var entry = await _db.OutboxEntries.FindAsync([id], ct);
            if (entry is null)
                return NotFound();

            if (entry.Status != DeliveryStatus.Failed)
                return BadRequest(new { message = $"Entry is {entry.Status}, not Failed. Only failed entries can be retried." });

            entry.Status = DeliveryStatus.Pending;
            entry.Attempts = 0;
            entry.NextRetryAt = DateTime.UtcNow;
            entry.LastError = null;
            await _db.SaveChangesAsync(ct);

            return Ok(new { message = "Entry re-queued for retry", outboxId = id });
        }
    }
}
