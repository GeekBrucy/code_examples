using file_upload_sftp.Data;
using file_upload_sftp.Dtos;
using file_upload_sftp.Models;
using file_upload_sftp.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace file_upload_sftp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SFTPController : ControllerBase
{
    private readonly IDistributionService _distribution;
    private readonly AppDbContext _db;

    public SFTPController(IDistributionService distribution, AppDbContext db)
    {
        _distribution = distribution;
        _db = db;
    }

    // --- Finalize a report (triggers automatic SFTP distribution to referred users) ---

    [HttpPost("reports/{reportId:int}/finalise")]
    public async Task<IActionResult> FinaliseReport(int reportId, CancellationToken ct)
    {
        var report = await _db.Reports.FindAsync([reportId], ct);
        if (report is null)
            return NotFound(new { message = $"Report {reportId} not found." });

        if (report.Status == "Finalised")
            return BadRequest(new { message = "Report is already finalised." });

        report.Status = "Finalised";
        report.FinalisedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);

        // Enqueue SFTP delivery for all referred external users
        var entryIds = await _distribution.EnqueueForFinalisedReportAsync(reportId, ct);

        return Ok(new
        {
            message = "Report finalised",
            reportId,
            sftpDeliveries = entryIds.Count,
            outboxEntryIds = entryIds
        });
    }

    // --- Manual refer: distribute to additional external users ---

    [HttpPost("reports/refer")]
    public async Task<IActionResult> ManualRefer([FromBody] ManualReferRequest request, CancellationToken ct)
    {
        var entryIds = await _distribution.EnqueueForExternalUsersAsync(
            request.ReportId, request.ExternalUserIds, ct);

        return Accepted(new
        {
            message = "Manual referral enqueued",
            reportId = request.ReportId,
            externalUserIds = request.ExternalUserIds,
            outboxEntryIds = entryIds
        });
    }

    // --- Audit endpoints ---

    [HttpGet("outbox")]
    public async Task<IActionResult> QueryOutbox(
        [FromQuery] int? reportId,
        [FromQuery] string? status,
        [FromQuery] int? externalUserId,
        CancellationToken ct)
    {
        var query = _db.OutboxEntries.AsNoTracking().AsQueryable();

        if (reportId.HasValue)
            query = query.Where(e => e.ReportId == reportId.Value);

        if (externalUserId.HasValue)
            query = query.Where(e => e.ExternalUserId == externalUserId.Value);

        if (Enum.TryParse<DeliveryStatus>(status, ignoreCase: true, out var parsedStatus))
            query = query.Where(e => e.Status == parsedStatus);

        var entries = await query
            .OrderByDescending(e => e.CreatedAt)
            .Take(100)
            .Select(e => new
            {
                e.Id,
                e.ReportId,
                e.ExternalUserId,
                Status = e.Status.ToString(),
                e.Attempts,
                e.MaxAttempts,
                e.LastError,
                e.NextRetryAt,
                e.CreatedAt,
                e.CompletedAt
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
