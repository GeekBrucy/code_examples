using API.Data;
using API.Models;
using API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

/// <summary>
/// Controller demonstrating real-world usage with DbContext and Services.
/// Shows how to structure code for testability with dependency injection.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = "Certificate")]
public class AuditController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly IAuditService _auditService;
    private readonly ILogger<AuditController> _logger;

    // Dependency Injection: DbContext and Service are injected
    // This makes the controller testable - we can mock these dependencies in unit tests
    public AuditController(
        AppDbContext context,
        IAuditService auditService,
        ILogger<AuditController> logger)
    {
        _context = context;
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// Logs the current authentication and returns the log entry.
    /// Demonstrates using a service layer (IAuditService).
    /// </summary>
    [HttpPost("log-current-auth")]
    public async Task<IActionResult> LogCurrentAuthentication()
    {
        var clientCert = HttpContext.Connection.ClientCertificate;
        if (clientCert == null)
        {
            return BadRequest(new { error = "No client certificate found" });
        }

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var endpoint = $"{Request.Method} {Request.Path}";

        try
        {
            // Using the service layer - this is what we'll mock in unit tests
            await _auditService.LogSuccessfulAuthenticationAsync(
                clientCert.Subject,
                clientCert.Thumbprint,
                clientCert.Issuer,
                ipAddress,
                endpoint);

            return Ok(new
            {
                message = "Authentication logged successfully",
                certificateThumbprint = clientCert.Thumbprint,
                timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log authentication");
            return StatusCode(500, new { error = "Failed to log authentication" });
        }
    }

    /// <summary>
    /// Gets audit logs for the current certificate.
    /// Demonstrates using DbContext directly for simple queries.
    /// </summary>
    [HttpGet("my-logs")]
    public async Task<IActionResult> GetMyAuditLogs()
    {
        var clientCert = HttpContext.Connection.ClientCertificate;
        if (clientCert == null)
        {
            return BadRequest(new { error = "No client certificate found" });
        }

        // Direct DbContext usage - simple, straightforward for basic queries
        // In unit tests, we'll mock DbContext's DbSet
        var logs = await _context.CertificateAuditLogs
            .Where(log => log.CertificateThumbprint == clientCert.Thumbprint)
            .OrderByDescending(log => log.AuthenticationTime)
            .Take(50)
            .Select(log => new
            {
                log.Id,
                log.AuthenticationTime,
                log.IsSuccessful,
                log.FailureReason,
                log.Endpoint,
                log.IpAddress
            })
            .ToListAsync();

        return Ok(new
        {
            certificateThumbprint = clientCert.Thumbprint,
            totalLogs = logs.Count,
            logs
        });
    }

    /// <summary>
    /// Gets recent audit logs (admin function).
    /// Demonstrates using service layer for complex business logic.
    /// </summary>
    [HttpGet("recent")]
    public async Task<IActionResult> GetRecentAuditLogs([FromQuery] int count = 100)
    {
        if (count < 1 || count > 1000)
        {
            return BadRequest(new { error = "Count must be between 1 and 1000" });
        }

        // Using service layer - provides abstraction and testability
        var logs = await _auditService.GetRecentAuditLogsAsync(count);

        return Ok(new
        {
            count = logs.Count,
            logs = logs.Select(log => new
            {
                log.Id,
                log.CertificateSubject,
                log.CertificateThumbprint,
                log.AuthenticationTime,
                log.IsSuccessful,
                log.FailureReason,
                log.Endpoint
            })
        });
    }

    /// <summary>
    /// Gets failed authentication attempts (security monitoring).
    /// Demonstrates combining service and business logic.
    /// </summary>
    [HttpGet("failed-attempts")]
    public async Task<IActionResult> GetFailedAttempts([FromQuery] int hoursAgo = 24)
    {
        if (hoursAgo < 1 || hoursAgo > 720) // Max 30 days
        {
            return BadRequest(new { error = "Hours must be between 1 and 720" });
        }

        var since = DateTime.UtcNow.AddHours(-hoursAgo);

        // Using service layer for complex query
        var failedAttempts = await _auditService.GetFailedAttemptsAsync(since);

        // Business logic in controller - group by thumbprint to identify suspicious patterns
        var suspiciousPatterns = failedAttempts
            .GroupBy(log => log.CertificateThumbprint)
            .Select(group => new
            {
                certificateThumbprint = group.Key,
                failedAttempts = group.Count(),
                firstAttempt = group.Min(l => l.AuthenticationTime),
                lastAttempt = group.Max(l => l.AuthenticationTime),
                reasons = group.Select(l => l.FailureReason).Distinct(),
                // Flag as suspicious if more than 5 failed attempts
                isSuspicious = group.Count() > 5
            })
            .OrderByDescending(x => x.failedAttempts)
            .ToList();

        return Ok(new
        {
            timeRange = new { since, until = DateTime.UtcNow },
            totalFailedAttempts = failedAttempts.Count,
            uniqueCertificates = suspiciousPatterns.Count,
            suspiciousCertificates = suspiciousPatterns.Count(x => x.isSuspicious),
            details = suspiciousPatterns
        });
    }

    /// <summary>
    /// Creates a sample audit log (for testing purposes).
    /// Demonstrates direct DbContext usage for write operations.
    /// </summary>
    [HttpPost("create-sample")]
    public async Task<IActionResult> CreateSampleLog([FromBody] CreateSampleLogRequest request)
    {
        var log = new CertificateAuditLog
        {
            CertificateSubject = request.Subject,
            CertificateThumbprint = request.Thumbprint,
            IssuerName = request.Issuer,
            AuthenticationTime = DateTime.UtcNow,
            IsSuccessful = request.IsSuccessful,
            FailureReason = request.FailureReason,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            Endpoint = $"{Request.Method} {Request.Path}"
        };

        // Direct DbContext add - simple and straightforward
        _context.CertificateAuditLogs.Add(log);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Sample audit log created with ID: {Id}", log.Id);

        return CreatedAtAction(
            nameof(GetAuditLogById),
            new { id = log.Id },
            log);
    }

    /// <summary>
    /// Gets a specific audit log by ID.
    /// Demonstrates error handling with DbContext queries.
    /// </summary>
    [HttpGet("{id}")]
    public async Task<IActionResult> GetAuditLogById(int id)
    {
        var log = await _context.CertificateAuditLogs.FindAsync(id);

        if (log == null)
        {
            return NotFound(new { error = $"Audit log with ID {id} not found" });
        }

        return Ok(log);
    }

    /// <summary>
    /// Gets statistics about certificate usage.
    /// Demonstrates complex queries with DbContext.
    /// </summary>
    [HttpGet("statistics")]
    public async Task<IActionResult> GetStatistics()
    {
        // Complex aggregation query - demonstrates DbContext capabilities
        var stats = await _context.CertificateAuditLogs
            .GroupBy(log => log.IsSuccessful)
            .Select(group => new
            {
                isSuccessful = group.Key,
                count = group.Count()
            })
            .ToListAsync();

        var totalLogs = await _context.CertificateAuditLogs.CountAsync();
        var uniqueCertificates = await _context.CertificateAuditLogs
            .Select(log => log.CertificateThumbprint)
            .Distinct()
            .CountAsync();

        var recentActivity = await _context.CertificateAuditLogs
            .Where(log => log.AuthenticationTime >= DateTime.UtcNow.AddHours(-24))
            .CountAsync();

        return Ok(new
        {
            totalLogs,
            uniqueCertificates,
            last24Hours = recentActivity,
            successRate = totalLogs > 0
                ? (double)(stats.FirstOrDefault(s => s.isSuccessful)?.count ?? 0) / totalLogs * 100
                : 0,
            breakdown = stats
        });
    }
}

/// <summary>
/// Request model for creating sample audit logs.
/// </summary>
public class CreateSampleLogRequest
{
    public required string Subject { get; set; }
    public required string Thumbprint { get; set; }
    public string? Issuer { get; set; }
    public bool IsSuccessful { get; set; }
    public string? FailureReason { get; set; }
}
