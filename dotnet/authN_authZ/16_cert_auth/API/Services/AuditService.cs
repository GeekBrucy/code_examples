using API.Data;
using API.Models;
using Microsoft.EntityFrameworkCore;

namespace API.Services;

/// <summary>
/// Implementation of audit service for certificate authentication.
/// This demonstrates a typical service that uses Entity Framework for data access.
/// </summary>
public class AuditService : IAuditService
{
    private readonly AppDbContext _context;
    private readonly ILogger<AuditService> _logger;

    public AuditService(AppDbContext context, ILogger<AuditService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task LogSuccessfulAuthenticationAsync(
        string certificateSubject,
        string certificateThumbprint,
        string? issuerName,
        string? ipAddress,
        string? endpoint)
    {
        var auditLog = new CertificateAuditLog
        {
            CertificateSubject = certificateSubject,
            CertificateThumbprint = certificateThumbprint,
            IssuerName = issuerName,
            AuthenticationTime = DateTime.UtcNow,
            IsSuccessful = true,
            IpAddress = ipAddress,
            Endpoint = endpoint
        };

        _context.CertificateAuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Successful authentication logged for certificate: {Thumbprint}",
            certificateThumbprint);
    }

    public async Task LogFailedAuthenticationAsync(
        string certificateSubject,
        string certificateThumbprint,
        string? issuerName,
        string failureReason,
        string? ipAddress,
        string? endpoint)
    {
        var auditLog = new CertificateAuditLog
        {
            CertificateSubject = certificateSubject,
            CertificateThumbprint = certificateThumbprint,
            IssuerName = issuerName,
            AuthenticationTime = DateTime.UtcNow,
            IsSuccessful = false,
            FailureReason = failureReason,
            IpAddress = ipAddress,
            Endpoint = endpoint
        };

        _context.CertificateAuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();

        _logger.LogWarning(
            "Failed authentication logged for certificate: {Thumbprint}. Reason: {Reason}",
            certificateThumbprint,
            failureReason);
    }

    public async Task<List<CertificateAuditLog>> GetAuditLogsByThumbprintAsync(string thumbprint)
    {
        return await _context.CertificateAuditLogs
            .Where(log => log.CertificateThumbprint == thumbprint)
            .OrderByDescending(log => log.AuthenticationTime)
            .ToListAsync();
    }

    public async Task<List<CertificateAuditLog>> GetRecentAuditLogsAsync(int count = 100)
    {
        return await _context.CertificateAuditLogs
            .OrderByDescending(log => log.AuthenticationTime)
            .Take(count)
            .ToListAsync();
    }

    public async Task<List<CertificateAuditLog>> GetFailedAttemptsAsync(DateTime since)
    {
        return await _context.CertificateAuditLogs
            .Where(log => !log.IsSuccessful && log.AuthenticationTime >= since)
            .OrderByDescending(log => log.AuthenticationTime)
            .ToListAsync();
    }
}
