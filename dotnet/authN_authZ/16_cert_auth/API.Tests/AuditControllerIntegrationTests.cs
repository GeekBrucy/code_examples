using API.Controllers;
using API.Data;
using API.Models;
using API.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace API.Tests;

/// <summary>
/// Integration tests for AuditController demonstrating REAL database usage.
///
/// KEY DIFFERENCES FROM UNIT TESTS:
/// - Use REAL in-memory database (not mocked DbContext)
/// - Use REAL service implementations (not mocked services)
/// - Test the FULL STACK: Controller -> Service -> Database
/// - Slower than unit tests, but tests actual integration
///
/// WHEN TO USE INTEGRATION TESTS:
/// - Testing data access code (queries, saves, updates)
/// - Testing end-to-end workflows
/// - Verifying services work correctly with real database
/// - Complex LINQ queries that are hard to mock
/// </summary>
public class AuditControllerIntegrationTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly IAuditService _auditService;
    private readonly AuditController _controller;
    private readonly X509Certificate2 _testCertificate;

    public AuditControllerIntegrationTests()
    {
        // INTEGRATION TEST SETUP:
        // Use REAL implementations, but with in-memory database for speed

        // 1. Create REAL in-memory database
        // Why in-memory? Fast, isolated, no cleanup needed
        // Each test gets its own database (unique name)
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .EnableDetailedErrors()
            .Options;

        _context = new AppDbContext(options);

        // 2. Create REAL service with REAL DbContext
        // Why real service? We want to test actual data access logic
        var mockLogger = new Mock<ILogger<AuditService>>();
        _auditService = new AuditService(_context, mockLogger.Object);

        // 3. Create controller with REAL dependencies
        var mockControllerLogger = new Mock<ILogger<AuditController>>();
        _controller = new AuditController(_context, _auditService, mockControllerLogger.Object);

        // 4. Setup HTTP context
        _testCertificate = CreateTestCertificate();
        SetupHttpContext(_controller, _testCertificate);
    }

    /// <summary>
    /// Integration test: Verify LogCurrentAuthentication saves to database.
    ///
    /// WHY INTEGRATION TEST?
    /// - We want to verify data is ACTUALLY saved to database
    /// - Unit test with mock would only verify method was called
    /// - This tests the full flow: Controller -> Service -> Database
    /// </summary>
    [Fact]
    public async Task LogCurrentAuthentication_SavesAuditLogToDatabase()
    {
        // Arrange
        var initialCount = await _context.CertificateAuditLogs.CountAsync();
        initialCount.Should().Be(0, "database should start empty");

        // Act
        var result = await _controller.LogCurrentAuthentication();

        // Assert
        // 1. Verify HTTP response
        result.Should().BeOfType<OkObjectResult>();

        // 2. Verify database was updated
        var logsAfter = await _context.CertificateAuditLogs.ToListAsync();
        logsAfter.Should().HaveCount(1, "one log should be saved");

        // 3. Verify saved data is correct
        var savedLog = logsAfter.First();
        savedLog.CertificateThumbprint.Should().Be(_testCertificate.Thumbprint);
        savedLog.CertificateSubject.Should().Be(_testCertificate.Subject);
        savedLog.IsSuccessful.Should().BeTrue();
    }

    /// <summary>
    /// Integration test: Verify GetMyAuditLogs retrieves correct data.
    ///
    /// WHY INTEGRATION TEST?
    /// - Tests complex LINQ query against real database
    /// - Mocking DbSet and IQueryable is very difficult
    /// - In-memory DB lets us test actual query behavior
    /// </summary>
    [Fact]
    public async Task GetMyAuditLogs_ReturnsOnlyCurrentCertificateLogs()
    {
        // Arrange
        // Add logs for the test certificate
        await _context.CertificateAuditLogs.AddRangeAsync(new[]
        {
            new CertificateAuditLog
            {
                CertificateSubject = _testCertificate.Subject,
                CertificateThumbprint = _testCertificate.Thumbprint,
                AuthenticationTime = DateTime.UtcNow.AddHours(-2),
                IsSuccessful = true
            },
            new CertificateAuditLog
            {
                CertificateSubject = _testCertificate.Subject,
                CertificateThumbprint = _testCertificate.Thumbprint,
                AuthenticationTime = DateTime.UtcNow.AddHours(-1),
                IsSuccessful = true
            }
        });

        // Add log for a DIFFERENT certificate (should not be returned)
        await _context.CertificateAuditLogs.AddAsync(new CertificateAuditLog
        {
            CertificateSubject = "CN=Other Certificate",
            CertificateThumbprint = "DIFFERENT_THUMBPRINT",
            AuthenticationTime = DateTime.UtcNow,
            IsSuccessful = true
        });

        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetMyAuditLogs();

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.Value.Should().NotBeNull();

        // Verify only logs for current certificate are returned
        var valueType = okResult.Value!.GetType();
        var totalLogsProp = valueType.GetProperty("totalLogs");
        var totalLogs = (int)totalLogsProp!.GetValue(okResult.Value)!;

        totalLogs.Should().Be(2, "should return only logs for current certificate");
    }

    /// <summary>
    /// Integration test: Verify GetRecentAuditLogs with multiple records.
    ///
    /// WHY INTEGRATION TEST?
    /// - Tests ordering (OrderByDescending) works correctly
    /// - Tests Take(count) limit works with real data
    /// - Difficult to mock DbSet with complex queries
    /// </summary>
    [Fact]
    public async Task GetRecentAuditLogs_ReturnsCorrectNumberOrderedByTime()
    {
        // Arrange
        // Add 10 audit logs with different timestamps
        var logs = Enumerable.Range(1, 10).Select(i => new CertificateAuditLog
        {
            CertificateSubject = $"CN=Test {i}",
            CertificateThumbprint = $"THUMB_{i:D3}",
            AuthenticationTime = DateTime.UtcNow.AddMinutes(-i),
            IsSuccessful = true
        });

        await _context.CertificateAuditLogs.AddRangeAsync(logs);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetRecentAuditLogs(5); // Request only 5

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.Value.Should().NotBeNull();

        var valueType = okResult.Value!.GetType();
        var countProp = valueType.GetProperty("count");
        var count = (int)countProp!.GetValue(okResult.Value)!;
        count.Should().Be(5, "should limit to requested count");

        // Verify ordering: most recent first
        var logsProp = valueType.GetProperty("logs");
        var returnedLogs = logsProp!.GetValue(okResult.Value) as IEnumerable<object>;
        returnedLogs.Should().NotBeNull();

        // First log should be the most recent (AuthenticationTime - 1 minute)
        var firstLog = returnedLogs!.First();
        var firstLogSubject = firstLog.GetType().GetProperty("CertificateSubject")!.GetValue(firstLog) as string;
        firstLogSubject.Should().Be("CN=Test 1");
    }

    /// <summary>
    /// Integration test: Verify CreateSampleLog persists correctly.
    ///
    /// WHY INTEGRATION TEST?
    /// - Tests entity validation and constraints
    /// - Tests SaveChangesAsync with real database
    /// - Verifies ID generation works
    /// </summary>
    [Fact]
    public async Task CreateSampleLog_PersistsToDatabase()
    {
        // Arrange
        var request = new CreateSampleLogRequest
        {
            Subject = "CN=Integration Test",
            Thumbprint = "INTEGRATION_TEST_123",
            Issuer = "CN=Test CA",
            IsSuccessful = true
        };

        // Act
        var result = await _controller.CreateSampleLog(request);

        // Assert
        // 1. Verify HTTP response
        var createdResult = result.Should().BeOfType<CreatedAtActionResult>().Subject;
        createdResult.ActionName.Should().Be(nameof(AuditController.GetAuditLogById));

        // 2. Verify database was updated
        var savedLog = await _context.CertificateAuditLogs
            .FirstOrDefaultAsync(l => l.CertificateThumbprint == request.Thumbprint);

        savedLog.Should().NotBeNull();
        savedLog!.CertificateSubject.Should().Be(request.Subject);
        savedLog.IssuerName.Should().Be(request.Issuer);
        savedLog.Id.Should().BeGreaterThan(0, "ID should be generated");
    }

    /// <summary>
    /// Integration test: Verify GetAuditLogById retrieval.
    ///
    /// WHY INTEGRATION TEST?
    /// - Tests FindAsync with real database
    /// - Simple query, but good for smoke testing
    /// </summary>
    [Fact]
    public async Task GetAuditLogById_ReturnsExistingLog()
    {
        // Arrange
        var log = new CertificateAuditLog
        {
            CertificateSubject = "CN=Find Me",
            CertificateThumbprint = "FINDME123",
            AuthenticationTime = DateTime.UtcNow,
            IsSuccessful = true
        };

        _context.CertificateAuditLogs.Add(log);
        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetAuditLogById(log.Id);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var returnedLog = okResult.Value.Should().BeOfType<CertificateAuditLog>().Subject;
        returnedLog.Id.Should().Be(log.Id);
        returnedLog.CertificateThumbprint.Should().Be("FINDME123");
    }

    [Fact]
    public async Task GetAuditLogById_ReturnsNotFoundForNonExistentId()
    {
        // Act
        var result = await _controller.GetAuditLogById(999);

        // Assert
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    /// <summary>
    /// Integration test: Verify complex aggregation queries.
    ///
    /// WHY INTEGRATION TEST?
    /// - Tests GroupBy, Count, Distinct with real database
    /// - Very difficult to mock IQueryable for these operations
    /// - In-memory DB executes actual LINQ-to-Entities
    /// </summary>
    [Fact]
    public async Task GetStatistics_CalculatesCorrectAggregations()
    {
        // Arrange
        // Add successful logs
        await _context.CertificateAuditLogs.AddRangeAsync(new[]
        {
            new CertificateAuditLog
            {
                CertificateSubject = "CN=Cert1",
                CertificateThumbprint = "CERT1",
                AuthenticationTime = DateTime.UtcNow,
                IsSuccessful = true
            },
            new CertificateAuditLog
            {
                CertificateSubject = "CN=Cert1",
                CertificateThumbprint = "CERT1", // Same cert, different log
                AuthenticationTime = DateTime.UtcNow.AddHours(-1),
                IsSuccessful = true
            },
            new CertificateAuditLog
            {
                CertificateSubject = "CN=Cert2",
                CertificateThumbprint = "CERT2", // Different cert
                AuthenticationTime = DateTime.UtcNow,
                IsSuccessful = true
            }
        });

        // Add failed log
        await _context.CertificateAuditLogs.AddAsync(new CertificateAuditLog
        {
            CertificateSubject = "CN=Failed",
            CertificateThumbprint = "FAILED",
            AuthenticationTime = DateTime.UtcNow,
            IsSuccessful = false,
            FailureReason = "Expired"
        });

        await _context.SaveChangesAsync();

        // Act
        var result = await _controller.GetStatistics();

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.Value.Should().NotBeNull();

        var valueType = okResult.Value!.GetType();

        // Verify aggregations
        var totalLogsProp = valueType.GetProperty("totalLogs");
        var totalLogs = (int)totalLogsProp!.GetValue(okResult.Value)!;
        totalLogs.Should().Be(4, "total of 4 logs");

        var uniqueCertsProp = valueType.GetProperty("uniqueCertificates");
        var uniqueCerts = (int)uniqueCertsProp!.GetValue(okResult.Value)!;
        uniqueCerts.Should().Be(3, "3 unique certificate thumbprints");

        var successRateProp = valueType.GetProperty("successRate");
        var successRate = (double)successRateProp!.GetValue(okResult.Value)!;
        successRate.Should().BeApproximately(75.0, 0.1, "3 out of 4 successful = 75%");
    }

    /// <summary>
    /// Integration test: Verify AuditService with real database.
    ///
    /// WHY TEST SERVICE IN INTEGRATION TESTS?
    /// - Service unit tests would mock DbContext
    /// - Integration tests verify service works with real database
    /// - Tests complete data access flow
    /// </summary>
    [Fact]
    public async Task AuditService_LogsAndRetrievesSuccessfully()
    {
        // Arrange & Act
        await _auditService.LogSuccessfulAuthenticationAsync(
            "CN=Service Test",
            "SERVICE_TEST_123",
            "CN=Test CA",
            "192.168.1.1",
            "GET /api/test");

        // Assert
        var logs = await _auditService.GetAuditLogsByThumbprintAsync("SERVICE_TEST_123");

        logs.Should().HaveCount(1);
        logs.First().IsSuccessful.Should().BeTrue();
        logs.First().IpAddress.Should().Be("192.168.1.1");
    }

    [Fact]
    public async Task AuditService_GetFailedAttempts_FiltersCorrectly()
    {
        // Arrange
        // Add recent failed attempt
        await _auditService.LogFailedAuthenticationAsync(
            "CN=Failed",
            "FAILED_123",
            "CN=CA",
            "Invalid",
            "10.0.0.1",
            "GET /api/secure");

        // Add old successful attempt (should not be returned)
        await _context.CertificateAuditLogs.AddAsync(new CertificateAuditLog
        {
            CertificateSubject = "CN=Old",
            CertificateThumbprint = "OLD_123",
            AuthenticationTime = DateTime.UtcNow.AddDays(-10), // Old
            IsSuccessful = false,
            FailureReason = "Expired"
        });
        await _context.SaveChangesAsync();

        // Act
        var failedAttempts = await _auditService.GetFailedAttemptsAsync(
            DateTime.UtcNow.AddHours(-1)); // Last hour only

        // Assert
        failedAttempts.Should().HaveCount(1, "only recent failed attempt");
        failedAttempts.First().CertificateThumbprint.Should().Be("FAILED_123");
    }

    // Helper methods

    private X509Certificate2 CreateTestCertificate()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Integration Test Certificate",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        var exported = cert.Export(X509ContentType.Pfx, "test");
        return X509CertificateLoader.LoadPkcs12(exported, "test");
    }

    private void SetupHttpContext(ControllerBase controller, X509Certificate2? certificate)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");

        if (certificate != null)
        {
            httpContext.Connection.ClientCertificate = certificate;
        }

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext
        };
    }

    public void Dispose()
    {
        _testCertificate?.Dispose();
        _context?.Dispose();
    }
}
