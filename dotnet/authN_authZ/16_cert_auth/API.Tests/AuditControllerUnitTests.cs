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
/// Unit tests for AuditController demonstrating WHEN and HOW to mock dependencies.
///
/// KEY CONCEPTS:
/// - Unit tests test ONE unit (the controller) in isolation
/// - External dependencies (DbContext, Services) are MOCKED
/// - Tests are fast because no real database is used
/// - Focus on testing controller logic, not data access or business logic
/// </summary>
public class AuditControllerUnitTests : IDisposable
{
    private readonly Mock<AppDbContext> _mockContext;
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly Mock<ILogger<AuditController>> _mockLogger;
    private readonly AuditController _controller;
    private readonly X509Certificate2? _testCertificate;

    public AuditControllerUnitTests()
    {
        // MOCKING SETUP:
        // We mock ALL external dependencies so we test ONLY the controller logic

        // 1. Mock DbContext
        // Why mock? We don't want to hit a real database in unit tests
        // How? Create a Mock<AppDbContext> with DbContextOptions
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()) // Unique DB per test
            .Options;
        _mockContext = new Mock<AppDbContext>(options);

        // 2. Mock Service Layer
        // Why mock? We're testing the CONTROLLER, not the service implementation
        // How? Mock the interface, setup expected method calls
        _mockAuditService = new Mock<IAuditService>();

        // 3. Mock Logger
        // Why mock? Logging is infrastructure, not business logic
        // How? Mock ILogger to verify log calls if needed
        _mockLogger = new Mock<ILogger<AuditController>>();

        // Create controller with mocked dependencies
        _controller = new AuditController(
            _mockContext.Object,
            _mockAuditService.Object,
            _mockLogger.Object);

        // Setup HTTP context with a test certificate
        _testCertificate = CreateTestCertificate();
        SetupHttpContext(_controller, _testCertificate);
    }

    /// <summary>
    /// Test: LogCurrentAuthentication should call audit service with correct parameters.
    ///
    /// WHY MOCK THE SERVICE?
    /// - We're testing that the CONTROLLER correctly calls the service
    /// - We don't care HOW the service implements the logging (that's tested in service unit tests)
    /// - We just verify the controller passes the right parameters
    /// </summary>
    [Fact]
    public async Task LogCurrentAuthentication_WithValidCertificate_CallsAuditService()
    {
        // Arrange
        // Setup the mock to expect a specific method call
        // For async methods returning Task (not Task<T>), use Returns with Task.CompletedTask
        _mockAuditService
            .Setup(s => s.LogSuccessfulAuthenticationAsync(
                It.IsAny<string>(),      // certificateSubject
                It.IsAny<string>(),      // certificateThumbprint
                It.IsAny<string?>(),     // issuerName
                It.IsAny<string?>(),     // ipAddress
                It.IsAny<string?>()))    // endpoint
            .Returns(Task.CompletedTask)  // For Task (not Task<T>), use Returns
            .Verifiable();  // Mark this setup as something we'll verify

        // Act
        var result = await _controller.LogCurrentAuthentication();

        // Assert
        result.Should().BeOfType<OkObjectResult>();

        // VERIFY THE MOCK: Ensure the service was called exactly once
        _mockAuditService.Verify(
            s => s.LogSuccessfulAuthenticationAsync(
                _testCertificate!.Subject,           // Expected subject
                _testCertificate.Thumbprint,         // Expected thumbprint
                _testCertificate.Issuer,             // Expected issuer
                It.IsAny<string?>(),                 // Don't care about IP
                It.Is<string>(e => e.Contains("POST"))),  // Endpoint should contain "POST"
            Times.Once);  // Should be called exactly once
    }

    /// <summary>
    /// Test: LogCurrentAuthentication should return 500 when service throws exception.
    ///
    /// WHY MOCK THE SERVICE TO THROW?
    /// - We need to test error handling in the controller
    /// - We can't easily make a real service throw in a predictable way
    /// - Mocking lets us simulate failures
    /// </summary>
    [Fact]
    public async Task LogCurrentAuthentication_WhenServiceFails_Returns500()
    {
        // Arrange
        // Setup mock to throw an exception
        _mockAuditService
            .Setup(s => s.LogSuccessfulAuthenticationAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<string?>()))
            .ThrowsAsync(new Exception("Database connection failed"));

        // Act
        var result = await _controller.LogCurrentAuthentication();

        // Assert
        var statusCodeResult = result.Should().BeOfType<ObjectResult>().Subject;
        statusCodeResult.StatusCode.Should().Be(500);
    }

    /// <summary>
    /// Test: GetMyAuditLogs uses DbContext directly.
    ///
    /// WHY IS THIS HARD TO TEST WITH MOCKS?
    /// - DbContext.DbSet is hard to mock because of LINQ queries
    /// - You'd need to mock IQueryable, AsAsyncEnumerable, etc.
    /// - This is where integration tests shine (use real in-memory DB)
    ///
    /// WHAT WE DO IN UNIT TESTS:
    /// - Test the happy path with minimal mocking
    /// - Leave complex query testing to integration tests
    /// </summary>
    [Fact]
    public async Task GetMyAuditLogs_WithoutCertificate_ReturnsBadRequest()
    {
        // Arrange
        // Remove certificate from HTTP context
        SetupHttpContext(_controller, null);

        // Act
        var result = await _controller.GetMyAuditLogs();

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    /// <summary>
    /// Test: GetRecentAuditLogs delegates to service.
    ///
    /// WHY MOCK THE SERVICE?
    /// - Controller just delegates to service, adds validation
    /// - We test that controller validates input and calls service
    /// - Service's implementation is tested separately
    /// </summary>
    [Fact]
    public async Task GetRecentAuditLogs_WithValidCount_CallsService()
    {
        // Arrange
        var expectedLogs = new List<CertificateAuditLog>
        {
            new() {
                Id = 1,
                CertificateSubject = "CN=Test",
                CertificateThumbprint = "ABC123",
                AuthenticationTime = DateTime.UtcNow,
                IsSuccessful = true
            }
        };

        _mockAuditService
            .Setup(s => s.GetRecentAuditLogsAsync(50))
            .ReturnsAsync(expectedLogs)
            .Verifiable();

        // Act
        var result = await _controller.GetRecentAuditLogs(50);

        // Assert
        result.Should().BeOfType<OkObjectResult>();
        _mockAuditService.Verify(s => s.GetRecentAuditLogsAsync(50), Times.Once);
    }

    /// <summary>
    /// Test: GetRecentAuditLogs validates input.
    ///
    /// WHY TEST THIS?
    /// - Controller is responsible for input validation
    /// - This is controller logic, not service logic
    /// - No need to call service if validation fails
    /// </summary>
    [Theory]
    [InlineData(0)]      // Too small
    [InlineData(-1)]     // Negative
    [InlineData(1001)]   // Too large
    public async Task GetRecentAuditLogs_WithInvalidCount_ReturnsBadRequest(int count)
    {
        // Act
        var result = await _controller.GetRecentAuditLogs(count);

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();

        // Verify service was NEVER called (because validation failed)
        _mockAuditService.Verify(
            s => s.GetRecentAuditLogsAsync(It.IsAny<int>()),
            Times.Never);
    }

    /// <summary>
    /// Test: GetFailedAttempts uses service and adds business logic.
    ///
    /// WHAT'S BEING TESTED?
    /// - Controller calls service with correct time calculation
    /// - Controller applies business logic (grouping, flagging suspicious)
    /// - This tests controller's value-add beyond just delegation
    /// </summary>
    [Fact]
    public async Task GetFailedAttempts_IdentifiesSuspiciousPatterns()
    {
        // Arrange
        var failedLogs = new List<CertificateAuditLog>();

        // Create multiple failures from same certificate (suspicious!)
        for (int i = 0; i < 10; i++)
        {
            failedLogs.Add(new CertificateAuditLog
            {
                Id = i,
                CertificateSubject = "CN=Suspicious",
                CertificateThumbprint = "SUSPICIOUS123",
                AuthenticationTime = DateTime.UtcNow.AddMinutes(-i),
                IsSuccessful = false,
                FailureReason = "Invalid certificate"
            });
        }

        // Add a few failures from different certificate (not suspicious)
        failedLogs.Add(new CertificateAuditLog
        {
            Id = 11,
            CertificateSubject = "CN=Normal",
            CertificateThumbprint = "NORMAL456",
            AuthenticationTime = DateTime.UtcNow,
            IsSuccessful = false,
            FailureReason = "Expired"
        });

        _mockAuditService
            .Setup(s => s.GetFailedAttemptsAsync(It.IsAny<DateTime>()))
            .ReturnsAsync(failedLogs);

        // Act
        var result = await _controller.GetFailedAttempts(24);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.Value.Should().NotBeNull();

        // Use reflection to get the property value (avoiding dynamic)
        var valueType = okResult.Value!.GetType();
        var suspiciousCertsProp = valueType.GetProperty("suspiciousCertificates");
        var suspiciousCerts = (int)suspiciousCertsProp!.GetValue(okResult.Value)!;

        // Verify business logic: suspicious certificate is flagged
        suspiciousCerts.Should().Be(1); // One cert has >5 failures
    }

    // Helper methods

    private X509Certificate2 CreateTestCertificate()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test Certificate",
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

        // Setup request path and method for endpoint logging
        httpContext.Request.Method = "POST";
        httpContext.Request.Path = "/api/audit/log-current-auth";

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
    }
}
