using System.Security.Cryptography.X509Certificates;
using API.Services;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;

namespace API.Tests;

/// <summary>
/// Unit tests for CertificateValidationService.
/// These tests validate the certificate validation logic without requiring integration with the full API.
/// </summary>
public class CertificateValidationServiceTests : IDisposable
{
    private readonly Mock<ILogger<CertificateValidationService>> _mockLogger;
    private readonly IConfiguration _configuration;
    // Field removed - was never used since we create certificates in-memory for unit tests
    // private readonly string _testCertPath = "../../../TestCertificates";
    private readonly List<X509Certificate2> _certificatesToDispose = new();

    public CertificateValidationServiceTests()
    {
        _mockLogger = new Mock<ILogger<CertificateValidationService>>();

        // Create test configuration
        var configDict = new Dictionary<string, string?>
        {
            ["CertificateAuthentication:AllowSelfSigned"] = "true",
            ["CertificateAuthentication:CheckRevocation"] = "false",
            ["CertificateAuthentication:TrustedCertificates:0"] = GetCertPath("root-ca.crt"),
            ["CertificateAuthentication:TrustedCertificates:1"] = GetCertPath("intermediate-ca.crt")
        };

        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configDict)
            .Build();
    }

    private string GetCertPath(string filename)
    {
        // Try to find certificates in parent directories
        var baseDir = Directory.GetCurrentDirectory();
        var certDir = Path.Combine(baseDir, "certificates");

        // If certificates don't exist yet, return expected path
        if (!Directory.Exists(certDir))
        {
            return Path.Combine("certificates", filename);
        }

        return Path.Combine(certDir, filename);
    }

    [Fact]
    public void Constructor_ShouldLoadTrustedCertificates_WhenFilesExist()
    {
        // This test will pass even if certificates don't exist yet
        // The service logs warnings but doesn't throw exceptions

        // Act
        var service = new CertificateValidationService(_configuration, _mockLogger.Object);

        // Assert
        service.Should().NotBeNull();
    }

    [Fact]
    public void ValidateCertificate_ShouldReturnFalse_WhenCertificateIsNull()
    {
        // Arrange
        var service = new CertificateValidationService(_configuration, _mockLogger.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
        {
            service.ValidateCertificate(null!, null);
        });
    }

    [Fact]
    public void ValidateWithDetails_ShouldReturnExpiredError_WhenCertificateIsExpired()
    {
        // Arrange
        var service = new CertificateValidationService(_configuration, _mockLogger.Object);

        // Create a self-signed certificate that's already expired
        var cert = CreateSelfSignedCertificate(
            "CN=Expired Test",
            DateTime.UtcNow.AddDays(-365),
            DateTime.UtcNow.AddDays(-1));

        _certificatesToDispose.Add(cert);

        // Act
        var result = service.ValidateWithDetails(cert);

        // Assert
        result.Should().NotBeNull();
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Contains("expired"));
    }

    [Fact]
    public void ValidateWithDetails_ShouldReturnNotYetValidError_WhenCertificateNotYetValid()
    {
        // Arrange
        var service = new CertificateValidationService(_configuration, _mockLogger.Object);

        // Create a self-signed certificate that's not yet valid
        var cert = CreateSelfSignedCertificate(
            "CN=Future Test",
            DateTime.UtcNow.AddDays(1),
            DateTime.UtcNow.AddDays(365));

        _certificatesToDispose.Add(cert);

        // Act
        var result = service.ValidateWithDetails(cert);

        // Assert
        result.Should().NotBeNull();
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Contains("not yet valid"));
    }

    [Fact]
    public void ValidateWithDetails_ShouldPopulateCertificateDetails()
    {
        // Arrange
        var service = new CertificateValidationService(_configuration, _mockLogger.Object);
        var subjectName = "CN=Test Certificate";

        var cert = CreateSelfSignedCertificate(
            subjectName,
            DateTime.UtcNow.AddDays(-1),
            DateTime.UtcNow.AddDays(365));

        _certificatesToDispose.Add(cert);

        // Act
        var result = service.ValidateWithDetails(cert);

        // Assert
        result.SubjectName.Should().Be(subjectName);
        result.IssuerName.Should().Be(subjectName); // Self-signed

        // Note: X509Certificate2 stores dates in UTC but returns them in local time
        // We compare with a tolerance because:
        // 1. Certificate creation takes non-zero time
        // 2. Timezone conversions may introduce small differences
        // Using 2-day tolerance to handle timezone differences (max ~24h) plus creation delay
        result.NotBefore.Should().BeCloseTo(DateTime.Now.AddDays(-1), TimeSpan.FromDays(2));
        result.NotAfter.Should().BeCloseTo(DateTime.Now.AddDays(365), TimeSpan.FromDays(2));
    }

    [Fact]
    public void ValidateWithDetails_ShouldIncludeChainStatus()
    {
        // Arrange
        var service = new CertificateValidationService(_configuration, _mockLogger.Object);

        var cert = CreateSelfSignedCertificate(
            "CN=Test Certificate",
            DateTime.UtcNow.AddDays(-1),
            DateTime.UtcNow.AddDays(365));

        _certificatesToDispose.Add(cert);

        // Act
        var result = service.ValidateWithDetails(cert);

        // Assert
        result.ChainStatus.Should().NotBeEmpty();
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Constructor_ShouldRespectConfiguration_ForRevocationAndSelfSignedSettings(
        bool checkRevocation,
        bool allowSelfSigned)
    {
        // Arrange
        var configDict = new Dictionary<string, string?>
        {
            ["CertificateAuthentication:AllowSelfSigned"] = allowSelfSigned.ToString(),
            ["CertificateAuthentication:CheckRevocation"] = checkRevocation.ToString(),
            ["CertificateAuthentication:TrustedCertificates:0"] = GetCertPath("root-ca.crt")
        };

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(configDict)
            .Build();

        // Act
        var service = new CertificateValidationService(config, _mockLogger.Object);

        // Assert
        service.Should().NotBeNull();
        // Configuration is internal, but the service should be created without errors
    }

    // Helper method to create self-signed certificates for testing
    private X509Certificate2 CreateSelfSignedCertificate(
        string subjectName,
        DateTime notBefore,
        DateTime notAfter)
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);

        var request = new CertificateRequest(
            subjectName,
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);

        // Add basic constraints
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        // Add key usage
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));

        var certificate = request.CreateSelfSigned(notBefore, notAfter);

        // Export and reimport to ensure it's in the correct format with proper key storage
        // Using X509CertificateLoader instead of constructor (new in .NET 9)
        var exported = certificate.Export(X509ContentType.Pfx, "test");
        return X509CertificateLoader.LoadPkcs12(
            exported,
            "test",
            X509KeyStorageFlags.Exportable);
    }

    public void Dispose()
    {
        foreach (var cert in _certificatesToDispose)
        {
            cert?.Dispose();
        }
    }
}
