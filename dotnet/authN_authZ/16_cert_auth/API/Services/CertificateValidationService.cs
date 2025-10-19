using System.Security.Cryptography.X509Certificates;

namespace API.Services;

/// <summary>
/// Validates client certificates against a local CA certificate without requiring
/// system-wide installation. This is ideal for development and testing environments.
/// </summary>
public class CertificateValidationService : ICertificateValidationService
{
    private readonly X509Certificate2Collection _trustedCertificates;
    private readonly ILogger<CertificateValidationService> _logger;
    private readonly bool _checkRevocation;
    private readonly bool _allowSelfSigned;

    public CertificateValidationService(
        IConfiguration configuration,
        ILogger<CertificateValidationService> logger)
    {
        _logger = logger;
        _trustedCertificates = new X509Certificate2Collection();

        // Load configuration
        var certConfig = configuration.GetSection("CertificateAuthentication");
        _checkRevocation = certConfig.GetValue("CheckRevocation", false);
        _allowSelfSigned = certConfig.GetValue("AllowSelfSigned", false);

        // Load trusted CA certificates from file system (not from system store)
        LoadTrustedCertificates(certConfig);
    }

    private void LoadTrustedCertificates(IConfigurationSection config)
    {
        var trustedCertPaths = config.GetSection("TrustedCertificates").Get<List<string>>() ?? new();

        foreach (var certPath in trustedCertPaths)
        {
            try
            {
                if (File.Exists(certPath))
                {
                    // Use X509CertificateLoader for .NET 9 (constructor is obsolete)
                    var cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
                    _trustedCertificates.Add(cert);
                    _logger.LogInformation(
                        "Loaded trusted certificate: {Subject} (Issuer: {Issuer})",
                        cert.Subject,
                        cert.Issuer);
                }
                else
                {
                    _logger.LogWarning("Trusted certificate file not found: {Path}", certPath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load trusted certificate from: {Path}", certPath);
            }
        }

        if (_trustedCertificates.Count == 0)
        {
            _logger.LogWarning(
                "No trusted certificates loaded. Certificate validation will fail unless AllowSelfSigned is true.");
        }
    }

    public bool ValidateCertificate(X509Certificate2 clientCertificate, X509Chain? chain)
    {
        var result = ValidateWithDetails(clientCertificate);
        return result.IsValid;
    }

    public CertificateValidationResult ValidateWithDetails(X509Certificate2 clientCertificate)
    {
        // Validate input parameter to prevent NullReferenceException
        // This provides a clear error message instead of allowing the code to crash
        ArgumentNullException.ThrowIfNull(clientCertificate, nameof(clientCertificate));

        var result = new CertificateValidationResult
        {
            SubjectName = clientCertificate.Subject,
            IssuerName = clientCertificate.Issuer,
            NotBefore = clientCertificate.NotBefore,
            NotAfter = clientCertificate.NotAfter
        };

        try
        {
            // 1. Check certificate validity period
            var now = DateTime.UtcNow;
            if (now < clientCertificate.NotBefore)
            {
                result.Errors.Add($"Certificate not yet valid. Valid from: {clientCertificate.NotBefore:u}");
            }

            if (now > clientCertificate.NotAfter)
            {
                result.Errors.Add($"Certificate has expired. Valid until: {clientCertificate.NotAfter:u}");
            }

            // 2. Build and validate certificate chain
            using var chain = new X509Chain();

            // Configure chain building to use our custom trust store
            chain.ChainPolicy.RevocationMode = _checkRevocation
                ? X509RevocationMode.Online
                : X509RevocationMode.NoCheck;

            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            // Add our trusted CA certificates to the chain's extra store
            // This allows validation without installing certificates system-wide
            chain.ChainPolicy.ExtraStore.AddRange(_trustedCertificates);

            // For development: allow partial chain if we only have root CA
            if (_allowSelfSigned)
            {
                chain.ChainPolicy.VerificationFlags |= X509VerificationFlags.AllowUnknownCertificateAuthority;
            }

            // Build the certificate chain
            var chainBuilt = chain.Build(clientCertificate);
            result.ChainIsValid = chainBuilt;

            // Collect chain status information
            foreach (var status in chain.ChainStatus)
            {
                var statusMessage = $"{status.Status}: {status.StatusInformation}";
                result.ChainStatus.Add(statusMessage);

                // Determine if this is an error or warning
                if (IsChainStatusError(status.Status))
                {
                    result.Errors.Add(statusMessage);
                }
                else
                {
                    result.Warnings.Add(statusMessage);
                }
            }

            // 3. Verify the chain terminates at one of our trusted certificates
            if (chainBuilt && chain.ChainElements.Count > 0)
            {
                var rootCert = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                var trustedRoot = _trustedCertificates
                    .Cast<X509Certificate2>()
                    .Any(trusted => trusted.Thumbprint == rootCert.Thumbprint);

                if (!trustedRoot && !_allowSelfSigned)
                {
                    result.Errors.Add(
                        $"Certificate chain does not terminate at a trusted root. " +
                        $"Root thumbprint: {rootCert.Thumbprint}");
                }
                else if (trustedRoot)
                {
                    _logger.LogInformation(
                        "Certificate chain validated successfully. Root: {Subject}",
                        rootCert.Subject);
                }
            }

            // 4. Additional validation: Check for client authentication EKU
            var hasClientAuthEku = clientCertificate.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .Any(ext => ext.EnhancedKeyUsages
                    .Cast<System.Security.Cryptography.Oid>()
                    .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2")); // Client Authentication OID

            if (!hasClientAuthEku)
            {
                result.Warnings.Add(
                    "Certificate does not have Client Authentication Extended Key Usage (EKU)");
            }

            // Determine overall validity
            result.IsValid = result.Errors.Count == 0;

            if (result.IsValid)
            {
                _logger.LogInformation(
                    "Certificate validation successful for: {Subject}",
                    clientCertificate.Subject);
            }
            else
            {
                _logger.LogWarning(
                    "Certificate validation failed for: {Subject}. Errors: {Errors}",
                    clientCertificate.Subject,
                    string.Join(", ", result.Errors));
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Exception during validation: {ex.Message}");
            _logger.LogError(ex, "Exception during certificate validation for: {Subject}",
                clientCertificate.Subject);
        }

        return result;
    }

    private bool IsChainStatusError(X509ChainStatusFlags status)
    {
        // These statuses should be considered errors (not warnings)
        var errorStatuses = new[]
        {
            X509ChainStatusFlags.NotTimeValid,
            X509ChainStatusFlags.NotTimeNested,
            X509ChainStatusFlags.Revoked,
            X509ChainStatusFlags.NotSignatureValid,
            X509ChainStatusFlags.NotValidForUsage,
            X509ChainStatusFlags.UntrustedRoot,
            X509ChainStatusFlags.RevocationStatusUnknown,
            X509ChainStatusFlags.Cyclic,
            X509ChainStatusFlags.InvalidExtension,
            X509ChainStatusFlags.InvalidPolicyConstraints,
            X509ChainStatusFlags.InvalidBasicConstraints,
            X509ChainStatusFlags.InvalidNameConstraints,
            X509ChainStatusFlags.HasNotSupportedNameConstraint,
            X509ChainStatusFlags.HasNotDefinedNameConstraint,
            X509ChainStatusFlags.HasNotPermittedNameConstraint,
            X509ChainStatusFlags.HasExcludedNameConstraint,
            X509ChainStatusFlags.CtlNotTimeValid,
            X509ChainStatusFlags.CtlNotSignatureValid,
            X509ChainStatusFlags.CtlNotValidForUsage
        };

        return errorStatuses.Any(errorStatus => status.HasFlag(errorStatus));
    }
}
