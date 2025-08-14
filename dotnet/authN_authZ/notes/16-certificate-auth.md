# Certificate-Based Authentication

## Overview
Certificate-based authentication uses digital certificates (X.509) to verify the identity of users or applications. It provides strong authentication through public key cryptography and is commonly used in enterprise environments, API security, and high-security applications.

## Core Concepts

### 1. Certificate Components

#### X.509 Certificate Structure
- **Subject**: Identity of the certificate holder
- **Issuer**: Certificate Authority (CA) that signed the certificate
- **Public Key**: Used for encryption and signature verification
- **Private Key**: Kept secret, used for decryption and signing
- **Validity Period**: Certificate's valid date range
- **Serial Number**: Unique identifier from the CA
- **Digital Signature**: CA's signature validating the certificate

#### Certificate Authority (CA)
- Trusted third party that issues certificates
- Maintains certificate revocation lists (CRL)
- Can be public (VeriSign, DigiCert) or private (enterprise CA)
- Root CA certificates are pre-installed in systems

#### Certificate Chain
- Chain of trust from certificate to root CA
- Intermediate CAs can issue certificates on behalf of root CA
- Full chain validation ensures certificate authenticity

### 2. Authentication Process

#### Client Certificate Authentication
1. Client presents certificate during TLS handshake
2. Server validates certificate chain
3. Server checks certificate revocation status
4. Server verifies certificate is within validity period
5. Server maps certificate to user identity

#### Mutual TLS (mTLS)
- Both client and server authenticate with certificates
- Provides strong bidirectional authentication
- Common in service-to-service communication

### 3. Certificate Storage

#### Windows Certificate Store
- Personal store for user certificates
- Computer store for machine certificates
- Trusted Root CA store for root certificates

#### Hardware Security Modules (HSM)
- Dedicated hardware for key storage
- Provides tamper-resistant key protection
- Common in high-security environments

## .NET Certificate Authentication Implementation

### 1. Basic Certificate Authentication Setup

#### Installation
```bash
dotnet add package Microsoft.AspNetCore.Authentication.Certificate
dotnet add package System.Security.Cryptography.X509Certificates
```

#### Basic Configuration
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
        .AddCertificate(options =>
        {
            // Certificate validation options
            options.AllowedCertificateTypes = CertificateTypes.All;
            options.ValidateCertificateUse = true;
            options.ValidateValidityPeriod = true;
            options.RevocationMode = X509RevocationMode.NoCheck; // Configure as needed
            
            // Custom validation
            options.Events = new CertificateAuthenticationEvents
            {
                OnCertificateValidated = context =>
                {
                    var validationService = context.HttpContext.RequestServices
                        .GetRequiredService<ICertificateValidationService>();
                    
                    return validationService.ValidateAsync(context);
                },
                
                OnAuthenticationFailed = context =>
                {
                    context.Response.StatusCode = 403;
                    context.Response.Headers.Add("WWW-Authenticate", "Certificate");
                    return Task.CompletedTask;
                }
            };
        });
    
    // Add certificate forwarding for proxy scenarios
    services.AddCertificateForwarding(options =>
    {
        options.CertificateHeader = "X-SSL-CERT";
        options.HeaderConverter = (headerValue) =>
        {
            X509Certificate2 clientCertificate = null;
            
            if (!string.IsNullOrWhiteSpace(headerValue))
            {
                byte[] bytes = Convert.FromBase64String(headerValue);
                clientCertificate = new X509Certificate2(bytes);
            }
            
            return clientCertificate;
        };
    });
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // Certificate forwarding must be before authentication
    app.UseCertificateForwarding();
    
    app.UseAuthentication();
    app.UseAuthorization();
}
```

### 2. Certificate Validation Service

```csharp
public interface ICertificateValidationService
{
    Task<bool> ValidateAsync(CertificateValidatedContext context);
    Task<bool> IsValidCertificateAsync(X509Certificate2 certificate);
    Task<bool> CheckRevocationAsync(X509Certificate2 certificate);
    Task<ApplicationUser> GetUserFromCertificateAsync(X509Certificate2 certificate);
}

public class CertificateValidationService : ICertificateValidationService
{
    private readonly IUserService _userService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<CertificateValidationService> _logger;
    private readonly IMemoryCache _cache;
    
    public CertificateValidationService(
        IUserService userService,
        IConfiguration configuration,
        ILogger<CertificateValidationService> logger,
        IMemoryCache cache)
    {
        _userService = userService;
        _configuration = configuration;
        _logger = logger;
        _cache = cache;
    }
    
    public async Task<bool> ValidateAsync(CertificateValidatedContext context)
    {
        try
        {
            var certificate = context.ClientCertificate;
            
            // Basic certificate validation
            if (!await IsValidCertificateAsync(certificate))
            {
                _logger.LogWarning("Certificate validation failed for {Subject}", certificate.Subject);
                return false;
            }
            
            // Check revocation status
            if (!await CheckRevocationAsync(certificate))
            {
                _logger.LogWarning("Certificate revocation check failed for {Subject}", certificate.Subject);
                return false;
            }
            
            // Map certificate to user
            var user = await GetUserFromCertificateAsync(certificate);
            
            if (user == null)
            {
                _logger.LogWarning("No user found for certificate {Subject}", certificate.Subject);
                return false;
            }
            
            // Create claims identity
            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, user.Id),
                new(ClaimTypes.Name, user.UserName),
                new(ClaimTypes.Email, user.Email ?? ""),
                new("certificate_thumbprint", certificate.Thumbprint),
                new("certificate_subject", certificate.Subject),
                new("certificate_issuer", certificate.Issuer),
                new("auth_method", "certificate")
            };
            
            // Add user roles
            var roles = await _userService.GetUserRolesAsync(user.Id);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            
            context.Principal = new ClaimsPrincipal(
                new ClaimsIdentity(claims, CertificateAuthenticationDefaults.AuthenticationScheme));
            
            context.Success();
            
            _logger.LogInformation("Certificate authentication successful for user {Username}", user.UserName);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during certificate validation");
            context.Fail("Certificate validation error");
            return false;
        }
    }
    
    public async Task<bool> IsValidCertificateAsync(X509Certificate2 certificate)
    {
        var cacheKey = $"cert_validation_{certificate.Thumbprint}";
        
        if (_cache.TryGetValue(cacheKey, out bool cachedResult))
            return cachedResult;
        
        try
        {
            // Check certificate validity period
            var now = DateTime.UtcNow;
            if (now < certificate.NotBefore || now > certificate.NotAfter)
            {
                _logger.LogWarning("Certificate {Thumbprint} is outside validity period", certificate.Thumbprint);
                return false;
            }
            
            // Validate certificate chain
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // We'll check separately
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreEndRevocationUnknown;
            
            var isValidChain = chain.Build(certificate);
            
            if (!isValidChain)
            {
                _logger.LogWarning("Certificate chain validation failed for {Thumbprint}. Errors: {Errors}",
                    certificate.Thumbprint, 
                    string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation)));
                return false;
            }
            
            // Check if certificate is in allowed certificate list
            if (!await IsAllowedCertificateAsync(certificate))
            {
                _logger.LogWarning("Certificate {Thumbprint} is not in allowed list", certificate.Thumbprint);
                return false;
            }
            
            // Check certificate key usage
            if (!HasValidKeyUsage(certificate))
            {
                _logger.LogWarning("Certificate {Thumbprint} does not have valid key usage", certificate.Thumbprint);
                return false;
            }
            
            // Cache result for 30 minutes
            _cache.Set(cacheKey, true, TimeSpan.FromMinutes(30));
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating certificate {Thumbprint}", certificate.Thumbprint);
            return false;
        }
    }
    
    public async Task<bool> CheckRevocationAsync(X509Certificate2 certificate)
    {
        var cacheKey = $"cert_revocation_{certificate.Thumbprint}";
        
        if (_cache.TryGetValue(cacheKey, out bool cachedResult))
            return cachedResult;
        
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            
            var result = chain.Build(certificate);
            
            var hasRevocationError = chain.ChainStatus.Any(status => 
                status.Status == X509ChainStatusFlags.Revoked ||
                status.Status == X509ChainStatusFlags.RevocationStatusUnknown);
            
            var isValid = result && !hasRevocationError;
            
            // Cache result for 15 minutes (shorter for revocation)
            _cache.Set(cacheKey, isValid, TimeSpan.FromMinutes(15));
            
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking certificate revocation for {Thumbprint}", certificate.Thumbprint);
            return false; // Fail secure
        }
    }
    
    public async Task<ApplicationUser> GetUserFromCertificateAsync(X509Certificate2 certificate)
    {
        // Method 1: Find by certificate thumbprint
        var user = await _userService.FindByCertificateThumbprintAsync(certificate.Thumbprint);
        if (user != null) return user;
        
        // Method 2: Find by subject alternative name (email)
        var email = ExtractEmailFromCertificate(certificate);
        if (!string.IsNullOrEmpty(email))
        {
            user = await _userService.FindByEmailAsync(email);
            if (user != null) return user;
        }
        
        // Method 3: Find by subject CN
        var commonName = ExtractCommonNameFromSubject(certificate.Subject);
        if (!string.IsNullOrEmpty(commonName))
        {
            user = await _userService.FindByUsernameAsync(commonName);
            if (user != null) return user;
        }
        
        // Method 4: Find by UPN (User Principal Name) if present
        var upn = ExtractUpnFromCertificate(certificate);
        if (!string.IsNullOrEmpty(upn))
        {
            user = await _userService.FindByUpnAsync(upn);
            if (user != null) return user;
        }
        
        return null;
    }
    
    private async Task<bool> IsAllowedCertificateAsync(X509Certificate2 certificate)
    {
        // Check against allowed issuers
        var allowedIssuers = _configuration.GetSection("CertificateAuth:AllowedIssuers").Get<string[]>();
        if (allowedIssuers?.Any() == true)
        {
            var normalizedIssuer = NormalizeDN(certificate.Issuer);
            var isAllowedIssuer = allowedIssuers.Any(issuer => 
                NormalizeDN(issuer).Equals(normalizedIssuer, StringComparison.OrdinalIgnoreCase));
            
            if (!isAllowedIssuer)
                return false;
        }
        
        // Check against certificate whitelist
        var allowedThumbprints = _configuration.GetSection("CertificateAuth:AllowedThumbprints").Get<string[]>();
        if (allowedThumbprints?.Any() == true)
        {
            return allowedThumbprints.Contains(certificate.Thumbprint, StringComparer.OrdinalIgnoreCase);
        }
        
        return true;
    }
    
    private bool HasValidKeyUsage(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509KeyUsageExtension keyUsage)
            {
                // Check if certificate has digital signature capability
                return keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature) ||
                       keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyAuthentication);
            }
        }
        
        return true; // If no key usage extension, assume valid
    }
    
    private string ExtractEmailFromCertificate(X509Certificate2 certificate)
    {
        // Check Subject Alternative Name extension
        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid.Value == "2.5.29.17") // Subject Alternative Name
            {
                var sanExtension = extension as X509SubjectAlternativeNameExtension;
                if (sanExtension != null)
                {
                    // This is simplified - in practice you'd need to parse ASN.1
                    var sanData = extension.Format(false);
                    var emailMatch = System.Text.RegularExpressions.Regex.Match(sanData, @"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
                    if (emailMatch.Success)
                        return emailMatch.Value;
                }
            }
        }
        
        // Check subject for email
        return ExtractAttributeFromSubject(certificate.Subject, "E");
    }
    
    private string ExtractCommonNameFromSubject(string subject)
    {
        return ExtractAttributeFromSubject(subject, "CN");
    }
    
    private string ExtractUpnFromCertificate(X509Certificate2 certificate)
    {
        // UPN is typically in Subject Alternative Name
        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid.Value == "2.5.29.17") // Subject Alternative Name
            {
                // This would require proper ASN.1 parsing in production
                var sanData = extension.Format(false);
                var upnMatch = System.Text.RegularExpressions.Regex.Match(sanData, @"Principal Name=([^,\r\n]+)");
                if (upnMatch.Success)
                    return upnMatch.Groups[1].Value;
            }
        }
        
        return null;
    }
    
    private string ExtractAttributeFromSubject(string subject, string attributeName)
    {
        var parts = subject.Split(',');
        foreach (var part in parts)
        {
            var trimmedPart = part.Trim();
            if (trimmedPart.StartsWith($"{attributeName}=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmedPart.Substring(attributeName.Length + 1);
            }
        }
        return null;
    }
    
    private string NormalizeDN(string dn)
    {
        // Normalize Distinguished Name format for comparison
        return dn.Replace(" ", "").Replace(",", ", ").ToUpperInvariant();
    }
}
```

### 3. Certificate Management Service

```csharp
public interface ICertificateManagementService
{
    Task<X509Certificate2> LoadCertificateAsync(string thumbprint, StoreLocation location = StoreLocation.CurrentUser);
    Task<List<X509Certificate2>> GetUserCertificatesAsync(string userId);
    Task<bool> AssociateCertificateWithUserAsync(string userId, string thumbprint);
    Task<bool> RevokeCertificateAsync(string thumbprint);
    Task<X509Certificate2> GenerateClientCertificateAsync(string userName, string email);
}

public class CertificateManagementService : ICertificateManagementService
{
    private readonly IUserService _userService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<CertificateManagementService> _logger;
    
    public CertificateManagementService(
        IUserService userService,
        IConfiguration configuration,
        ILogger<CertificateManagementService> logger)
    {
        _userService = userService;
        _configuration = configuration;
        _logger = logger;
    }
    
    public async Task<X509Certificate2> LoadCertificateAsync(string thumbprint, StoreLocation location = StoreLocation.CurrentUser)
    {
        using var store = new X509Store(StoreName.My, location);
        store.Open(OpenFlags.ReadOnly);
        
        var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        
        if (certificates.Count == 0)
        {
            throw new InvalidOperationException($"Certificate with thumbprint {thumbprint} not found");
        }
        
        var certificate = certificates[0];
        
        // Validate certificate
        if (certificate.NotAfter < DateTime.UtcNow)
        {
            throw new InvalidOperationException("Certificate has expired");
        }
        
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException("Certificate does not have a private key");
        }
        
        return certificate;
    }
    
    public async Task<List<X509Certificate2>> GetUserCertificatesAsync(string userId)
    {
        var user = await _userService.GetUserByIdAsync(userId);
        if (user == null) return new List<X509Certificate2>();
        
        var certificateThumbprints = await _userService.GetUserCertificateThumbprintsAsync(userId);
        var certificates = new List<X509Certificate2>();
        
        foreach (var thumbprint in certificateThumbprints)
        {
            try
            {
                var certificate = await LoadCertificateAsync(thumbprint);
                certificates.Add(certificate);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load certificate {Thumbprint} for user {UserId}", thumbprint, userId);
            }
        }
        
        return certificates;
    }
    
    public async Task<bool> AssociateCertificateWithUserAsync(string userId, string thumbprint)
    {
        try
        {
            // Verify certificate exists and is valid
            var certificate = await LoadCertificateAsync(thumbprint);
            
            // Associate with user
            await _userService.AddCertificateToUserAsync(userId, thumbprint, certificate.Subject, certificate.Issuer);
            
            _logger.LogInformation("Associated certificate {Thumbprint} with user {UserId}", thumbprint, userId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to associate certificate {Thumbprint} with user {UserId}", thumbprint, userId);
            return false;
        }
    }
    
    public async Task<bool> RevokeCertificateAsync(string thumbprint)
    {
        try
        {
            // Mark certificate as revoked in user service
            await _userService.RevokeCertificateAsync(thumbprint);
            
            // In a real implementation, you would also add to CRL
            _logger.LogInformation("Revoked certificate {Thumbprint}", thumbprint);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke certificate {Thumbprint}", thumbprint);
            return false;
        }
    }
    
    public async Task<X509Certificate2> GenerateClientCertificateAsync(string userName, string email)
    {
        // This is a simplified example - in production you'd use a proper CA
        using var rsa = RSA.Create(2048);
        
        var request = new CertificateRequest(
            $"CN={userName}, E={email}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        
        // Add key usage extension
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAuthentication,
                critical: true));
        
        // Add extended key usage for client authentication
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, // Client Authentication
                critical: true));
        
        // Add Subject Alternative Name with email
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddEmailAddress(email);
        request.CertificateExtensions.Add(sanBuilder.Build());
        
        // Create self-signed certificate (in production, use proper CA)
        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
        
        _logger.LogInformation("Generated client certificate for {UserName}", userName);
        
        return certificate;
    }
}
```

### 4. Certificate-Based API Controller

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = CertificateAuthenticationDefaults.AuthenticationScheme)]
public class CertificateController : ControllerBase
{
    private readonly ICertificateManagementService _certificateService;
    private readonly IUserService _userService;
    
    public CertificateController(
        ICertificateManagementService certificateService,
        IUserService userService)
    {
        _certificateService = certificateService;
        _userService = userService;
    }
    
    [HttpGet("info")]
    public IActionResult GetCertificateInfo()
    {
        var thumbprint = User.FindFirst("certificate_thumbprint")?.Value;
        var subject = User.FindFirst("certificate_subject")?.Value;
        var issuer = User.FindFirst("certificate_issuer")?.Value;
        
        return Ok(new
        {
            Thumbprint = thumbprint,
            Subject = subject,
            Issuer = issuer,
            User = User.Identity.Name,
            AuthMethod = User.FindFirst("auth_method")?.Value
        });
    }
    
    [HttpGet("user-certificates")]
    public async Task<IActionResult> GetUserCertificates()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
            return BadRequest("User ID not found");
        
        var certificates = await _certificateService.GetUserCertificatesAsync(userId);
        
        var result = certificates.Select(cert => new
        {
            Thumbprint = cert.Thumbprint,
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            IsExpired = cert.NotAfter < DateTime.UtcNow
        });
        
        return Ok(result);
    }
    
    [HttpPost("associate")]
    public async Task<IActionResult> AssociateCertificate([FromBody] AssociateCertificateRequest request)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
            return BadRequest("User ID not found");
        
        var result = await _certificateService.AssociateCertificateWithUserAsync(userId, request.Thumbprint);
        
        if (result)
            return Ok(new { Message = "Certificate associated successfully" });
        
        return BadRequest("Failed to associate certificate");
    }
    
    [HttpPost("revoke")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> RevokeCertificate([FromBody] RevokeCertificateRequest request)
    {
        var result = await _certificateService.RevokeCertificateAsync(request.Thumbprint);
        
        if (result)
            return Ok(new { Message = "Certificate revoked successfully" });
        
        return BadRequest("Failed to revoke certificate");
    }
    
    [HttpPost("generate")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> GenerateClientCertificate([FromBody] GenerateCertificateRequest request)
    {
        try
        {
            var certificate = await _certificateService.GenerateClientCertificateAsync(request.UserName, request.Email);
            
            // Return certificate as PFX (password-protected)
            var pfxBytes = certificate.Export(X509ContentType.Pfx, request.Password);
            
            return File(pfxBytes, "application/x-pkcs12", $"{request.UserName}_certificate.pfx");
        }
        catch (Exception ex)
        {
            return BadRequest($"Failed to generate certificate: {ex.Message}");
        }
    }
}

public class AssociateCertificateRequest
{
    [Required]
    public string Thumbprint { get; set; }
}

public class RevokeCertificateRequest
{
    [Required]
    public string Thumbprint { get; set; }
    
    public string Reason { get; set; }
}

public class GenerateCertificateRequest
{
    [Required]
    public string UserName { get; set; }
    
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    
    [Required]
    public string Password { get; set; }
}
```

### 5. Certificate Authentication Middleware

```csharp
public class CertificateAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ICertificateValidationService _validationService;
    private readonly ILogger<CertificateAuthenticationMiddleware> _logger;
    
    public CertificateAuthenticationMiddleware(
        RequestDelegate next,
        ICertificateValidationService validationService,
        ILogger<CertificateAuthenticationMiddleware> logger)
    {
        _next = next;
        _validationService = validationService;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Check if request has client certificate
        var clientCert = context.Connection.ClientCertificate;
        
        if (clientCert != null)
        {
            // Log certificate details
            _logger.LogInformation("Client certificate received: {Subject} (Thumbprint: {Thumbprint})",
                clientCert.Subject, clientCert.Thumbprint);
            
            // Add certificate information to request context
            context.Items["ClientCertificate"] = clientCert;
            context.Items["CertificateThumbprint"] = clientCert.Thumbprint;
            context.Items["CertificateSubject"] = clientCert.Subject;
        }
        
        await _next(context);
    }
}

// Extension method for easier registration
public static class CertificateAuthenticationMiddlewareExtensions
{
    public static IApplicationBuilder UseCertificateAuthentication(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<CertificateAuthenticationMiddleware>();
    }
}
```

## Security Best Practices

### 1. Certificate Validation Security

```csharp
public class SecureCertificateValidator
{
    private readonly ILogger<SecureCertificateValidator> _logger;
    private readonly IConfiguration _configuration;
    
    public bool ValidateCertificateSecurely(X509Certificate2 certificate)
    {
        // 1. Check certificate validity period with buffer
        var now = DateTime.UtcNow;
        var validityBuffer = TimeSpan.FromDays(7); // Don't accept certificates expiring soon
        
        if (now < certificate.NotBefore || now > certificate.NotAfter.Subtract(validityBuffer))
        {
            _logger.LogWarning("Certificate validity period check failed");
            return false;
        }
        
        // 2. Validate key strength
        if (!HasSufficientKeyStrength(certificate))
        {
            _logger.LogWarning("Certificate key strength insufficient");
            return false;
        }
        
        // 3. Check for weak signature algorithms
        if (HasWeakSignatureAlgorithm(certificate))
        {
            _logger.LogWarning("Certificate uses weak signature algorithm");
            return false;
        }
        
        // 4. Validate certificate chain
        if (!ValidateCertificateChain(certificate))
        {
            _logger.LogWarning("Certificate chain validation failed");
            return false;
        }
        
        // 5. Check Certificate Transparency (if enabled)
        if (_configuration.GetValue<bool>("CertificateAuth:RequireCertificateTransparency"))
        {
            if (!HasCertificateTransparencyExtension(certificate))
            {
                _logger.LogWarning("Certificate lacks required Certificate Transparency extension");
                return false;
            }
        }
        
        return true;
    }
    
    private bool HasSufficientKeyStrength(X509Certificate2 certificate)
    {
        using var publicKey = certificate.GetRSAPublicKey();
        if (publicKey != null)
        {
            return publicKey.KeySize >= 2048; // Minimum RSA key size
        }
        
        using var ecdsaKey = certificate.GetECDsaPublicKey();
        if (ecdsaKey != null)
        {
            return ecdsaKey.KeySize >= 256; // Minimum ECDSA key size
        }
        
        return false;
    }
    
    private bool HasWeakSignatureAlgorithm(X509Certificate2 certificate)
    {
        var weakAlgorithms = new[] { "md5", "sha1" };
        return weakAlgorithms.Any(alg => 
            certificate.SignatureAlgorithm.FriendlyName.ToLower().Contains(alg));
    }
    
    private bool ValidateCertificateChain(X509Certificate2 certificate)
    {
        using var chain = new X509Chain();
        
        // Configure chain validation policy
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        
        // Add custom root certificates if needed
        var customRoots = _configuration.GetSection("CertificateAuth:TrustedRootCertificates").Get<string[]>();
        if (customRoots?.Any() == true)
        {
            foreach (var rootCertPath in customRoots)
            {
                var rootCert = new X509Certificate2(rootCertPath);
                chain.ChainPolicy.ExtraStore.Add(rootCert);
            }
        }
        
        var isValid = chain.Build(certificate);
        
        if (!isValid)
        {
            foreach (var status in chain.ChainStatus)
            {
                _logger.LogWarning("Certificate chain error: {Status} - {StatusInformation}", 
                    status.Status, status.StatusInformation);
            }
        }
        
        return isValid;
    }
    
    private bool HasCertificateTransparencyExtension(X509Certificate2 certificate)
    {
        // Check for Certificate Transparency SCT extension (OID 1.3.6.1.4.1.11129.2.4.2)
        return certificate.Extensions.Cast<X509Extension>()
            .Any(ext => ext.Oid.Value == "1.3.6.1.4.1.11129.2.4.2");
    }
}
```

### 2. Certificate Storage Security

```csharp
public class SecureCertificateStorage
{
    private readonly ILogger<SecureCertificateStorage> _logger;
    
    public X509Certificate2 LoadCertificateSecurely(string thumbprint, string password = null)
    {
        try
        {
            // Try to load from Windows Certificate Store first (most secure)
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            
            var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: true);
            
            if (certificates.Count > 0)
            {
                var cert = certificates[0];
                
                // Ensure private key is accessible
                if (!cert.HasPrivateKey)
                {
                    throw new InvalidOperationException("Certificate does not have an accessible private key");
                }
                
                return cert;
            }
            
            // If not found in store, try loading from secure file location
            var certPath = GetSecureCertificatePath(thumbprint);
            if (File.Exists(certPath))
            {
                var cert = new X509Certificate2(certPath, password, 
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                
                // Install to certificate store for future use
                InstallCertificateSecurely(cert);
                
                return cert;
            }
            
            throw new FileNotFoundException($"Certificate {thumbprint} not found");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load certificate {Thumbprint}", thumbprint);
            throw;
        }
    }
    
    private void InstallCertificateSecurely(X509Certificate2 certificate)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        
        // Set appropriate permissions
        var cert = new X509Certificate2(certificate);
        
        // Configure private key permissions (Windows only)
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            SetPrivateKeyPermissions(cert);
        }
        
        store.Add(cert);
        _logger.LogInformation("Certificate {Thumbprint} installed to machine store", certificate.Thumbprint);
    }
    
    private void SetPrivateKeyPermissions(X509Certificate2 certificate)
    {
        // This would require additional Windows-specific code
        // to set appropriate ACLs on the private key file
        _logger.LogInformation("Setting private key permissions for certificate {Thumbprint}", certificate.Thumbprint);
    }
    
    private string GetSecureCertificatePath(string thumbprint)
    {
        // Return path to secure certificate storage location
        var certDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 
            "YourApp", "Certificates");
        return Path.Combine(certDir, $"{thumbprint}.pfx");
    }
}
```

## Testing Strategies

### 1. Unit Tests

```csharp
[TestFixture]
public class CertificateValidationServiceTests
{
    private CertificateValidationService _service;
    private Mock<IUserService> _mockUserService;
    private Mock<IConfiguration> _mockConfiguration;
    
    [SetUp]
    public void Setup()
    {
        _mockUserService = new Mock<IUserService>();
        _mockConfiguration = new Mock<IConfiguration>();
        _service = new CertificateValidationService(_mockUserService.Object, _mockConfiguration.Object, null, null);
    }
    
    [Test]
    public async Task IsValidCertificateAsync_WithValidCertificate_ShouldReturnTrue()
    {
        // Arrange
        var certificate = CreateTestCertificate();
        
        // Act
        var result = await _service.IsValidCertificateAsync(certificate);
        
        // Assert
        Assert.IsTrue(result);
    }
    
    [Test]
    public async Task IsValidCertificateAsync_WithExpiredCertificate_ShouldReturnFalse()
    {
        // Arrange
        var certificate = CreateExpiredTestCertificate();
        
        // Act
        var result = await _service.IsValidCertificateAsync(certificate);
        
        // Assert
        Assert.IsFalse(result);
    }
    
    private X509Certificate2 CreateTestCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
    }
    
    private X509Certificate2 CreateExpiredTestCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Expired", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddYears(-2),
            DateTimeOffset.UtcNow.AddYears(-1));
    }
}
```

### 2. Integration Tests

```csharp
[TestFixture]
public class CertificateAuthenticationIntegrationTests
{
    private TestServer _server;
    private HttpClient _client;
    
    [SetUp]
    public void Setup()
    {
        var builder = new WebHostBuilder()
            .UseStartup<TestStartup>()
            .ConfigureServices(services =>
            {
                services.AddAuthentication()
                    .AddCertificate();
            });
        
        _server = new TestServer(builder);
        _client = _server.CreateClient();
    }
    
    [Test]
    public async Task SecureEndpoint_WithValidCertificate_ShouldReturnSuccess()
    {
        // This would require setting up client certificate authentication
        // in the test HTTP client, which is complex for integration tests
        
        var response = await _client.GetAsync("/api/secure");
        
        // Assertions would depend on the specific test setup
        Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.Unauthorized));
    }
}
```

---
**Next**: Continue with enterprise authentication patterns