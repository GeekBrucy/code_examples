# Multi-Factor Authentication (MFA)

## Overview
Multi-Factor Authentication (MFA) adds additional security layers beyond passwords by requiring users to provide two or more verification factors. It significantly reduces the risk of account compromise even if passwords are stolen.

## Authentication Factors

### 1. Factor Types
- **Something you know** (Knowledge): Password, PIN, security questions
- **Something you have** (Possession): Phone, hardware token, smart card
- **Something you are** (Inherence): Fingerprint, face, voice, retina

### 2. MFA Methods

#### SMS/Text Message OTP
- One-time password sent via SMS
- Most common but least secure
- Vulnerable to SIM swapping and interception

#### Email OTP
- One-time code sent to registered email
- Better than SMS but still vulnerable
- Email account compromise risk

#### Time-based One-Time Password (TOTP)
- RFC 6238 standard
- Apps: Google Authenticator, Authy, Microsoft Authenticator
- Most secure software-based method
- Works offline

#### Hardware Tokens
- **FIDO2/WebAuthn**: Modern standard
- **YubiKey**: Popular hardware token
- **Smart Cards**: Enterprise environment
- Most secure option

#### Push Notifications
- Mobile app push notifications
- User approves/denies login attempt
- Better UX than entering codes

#### Biometric Authentication
- Fingerprint scanning
- Face recognition
- Voice recognition
- Device-dependent

## .NET Implementation

### 1. TOTP Implementation

#### Installation
```bash
dotnet add package OtpNet
dotnet add package QRCoder
```

#### TOTP Service
```csharp
using OtpNet;
using QRCoder;
using System.Drawing;

public class TotpService
{
    public class TotpSetupResult
    {
        public string Secret { get; set; }
        public string QrCodeImageUrl { get; set; }
        public string ManualEntryKey { get; set; }
    }
    
    public TotpSetupResult GenerateSetup(string userEmail, string issuer = "YourApp")
    {
        var key = KeyGeneration.GenerateRandomKey(20);
        var base32String = Base32Encoding.ToString(key);
        
        var setupInfo = $"otpauth://totp/{issuer}:{userEmail}?secret={base32String}&issuer={issuer}";
        
        return new TotpSetupResult
        {
            Secret = base32String,
            QrCodeImageUrl = GenerateQrCodeDataUri(setupInfo),
            ManualEntryKey = FormatSecretForManualEntry(base32String)
        };
    }
    
    public bool ValidateCode(string secret, string code, int windowSize = 1)
    {
        var keyBytes = Base32Encoding.ToBytes(secret);
        var totp = new Totp(keyBytes);
        
        return totp.VerifyTotp(code, out long timeStepMatched, 
            new VerificationWindow(windowSize, windowSize));
    }
    
    public string GetCurrentCode(string secret)
    {
        var keyBytes = Base32Encoding.ToBytes(secret);
        var totp = new Totp(keyBytes);
        return totp.ComputeTotp();
    }
    
    private string GenerateQrCodeDataUri(string totpSetupString)
    {
        var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(totpSetupString, QRCodeGenerator.ECCLevel.Q);
        var qrCode = new Base64QRCode(qrCodeData);
        return qrCode.GetGraphic(20);
    }
    
    private string FormatSecretForManualEntry(string secret)
    {
        return string.Join(" ", Enumerable.Range(0, secret.Length / 4)
            .Select(i => secret.Substring(i * 4, 4)));
    }
}
```

#### User MFA Model
```csharp
public class UserMfaSettings
{
    public int UserId { get; set; }
    public bool IsMfaEnabled { get; set; }
    public string TotpSecret { get; set; }
    public List<string> BackupCodes { get; set; } = new();
    public DateTime? LastUsedAt { get; set; }
    public bool IsSetupComplete { get; set; }
}

public class MfaDbContext : DbContext
{
    public DbSet<UserMfaSettings> UserMfaSettings { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserMfaSettings>(entity =>
        {
            entity.HasKey(e => e.UserId);
            entity.Property(e => e.TotpSecret).HasMaxLength(50);
            entity.Property(e => e.BackupCodes)
                .HasConversion(
                    v => string.Join(';', v),
                    v => v.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList()
                );
        });
    }
}
```

### 2. MFA Controller Implementation

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class MfaController : ControllerBase
{
    private readonly TotpService _totpService;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly MfaDbContext _context;
    
    public MfaController(
        TotpService totpService,
        UserManager<IdentityUser> userManager,
        MfaDbContext context)
    {
        _totpService = totpService;
        _userManager = userManager;
        _context = context;
    }
    
    [HttpPost("setup")]
    public async Task<IActionResult> SetupMfa()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        var user = await _userManager.FindByIdAsync(userId.ToString());
        
        // Check if MFA is already enabled
        var existingSettings = await _context.UserMfaSettings
            .FirstOrDefaultAsync(x => x.UserId == userId);
            
        if (existingSettings?.IsMfaEnabled == true)
            return BadRequest("MFA is already enabled");
        
        // Generate TOTP setup
        var setup = _totpService.GenerateSetup(user.Email);
        
        // Save secret (encrypted in production)
        var mfaSettings = existingSettings ?? new UserMfaSettings { UserId = userId };
        mfaSettings.TotpSecret = setup.Secret;
        mfaSettings.IsSetupComplete = false;
        
        if (existingSettings == null)
            _context.UserMfaSettings.Add(mfaSettings);
        
        await _context.SaveChangesAsync();
        
        return Ok(new
        {
            QrCode = setup.QrCodeImageUrl,
            ManualEntryKey = setup.ManualEntryKey,
            Message = "Scan QR code with your authenticator app"
        });
    }
    
    [HttpPost("verify-setup")]
    public async Task<IActionResult> VerifySetup([FromBody] VerifySetupRequest request)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        
        var mfaSettings = await _context.UserMfaSettings
            .FirstOrDefaultAsync(x => x.UserId == userId);
            
        if (mfaSettings == null)
            return BadRequest("MFA setup not initiated");
        
        // Verify the TOTP code
        if (!_totpService.ValidateCode(mfaSettings.TotpSecret, request.Code))
            return BadRequest("Invalid verification code");
        
        // Generate backup codes
        var backupCodes = GenerateBackupCodes(10);
        
        // Enable MFA
        mfaSettings.IsMfaEnabled = true;
        mfaSettings.IsSetupComplete = true;
        mfaSettings.BackupCodes = backupCodes;
        mfaSettings.LastUsedAt = DateTime.UtcNow;
        
        await _context.SaveChangesAsync();
        
        return Ok(new
        {
            Message = "MFA successfully enabled",
            BackupCodes = backupCodes
        });
    }
    
    [HttpPost("verify")]
    public async Task<IActionResult> VerifyMfa([FromBody] VerifyMfaRequest request)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        
        var mfaSettings = await _context.UserMfaSettings
            .FirstOrDefaultAsync(x => x.UserId == userId);
            
        if (mfaSettings?.IsMfaEnabled != true)
            return BadRequest("MFA is not enabled");
        
        bool isValid = false;
        
        // Check TOTP code
        if (!string.IsNullOrEmpty(request.TotpCode))
        {
            isValid = _totpService.ValidateCode(mfaSettings.TotpSecret, request.TotpCode);
        }
        // Check backup code
        else if (!string.IsNullOrEmpty(request.BackupCode))
        {
            isValid = mfaSettings.BackupCodes.Contains(request.BackupCode);
            if (isValid)
            {
                // Remove used backup code
                mfaSettings.BackupCodes.Remove(request.BackupCode);
                await _context.SaveChangesAsync();
            }
        }
        
        if (!isValid)
            return Unauthorized("Invalid MFA code");
        
        // Update last used
        mfaSettings.LastUsedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        
        // Add MFA claim
        var claimsIdentity = (ClaimsIdentity)User.Identity;
        claimsIdentity.AddClaim(new Claim("mfa_verified", "true"));
        claimsIdentity.AddClaim(new Claim("mfa_verified_at", DateTime.UtcNow.ToString("O")));
        
        return Ok(new { Message = "MFA verification successful" });
    }
    
    private List<string> GenerateBackupCodes(int count)
    {
        var codes = new List<string>();
        var random = new Random();
        
        for (int i = 0; i < count; i++)
        {
            codes.Add(random.Next(100000, 999999).ToString());
        }
        
        return codes;
    }
}

public class VerifySetupRequest
{
    public string Code { get; set; }
}

public class VerifyMfaRequest
{
    public string TotpCode { get; set; }
    public string BackupCode { get; set; }
}
```

### 3. SMS-Based MFA Implementation

```csharp
public interface ISmsService
{
    Task<bool> SendSmsAsync(string phoneNumber, string message);
}

public class TwilioSmsService : ISmsService
{
    private readonly IConfiguration _config;
    
    public TwilioSmsService(IConfiguration config)
    {
        _config = config;
    }
    
    public async Task<bool> SendSmsAsync(string phoneNumber, string message)
    {
        try
        {
            var accountSid = _config["Twilio:AccountSid"];
            var authToken = _config["Twilio:AuthToken"];
            var fromNumber = _config["Twilio:FromNumber"];
            
            TwilioClient.Init(accountSid, authToken);
            
            var messageResource = await MessageResource.CreateAsync(
                body: message,
                from: new PhoneNumber(fromNumber),
                to: new PhoneNumber(phoneNumber)
            );
            
            return messageResource.Status != MessageResource.StatusEnum.Failed;
        }
        catch (Exception)
        {
            return false;
        }
    }
}

public class SmsMfaService
{
    private readonly ISmsService _smsService;
    private readonly IMemoryCache _cache;
    
    public SmsMfaService(ISmsService smsService, IMemoryCache cache)
    {
        _smsService = smsService;
        _cache = cache;
    }
    
    public async Task<bool> SendCodeAsync(string phoneNumber, string userId)
    {
        var code = GenerateRandomCode();
        var cacheKey = $"sms_mfa_{userId}";
        
        // Store code with 5-minute expiration
        _cache.Set(cacheKey, code, TimeSpan.FromMinutes(5));
        
        var message = $"Your verification code is: {code}. Valid for 5 minutes.";
        return await _smsService.SendSmsAsync(phoneNumber, message);
    }
    
    public bool VerifyCode(string userId, string code)
    {
        var cacheKey = $"sms_mfa_{userId}";
        
        if (_cache.TryGetValue(cacheKey, out string storedCode))
        {
            if (storedCode == code)
            {
                _cache.Remove(cacheKey); // Remove used code
                return true;
            }
        }
        
        return false;
    }
    
    private string GenerateRandomCode()
    {
        var random = new Random();
        return random.Next(100000, 999999).ToString();
    }
}
```

### 4. MFA Middleware

```csharp
public class MfaRequirementMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IServiceScopeFactory _scopeFactory;
    
    public MfaRequirementMiddleware(RequestDelegate next, IServiceScopeFactory scopeFactory)
    {
        _next = next;
        _scopeFactory = scopeFactory;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Skip MFA check for certain paths
        var path = context.Request.Path.Value?.ToLower();
        var skipPaths = new[] { "/api/mfa", "/api/auth/login", "/api/auth/logout" };
        
        if (skipPaths.Any(p => path?.StartsWith(p) == true))
        {
            await _next(context);
            return;
        }
        
        // Check if user is authenticated
        if (!context.User.Identity?.IsAuthenticated == true)
        {
            await _next(context);
            return;
        }
        
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            await _next(context);
            return;
        }
        
        using var scope = _scopeFactory.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MfaDbContext>();
        
        var mfaSettings = await dbContext.UserMfaSettings
            .FirstOrDefaultAsync(x => x.UserId == int.Parse(userId));
        
        // If MFA is required but not verified
        if (mfaSettings?.IsMfaEnabled == true)
        {
            var mfaVerifiedClaim = context.User.FindFirst("mfa_verified");
            if (mfaVerifiedClaim?.Value != "true")
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("MFA verification required");
                return;
            }
            
            // Check if MFA verification is still valid (e.g., 30 minutes)
            var mfaVerifiedAtClaim = context.User.FindFirst("mfa_verified_at");
            if (DateTime.TryParse(mfaVerifiedAtClaim?.Value, out var verifiedAt))
            {
                if (DateTime.UtcNow - verifiedAt > TimeSpan.FromMinutes(30))
                {
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsync("MFA verification expired");
                    return;
                }
            }
        }
        
        await _next(context);
    }
}
```

### 5. WebAuthn/FIDO2 Implementation

```bash
dotnet add package Fido2.NetFramework
```

```csharp
public class WebAuthnService
{
    private readonly IFido2 _fido2;
    
    public WebAuthnService(IFido2 fido2)
    {
        _fido2 = fido2;
    }
    
    public CredentialCreateOptions BeginRegistration(string username, string displayName)
    {
        var user = new Fido2User
        {
            DisplayName = displayName,
            Name = username,
            Id = Encoding.UTF8.GetBytes(username)
        };
        
        var options = _fido2.RequestNewCredential(
            user, 
            new List<PublicKeyCredentialDescriptor>(),
            AuthenticatorSelection.Default,
            AttestationConveyancePreference.None);
            
        return options;
    }
    
    public async Task<bool> CompleteRegistration(
        string username,
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions originalOptions)
    {
        try
        {
            var success = await _fido2.MakeNewCredentialAsync(
                attestationResponse,
                originalOptions,
                (args, cancellationToken) => Task.FromResult(true));
                
            return success.Status == "ok";
        }
        catch
        {
            return false;
        }
    }
}
```

## Security Best Practices

### 1. Implementation Guidelines
- **Rate limiting**: Prevent brute force attacks on codes
- **Time windows**: Use appropriate time windows for TOTP
- **Backup codes**: Always provide backup recovery methods
- **Secure storage**: Encrypt secrets and sensitive data
- **Audit logging**: Log all MFA events

### 2. User Experience
- **Clear instructions**: Guide users through setup process
- **QR codes**: Make TOTP setup easy with QR codes
- **Multiple options**: Support multiple MFA methods
- **Recovery process**: Provide account recovery mechanisms
- **Remember device**: Optional device trust for convenience

### 3. Common Vulnerabilities
- **SIM swapping**: SMS-based MFA vulnerability
- **Phishing**: Users entering codes on fake sites
- **Replay attacks**: Reusing old codes
- **Social engineering**: Attackers convincing users to share codes
- **Backup code exposure**: Insecure storage of backup codes

## Testing Strategies

### 1. Unit Tests
```csharp
[TestFixture]
public class TotpServiceTests
{
    private TotpService _service;
    
    [SetUp]
    public void Setup()
    {
        _service = new TotpService();
    }
    
    [Test]
    public void GenerateSetup_ShouldReturnValidSetup()
    {
        var result = _service.GenerateSetup("test@example.com");
        
        Assert.IsNotNull(result.Secret);
        Assert.IsNotNull(result.QrCodeImageUrl);
        Assert.IsNotNull(result.ManualEntryKey);
    }
    
    [Test]
    public void ValidateCode_WithValidCode_ShouldReturnTrue()
    {
        var secret = "JBSWY3DPEHPK3PXP";
        var code = _service.GetCurrentCode(secret);
        
        var result = _service.ValidateCode(secret, code);
        
        Assert.IsTrue(result);
    }
}
```

### 2. Integration Tests
```csharp
[Test]
public async Task MfaSetup_CompleteFlow_ShouldWork()
{
    // Setup
    var response = await _client.PostAsync("/api/mfa/setup", null);
    response.EnsureSuccessStatusCode();
    
    var setupData = await response.Content.ReadFromJsonAsync<dynamic>();
    
    // Verify
    var verifyRequest = new { Code = "123456" }; // Use actual TOTP code in real test
    var verifyResponse = await _client.PostAsJsonAsync("/api/mfa/verify-setup", verifyRequest);
    
    Assert.That(verifyResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
}
```

## Monitoring and Analytics

### 1. Key Metrics
- MFA adoption rate
- Authentication success/failure rates
- Method usage distribution
- Support ticket volume related to MFA

### 2. Logging Examples
```csharp
public class MfaAuditService
{
    private readonly ILogger<MfaAuditService> _logger;
    
    public void LogMfaEvent(string userId, string eventType, string method, bool success)
    {
        _logger.LogInformation("MFA Event: {EventType} for User {UserId} using {Method}. Success: {Success}",
            eventType, userId, method, success);
    }
}
```

---
**Next**: Continue to `03-passwordless-auth.md` to learn about passwordless authentication methods