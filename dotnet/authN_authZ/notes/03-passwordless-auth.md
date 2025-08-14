# Passwordless Authentication

## Overview
Passwordless authentication eliminates the need for traditional passwords by using alternative verification methods like magic links, biometrics, or hardware tokens. This approach improves security and user experience by removing password-related vulnerabilities.

## Passwordless Methods

### 1. Magic Links
- Email-based authentication links
- Temporary, time-limited access
- No password required
- Simple implementation

### 2. WebAuthn/FIDO2
- Hardware security keys
- Biometric authentication
- Platform authenticators (TouchID, FaceID)
- Industry standard (W3C/FIDO Alliance)

### 3. SMS/Email OTP
- One-time codes without passwords
- Phone or email verification
- Simpler than password + MFA

### 4. Passkeys
- Modern replacement for passwords
- Cross-device synchronization
- Apple/Google/Microsoft implementation
- Built on WebAuthn standard

### 5. Biometric Authentication
- Fingerprint recognition
- Face recognition
- Voice authentication
- Device-dependent

## .NET Implementation

### 1. Magic Link Authentication

#### Email Service Interface
```csharp
public interface IEmailService
{
    Task<bool> SendMagicLinkAsync(string email, string magicLink);
}

public class EmailService : IEmailService
{
    private readonly IConfiguration _config;
    
    public EmailService(IConfiguration config)
    {
        _config = config;
    }
    
    public async Task<bool> SendMagicLinkAsync(string email, string magicLink)
    {
        try
        {
            var smtpClient = new SmtpClient(_config["Email:SmtpServer"])
            {
                Port = int.Parse(_config["Email:Port"]),
                Credentials = new NetworkCredential(
                    _config["Email:Username"], 
                    _config["Email:Password"]),
                EnableSsl = true,
            };
            
            var mailMessage = new MailMessage
            {
                From = new MailAddress(_config["Email:FromAddress"]),
                Subject = "Your Magic Link",
                Body = $@"
                    <h2>Sign in to Your Account</h2>
                    <p>Click the link below to sign in:</p>
                    <a href='{magicLink}'>Sign In</a>
                    <p>This link expires in 15 minutes.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                ",
                IsBodyHtml = true
            };
            
            mailMessage.To.Add(email);
            
            await smtpClient.SendMailAsync(mailMessage);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
```

#### Magic Link Service
```csharp
public class MagicLinkService
{
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _config;
    private readonly IEmailService _emailService;
    
    public MagicLinkService(
        IMemoryCache cache, 
        IConfiguration config,
        IEmailService emailService)
    {
        _cache = cache;
        _config = config;
        _emailService = emailService;
    }
    
    public async Task<bool> SendMagicLinkAsync(string email)
    {
        var token = GenerateSecureToken();
        var magicLink = $"{_config["App:BaseUrl"]}/auth/magic-login?token={token}&email={Uri.EscapeDataString(email)}";
        
        // Store token with 15-minute expiration
        var cacheKey = $"magic_link_{token}";
        _cache.Set(cacheKey, email, TimeSpan.FromMinutes(15));
        
        return await _emailService.SendMagicLinkAsync(email, magicLink);
    }
    
    public bool ValidateToken(string token, string email)
    {
        var cacheKey = $"magic_link_{token}";
        
        if (_cache.TryGetValue(cacheKey, out string storedEmail))
        {
            if (storedEmail.Equals(email, StringComparison.OrdinalIgnoreCase))
            {
                _cache.Remove(cacheKey); // Single use token
                return true;
            }
        }
        
        return false;
    }
    
    private string GenerateSecureToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
```

#### Magic Link Controller
```csharp
[ApiController]
[Route("api/[controller]")]
public class MagicLinkController : ControllerBase
{
    private readonly MagicLinkService _magicLinkService;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IJwtTokenService _jwtTokenService;
    
    public MagicLinkController(
        MagicLinkService magicLinkService,
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IJwtTokenService jwtTokenService)
    {
        _magicLinkService = magicLinkService;
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtTokenService = jwtTokenService;
    }
    
    [HttpPost("send")]
    public async Task<IActionResult> SendMagicLink([FromBody] SendMagicLinkRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        // Check if user exists
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
            return BadRequest("User not found");
        
        var success = await _magicLinkService.SendMagicLinkAsync(request.Email);
        
        if (success)
            return Ok(new { Message = "Magic link sent to your email" });
        
        return StatusCode(500, "Failed to send magic link");
    }
    
    [HttpGet("verify")]
    public async Task<IActionResult> VerifyMagicLink([FromQuery] string token, [FromQuery] string email)
    {
        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            return BadRequest("Token and email are required");
        
        if (!_magicLinkService.ValidateToken(token, email))
            return Unauthorized("Invalid or expired magic link");
        
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
            return BadRequest("User not found");
        
        // Sign in the user
        await _signInManager.SignInAsync(user, isPersistent: false);
        
        // Generate JWT token for API access
        var jwtToken = _jwtTokenService.GenerateToken(user);
        
        return Ok(new
        {
            Message = "Successfully authenticated",
            Token = jwtToken,
            User = new { user.Id, user.Email }
        });
    }
}

public class SendMagicLinkRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
```

### 2. WebAuthn/FIDO2 Implementation

#### Installation
```bash
dotnet add package Fido2.NetFramework
```

#### WebAuthn Service
```csharp
public class WebAuthnService
{
    private readonly IFido2 _fido2;
    private readonly IMemoryCache _cache;
    
    public WebAuthnService(IFido2 fido2, IMemoryCache cache)
    {
        _fido2 = fido2;
        _cache = cache;
    }
    
    public CredentialCreateOptions BeginRegistration(string userId, string username, string displayName)
    {
        var user = new Fido2User
        {
            DisplayName = displayName,
            Name = username,
            Id = Encoding.UTF8.GetBytes(userId)
        };
        
        // Get existing credentials for this user
        var existingCredentials = GetUserCredentials(userId);
        
        var options = _fido2.RequestNewCredential(
            user,
            existingCredentials,
            AuthenticatorSelection.Default,
            AttestationConveyancePreference.Direct);
        
        // Store options for verification
        _cache.Set($"webauthn_create_{userId}", options, TimeSpan.FromMinutes(5));
        
        return options;
    }
    
    public async Task<CredentialMakeResult> CompleteRegistration(
        string userId,
        AuthenticatorAttestationRawResponse attestationResponse)
    {
        var cacheKey = $"webauthn_create_{userId}";
        
        if (!_cache.TryGetValue(cacheKey, out CredentialCreateOptions originalOptions))
            throw new InvalidOperationException("Registration session not found or expired");
        
        var result = await _fido2.MakeNewCredentialAsync(
            attestationResponse,
            originalOptions,
            async (args, cancellationToken) =>
            {
                // In production, validate against your user database
                return await Task.FromResult(true);
            });
        
        if (result.Status == "ok")
        {
            // Store credential in database
            await StoreCredentialAsync(userId, result.Result);
            _cache.Remove(cacheKey);
        }
        
        return result;
    }
    
    public AssertionOptions BeginAssertion(string userId = null)
    {
        var existingCredentials = userId != null 
            ? GetUserCredentials(userId) 
            : new List<PublicKeyCredentialDescriptor>();
        
        var options = _fido2.GetAssertionOptions(
            existingCredentials,
            UserVerificationRequirement.Preferred);
        
        // Store challenge for verification
        var sessionId = Guid.NewGuid().ToString();
        _cache.Set($"webauthn_assert_{sessionId}", options, TimeSpan.FromMinutes(5));
        
        // Return session ID with options
        options.Extensions = new AuthenticationExtensionsClientInputs
        {
            UserVerificationMethod = true
        };
        
        return options;
    }
    
    public async Task<AssertionVerificationResult> CompleteAssertion(
        string sessionId,
        AuthenticatorAssertionRawResponse assertionResponse)
    {
        var cacheKey = $"webauthn_assert_{sessionId}";
        
        if (!_cache.TryGetValue(cacheKey, out AssertionOptions originalOptions))
            throw new InvalidOperationException("Assertion session not found or expired");
        
        // Get stored credential
        var credential = await GetStoredCredentialAsync(assertionResponse.Id);
        if (credential == null)
            throw new InvalidOperationException("Credential not found");
        
        var result = await _fido2.MakeAssertionAsync(
            assertionResponse,
            originalOptions,
            credential.PublicKey,
            credential.SignatureCounter,
            async (args, cancellationToken) =>
            {
                // Verify user handle matches
                return await Task.FromResult(true);
            });
        
        if (result.Status == "ok")
        {
            // Update signature counter
            await UpdateCredentialCounterAsync(assertionResponse.Id, result.Counter);
            _cache.Remove(cacheKey);
        }
        
        return result;
    }
    
    private List<PublicKeyCredentialDescriptor> GetUserCredentials(string userId)
    {
        // In production, fetch from database
        return new List<PublicKeyCredentialDescriptor>();
    }
    
    private async Task StoreCredentialAsync(string userId, MakeNewCredentialResult credential)
    {
        // Store in database
        // Implementation depends on your data model
        await Task.CompletedTask;
    }
    
    private async Task<StoredCredential> GetStoredCredentialAsync(byte[] credentialId)
    {
        // Fetch from database
        return await Task.FromResult<StoredCredential>(null);
    }
    
    private async Task UpdateCredentialCounterAsync(byte[] credentialId, uint counter)
    {
        // Update counter in database
        await Task.CompletedTask;
    }
}

public class StoredCredential
{
    public byte[] CredentialId { get; set; }
    public byte[] PublicKey { get; set; }
    public uint SignatureCounter { get; set; }
    public string UserId { get; set; }
}
```

#### WebAuthn Controller
```csharp
[ApiController]
[Route("api/[controller]")]
public class WebAuthnController : ControllerBase
{
    private readonly WebAuthnService _webAuthnService;
    private readonly UserManager<IdentityUser> _userManager;
    
    public WebAuthnController(WebAuthnService webAuthnService, UserManager<IdentityUser> userManager)
    {
        _webAuthnService = webAuthnService;
        _userManager = userManager;
    }
    
    [HttpPost("register/begin")]
    [Authorize]
    public IActionResult BeginRegistration()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var username = User.FindFirst(ClaimTypes.Name)?.Value;
        var displayName = User.FindFirst(ClaimTypes.GivenName)?.Value ?? username;
        
        var options = _webAuthnService.BeginRegistration(userId, username, displayName);
        
        return Ok(options);
    }
    
    [HttpPost("register/complete")]
    [Authorize]
    public async Task<IActionResult> CompleteRegistration([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var result = await _webAuthnService.CompleteRegistration(userId, attestationResponse);
            
            if (result.Status == "ok")
                return Ok(new { Message = "WebAuthn credential registered successfully" });
            
            return BadRequest(new { Message = "Registration failed", Error = result.ErrorMessage });
        }
        catch (Exception ex)
        {
            return BadRequest(new { Message = "Registration failed", Error = ex.Message });
        }
    }
    
    [HttpPost("authenticate/begin")]
    public IActionResult BeginAuthentication([FromBody] BeginAuthRequest request)
    {
        var options = _webAuthnService.BeginAssertion(request?.UserId);
        
        // Store session ID in response
        var sessionId = Guid.NewGuid().ToString();
        HttpContext.Session.SetString("webauthn_session", sessionId);
        
        return Ok(new { Options = options, SessionId = sessionId });
    }
    
    [HttpPost("authenticate/complete")]
    public async Task<IActionResult> CompleteAuthentication(
        [FromBody] CompleteAuthRequest request)
    {
        try
        {
            var result = await _webAuthnService.CompleteAssertion(
                request.SessionId, 
                request.AssertionResponse);
            
            if (result.Status == "ok")
            {
                // Get user from credential
                var userId = GetUserIdFromCredential(request.AssertionResponse.Id);
                var user = await _userManager.FindByIdAsync(userId);
                
                if (user != null)
                {
                    // Sign in user
                    var claimsIdentity = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Id),
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim("auth_method", "webauthn")
                    }, "webauthn");
                    
                    var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);
                    
                    return Ok(new { Message = "Authentication successful", User = new { user.Id, user.UserName } });
                }
            }
            
            return Unauthorized(new { Message = "Authentication failed" });
        }
        catch (Exception ex)
        {
            return BadRequest(new { Message = "Authentication failed", Error = ex.Message });
        }
    }
    
    private string GetUserIdFromCredential(byte[] credentialId)
    {
        // Look up user ID from credential ID
        // Implementation depends on your data model
        return "user123";
    }
}

public class BeginAuthRequest
{
    public string UserId { get; set; }
}

public class CompleteAuthRequest
{
    public string SessionId { get; set; }
    public AuthenticatorAssertionRawResponse AssertionResponse { get; set; }
}
```

### 3. Passkeys Implementation

#### Passkey Service (Building on WebAuthn)
```csharp
public class PasskeyService
{
    private readonly WebAuthnService _webAuthnService;
    private readonly IPasskeyRepository _passkeyRepository;
    
    public PasskeyService(WebAuthnService webAuthnService, IPasskeyRepository passkeyRepository)
    {
        _webAuthnService = webAuthnService;
        _passkeyRepository = passkeyRepository;
    }
    
    public async Task<CredentialCreateOptions> CreatePasskeyOptions(string userId, string email)
    {
        var options = _webAuthnService.BeginRegistration(userId, email, email);
        
        // Passkey-specific options
        options.AuthenticatorSelection = new AuthenticatorSelection
        {
            RequireResidentKey = true,
            UserVerification = UserVerificationRequirement.Required,
            AuthenticatorAttachment = AuthenticatorAttachment.Platform
        };
        
        return options;
    }
    
    public async Task<bool> RegisterPasskey(
        string userId,
        AuthenticatorAttestationRawResponse attestationResponse)
    {
        var result = await _webAuthnService.CompleteRegistration(userId, attestationResponse);
        
        if (result.Status == "ok")
        {
            // Store passkey metadata
            await _passkeyRepository.StorePasskeyAsync(new Passkey
            {
                UserId = userId,
                CredentialId = result.Result.CredentialId,
                PublicKey = result.Result.PublicKey,
                SignatureCounter = result.Result.Counter,
                CreatedAt = DateTime.UtcNow,
                LastUsedAt = DateTime.UtcNow,
                DeviceType = "platform",
                IsActive = true
            });
            
            return true;
        }
        
        return false;
    }
    
    public async Task<AssertionOptions> CreateAuthenticationOptions()
    {
        // For passkeys, we don't need to specify user credentials
        var options = _webAuthnService.BeginAssertion();
        
        options.UserVerification = UserVerificationRequirement.Required;
        
        return options;
    }
}

public class Passkey
{
    public string Id { get; set; }
    public string UserId { get; set; }
    public byte[] CredentialId { get; set; }
    public byte[] PublicKey { get; set; }
    public uint SignatureCounter { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime LastUsedAt { get; set; }
    public string DeviceType { get; set; }
    public bool IsActive { get; set; }
    public string FriendlyName { get; set; }
}
```

### 4. Biometric Authentication Integration

#### Platform-Specific Implementation
```csharp
public interface IBiometricService
{
    Task<bool> IsBiometricAvailableAsync();
    Task<BiometricAuthResult> AuthenticateAsync(string reason);
}

public class BiometricAuthResult
{
    public bool IsSuccess { get; set; }
    public string ErrorMessage { get; set; }
    public BiometricType Type { get; set; }
}

public enum BiometricType
{
    Fingerprint,
    Face,
    Voice,
    None
}

// Platform-specific implementations would use:
// - Windows Hello API
// - TouchID/FaceID on iOS
// - Android Biometric API
// - WebAuthn biometric authenticators

public class WebBiometricService : IBiometricService
{
    // Uses WebAuthn with platform authenticators
    private readonly WebAuthnService _webAuthnService;
    
    public async Task<bool> IsBiometricAvailableAsync()
    {
        // Check if WebAuthn and platform authenticators are available
        return await Task.FromResult(true);
    }
    
    public async Task<BiometricAuthResult> AuthenticateAsync(string reason)
    {
        try
        {
            var options = _webAuthnService.BeginAssertion();
            options.UserVerification = UserVerificationRequirement.Required;
            
            // This would trigger biometric prompt in browser
            // Actual implementation requires JavaScript integration
            
            return new BiometricAuthResult
            {
                IsSuccess = true,
                Type = BiometricType.Fingerprint
            };
        }
        catch (Exception ex)
        {
            return new BiometricAuthResult
            {
                IsSuccess = false,
                ErrorMessage = ex.Message
            };
        }
    }
}
```

## Security Considerations

### 1. Magic Links
- **Time-limited**: Short expiration times (5-15 minutes)
- **Single-use**: Invalidate after use
- **HTTPS only**: Secure transmission
- **Rate limiting**: Prevent spam/abuse
- **User validation**: Verify email ownership

### 2. WebAuthn/FIDO2
- **Proper validation**: Verify attestation and assertions
- **Origin checking**: Validate request origin
- **Challenge verification**: Use cryptographically secure challenges
- **Counter verification**: Prevent replay attacks
- **Backup credentials**: Multiple authenticators per user

### 3. General Best Practices
```csharp
public class PasswordlessSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<PasswordlessSecurityMiddleware> _logger;
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Add security headers
        context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Add("X-Frame-Options", "DENY");
        context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
        
        // Log passwordless authentication events
        if (context.Request.Path.StartsWithSegments("/api/magiclink") ||
            context.Request.Path.StartsWithSegments("/api/webauthn"))
        {
            _logger.LogInformation("Passwordless auth request: {Path} from {IP}",
                context.Request.Path, context.Connection.RemoteIpAddress);
        }
        
        await _next(context);
    }
}
```

## Testing Strategies

### 1. Magic Link Testing
```csharp
[TestFixture]
public class MagicLinkTests
{
    private MagicLinkService _service;
    private Mock<IEmailService> _mockEmailService;
    
    [SetUp]
    public void Setup()
    {
        _mockEmailService = new Mock<IEmailService>();
        var cache = new MemoryCache(new MemoryCacheOptions());
        var config = new Mock<IConfiguration>();
        
        _service = new MagicLinkService(cache, config.Object, _mockEmailService.Object);
    }
    
    [Test]
    public async Task SendMagicLink_ShouldGenerateAndCacheToken()
    {
        _mockEmailService.Setup(x => x.SendMagicLinkAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(true);
        
        var result = await _service.SendMagicLinkAsync("test@example.com");
        
        Assert.IsTrue(result);
        _mockEmailService.Verify(x => x.SendMagicLinkAsync("test@example.com", It.IsAny<string>()), Times.Once);
    }
}
```

### 2. WebAuthn Testing
```csharp
[Test]
public async Task WebAuthn_RegistrationFlow_ShouldWork()
{
    // This requires specialized WebAuthn testing tools
    // Such as virtual authenticators in browser automation
    
    var options = _webAuthnService.BeginRegistration("user123", "test@example.com", "Test User");
    
    Assert.IsNotNull(options);
    Assert.IsNotNull(options.Challenge);
    Assert.AreEqual("test@example.com", options.User.Name);
}
```

## Frontend Integration

### 1. Magic Link JavaScript
```javascript
async function sendMagicLink(email) {
    try {
        const response = await fetch('/api/magiclink/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        
        if (response.ok) {
            showMessage('Magic link sent to your email!');
        } else {
            showError('Failed to send magic link');
        }
    } catch (error) {
        showError('Network error occurred');
    }
}
```

### 2. WebAuthn JavaScript
```javascript
async function registerWebAuthn() {
    try {
        // Get registration options
        const optionsResponse = await fetch('/api/webauthn/register/begin', {
            method: 'POST',
            credentials: 'include'
        });
        const options = await optionsResponse.json();
        
        // Convert base64 to ArrayBuffer
        options.challenge = base64ToArrayBuffer(options.challenge);
        options.user.id = base64ToArrayBuffer(options.user.id);
        
        // Create credential
        const credential = await navigator.credentials.create({
            publicKey: options
        });
        
        // Send to server
        const registrationResponse = await fetch('/api/webauthn/register/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: credential.id,
                rawId: arrayBufferToBase64(credential.rawId),
                response: {
                    attestationObject: arrayBufferToBase64(credential.response.attestationObject),
                    clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON)
                },
                type: credential.type
            })
        });
        
        if (registrationResponse.ok) {
            showMessage('WebAuthn credential registered successfully!');
        }
    } catch (error) {
        showError('WebAuthn registration failed: ' + error.message);
    }
}
```

---
**Next**: Continue to `04-jwt-tokens.md` to learn about JSON Web Token implementation