# JWT (JSON Web Tokens)

## Overview
JSON Web Tokens (JWT) are a compact, URL-safe means of representing claims between two parties. JWTs are commonly used for authentication and information exchange in modern web applications, especially for stateless authentication in APIs and microservices.

## JWT Structure

### 1. Token Format
JWT consists of three parts separated by dots (.):
```
header.payload.signature
```

#### Header
Contains metadata about the token:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

#### Payload (Claims)
Contains the actual data:
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1516242622
}
```

#### Signature
Verifies the token integrity:
```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

### 2. Standard Claims

#### Registered Claims (RFC 7519)
- **iss** (issuer): Token issuer
- **sub** (subject): Token subject (usually user ID)
- **aud** (audience): Token audience
- **exp** (expiration): Expiration time
- **nbf** (not before): Token valid from time
- **iat** (issued at): Token issued time
- **jti** (JWT ID): Unique token identifier

#### Public Claims
- Registered in IANA registry
- Should be collision-resistant

#### Private Claims
- Custom claims for specific applications
- Should avoid conflicts

## .NET Implementation

### 1. JWT Service Implementation

#### Installation
```bash
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```

#### JWT Service
```csharp
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

public interface IJwtTokenService
{
    string GenerateAccessToken(IdentityUser user, IList<string> roles = null);
    string GenerateRefreshToken();
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    bool ValidateToken(string token);
}

public class JwtTokenService : IJwtTokenService
{
    private readonly IConfiguration _configuration;
    private readonly SymmetricSecurityKey _key;
    private readonly string _issuer;
    private readonly string _audience;
    
    public JwtTokenService(IConfiguration configuration)
    {
        _configuration = configuration;
        _issuer = _configuration["Jwt:Issuer"];
        _audience = _configuration["Jwt:Audience"];
        
        var secretKey = _configuration["Jwt:SecretKey"];
        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
    }
    
    public string GenerateAccessToken(IdentityUser user, IList<string> roles = null)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };
        
        // Add role claims
        if (roles != null)
        {
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
        }
        
        var credentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);
        var expiry = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:AccessTokenExpiryMinutes"]));
        
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            expires: expiry,
            signingCredentials: credentials
        );
        
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
    
    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _key,
            ValidateLifetime = false, // Don't validate expiry for refresh
            ValidIssuer = _issuer,
            ValidAudience = _audience,
            ClockSkew = TimeSpan.Zero
        };
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        
        if (securityToken is not JwtSecurityToken jwtSecurityToken || 
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }
        
        return principal;
    }
    
    public bool ValidateToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _key,
                ValidateIssuer = true,
                ValidIssuer = _issuer,
                ValidateAudience = true,
                ValidAudience = _audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            
            tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
```

### 2. Refresh Token Management

#### Refresh Token Model
```csharp
public class RefreshToken
{
    public int Id { get; set; }
    public string Token { get; set; }
    public string UserId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool IsRevoked { get; set; }
    public string CreatedByIp { get; set; }
    public string RevokedByIp { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string ReplacedByToken { get; set; }
    
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public bool IsActive => !IsRevoked && !IsExpired;
}

public class AuthDbContext : DbContext
{
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Token).IsRequired().HasMaxLength(500);
            entity.Property(e => e.UserId).IsRequired().HasMaxLength(450);
            entity.HasIndex(e => e.Token).IsUnique();
            entity.HasIndex(e => new { e.UserId, e.IsRevoked });
        });
    }
}
```

#### Refresh Token Service
```csharp
public interface IRefreshTokenService
{
    Task<RefreshToken> CreateRefreshTokenAsync(string userId, string ipAddress);
    Task<RefreshToken> GetRefreshTokenAsync(string token);
    Task<bool> RevokeTokenAsync(string token, string ipAddress);
    Task<bool> RevokeAllUserTokensAsync(string userId, string ipAddress);
    Task CleanupExpiredTokensAsync();
}

public class RefreshTokenService : IRefreshTokenService
{
    private readonly AuthDbContext _context;
    private readonly IConfiguration _configuration;
    
    public RefreshTokenService(AuthDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }
    
    public async Task<RefreshToken> CreateRefreshTokenAsync(string userId, string ipAddress)
    {
        var refreshToken = new RefreshToken
        {
            Token = GenerateRefreshToken(),
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddDays(int.Parse(_configuration["Jwt:RefreshTokenExpiryDays"])),
            CreatedAt = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };
        
        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();
        
        return refreshToken;
    }
    
    public async Task<RefreshToken> GetRefreshTokenAsync(string token)
    {
        return await _context.RefreshTokens
            .FirstOrDefaultAsync(x => x.Token == token);
    }
    
    public async Task<bool> RevokeTokenAsync(string token, string ipAddress)
    {
        var refreshToken = await GetRefreshTokenAsync(token);
        
        if (refreshToken == null || !refreshToken.IsActive)
            return false;
        
        refreshToken.IsRevoked = true;
        refreshToken.RevokedAt = DateTime.UtcNow;
        refreshToken.RevokedByIp = ipAddress;
        
        await _context.SaveChangesAsync();
        return true;
    }
    
    public async Task<bool> RevokeAllUserTokensAsync(string userId, string ipAddress)
    {
        var tokens = await _context.RefreshTokens
            .Where(x => x.UserId == userId && !x.IsRevoked)
            .ToListAsync();
        
        foreach (var token in tokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;
        }
        
        await _context.SaveChangesAsync();
        return true;
    }
    
    public async Task CleanupExpiredTokensAsync()
    {
        var expiredTokens = await _context.RefreshTokens
            .Where(x => x.ExpiresAt <= DateTime.UtcNow)
            .ToListAsync();
        
        _context.RefreshTokens.RemoveRange(expiredTokens);
        await _context.SaveChangesAsync();
    }
    
    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}
```

### 3. JWT Authentication Controller

```csharp
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly ILogger<AuthController> _logger;
    
    public AuthController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IJwtTokenService jwtTokenService,
        IRefreshTokenService refreshTokenService,
        ILogger<AuthController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtTokenService = jwtTokenService;
        _refreshTokenService = refreshTokenService;
        _logger = logger;
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            _logger.LogWarning("Login attempt for non-existent user: {Email}", request.Email);
            return Unauthorized("Invalid credentials");
        }
        
        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        
        if (!result.Succeeded)
        {
            _logger.LogWarning("Failed login attempt for user: {UserId}", user.Id);
            
            if (result.IsLockedOut)
                return Unauthorized("Account is locked out");
            
            return Unauthorized("Invalid credentials");
        }
        
        var roles = await _userManager.GetRolesAsync(user);
        var accessToken = _jwtTokenService.GenerateAccessToken(user, roles);
        var refreshToken = await _refreshTokenService.CreateRefreshTokenAsync(user.Id, GetIpAddress());
        
        _logger.LogInformation("User {UserId} logged in successfully", user.Id);
        
        return Ok(new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token,
            ExpiresAt = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:AccessTokenExpiryMinutes"])),
            User = new UserInfo { Id = user.Id, Email = user.Email, UserName = user.UserName }
        });
    }
    
    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
            return BadRequest("Refresh token is required");
        
        var refreshToken = await _refreshTokenService.GetRefreshTokenAsync(request.RefreshToken);
        
        if (refreshToken == null || !refreshToken.IsActive)
            return Unauthorized("Invalid refresh token");
        
        var user = await _userManager.FindByIdAsync(refreshToken.UserId);
        if (user == null)
            return Unauthorized("User not found");
        
        // Revoke old refresh token
        await _refreshTokenService.RevokeTokenAsync(request.RefreshToken, GetIpAddress());
        
        // Generate new tokens
        var roles = await _userManager.GetRolesAsync(user);
        var newAccessToken = _jwtTokenService.GenerateAccessToken(user, roles);
        var newRefreshToken = await _refreshTokenService.CreateRefreshTokenAsync(user.Id, GetIpAddress());
        
        return Ok(new LoginResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken.Token,
            ExpiresAt = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:AccessTokenExpiryMinutes"])),
            User = new UserInfo { Id = user.Id, Email = user.Email, UserName = user.UserName }
        });
    }
    
    [HttpPost("revoke")]
    [Authorize]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest request)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (!string.IsNullOrEmpty(request.RefreshToken))
        {
            // Revoke specific token
            await _refreshTokenService.RevokeTokenAsync(request.RefreshToken, GetIpAddress());
        }
        else
        {
            // Revoke all user tokens
            await _refreshTokenService.RevokeAllUserTokensAsync(userId, GetIpAddress());
        }
        
        return Ok(new { Message = "Token(s) revoked successfully" });
    }
    
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        await _refreshTokenService.RevokeAllUserTokensAsync(userId, GetIpAddress());
        
        return Ok(new { Message = "Logged out successfully" });
    }
    
    private string GetIpAddress()
    {
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}

public class LoginRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    
    [Required]
    public string Password { get; set; }
}

public class RefreshTokenRequest
{
    [Required]
    public string RefreshToken { get; set; }
}

public class RevokeTokenRequest
{
    public string RefreshToken { get; set; }
}

public class LoginResponse
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public DateTime ExpiresAt { get; set; }
    public UserInfo User { get; set; }
}

public class UserInfo
{
    public string Id { get; set; }
    public string Email { get; set; }
    public string UserName { get; set; }
}
```

### 4. JWT Middleware Configuration

#### Startup Configuration
```csharp
public void ConfigureServices(IServiceCollection services)
{
    // JWT Configuration
    services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = Configuration["Jwt:Issuer"],
            ValidAudience = Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:SecretKey"])),
            ClockSkew = TimeSpan.Zero
        };
        
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                {
                    context.Response.Headers.Add("Token-Expired", "true");
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                // Additional token validation logic
                var jti = context.Principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
                // Check if token is in blacklist, etc.
                return Task.CompletedTask;
            }
        };
    });
    
    services.AddScoped<IJwtTokenService, JwtTokenService>();
    services.AddScoped<IRefreshTokenService, RefreshTokenService>();
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseAuthentication();
    app.UseAuthorization();
}
```

### 5. Advanced JWT Features

#### Token Blacklisting
```csharp
public interface ITokenBlacklistService
{
    Task BlacklistTokenAsync(string jti, DateTime expiry);
    Task<bool> IsTokenBlacklistedAsync(string jti);
    Task CleanupExpiredTokensAsync();
}

public class TokenBlacklistService : ITokenBlacklistService
{
    private readonly IMemoryCache _cache;
    private readonly AuthDbContext _context;
    
    public async Task BlacklistTokenAsync(string jti, DateTime expiry)
    {
        // Store in cache for fast access
        _cache.Set($"blacklist_{jti}", true, expiry);
        
        // Store in database for persistence
        _context.BlacklistedTokens.Add(new BlacklistedToken
        {
            Jti = jti,
            ExpiresAt = expiry,
            BlacklistedAt = DateTime.UtcNow
        });
        
        await _context.SaveChangesAsync();
    }
    
    public async Task<bool> IsTokenBlacklistedAsync(string jti)
    {
        // Check cache first
        if (_cache.TryGetValue($"blacklist_{jti}", out _))
            return true;
        
        // Check database
        return await _context.BlacklistedTokens
            .AnyAsync(x => x.Jti == jti && x.ExpiresAt > DateTime.UtcNow);
    }
    
    public async Task CleanupExpiredTokensAsync()
    {
        var expiredTokens = await _context.BlacklistedTokens
            .Where(x => x.ExpiresAt <= DateTime.UtcNow)
            .ToListAsync();
        
        _context.BlacklistedTokens.RemoveRange(expiredTokens);
        await _context.SaveChangesAsync();
    }
}
```

#### Custom JWT Claims
```csharp
public class CustomClaimsService
{
    public async Task<List<Claim>> GetCustomClaimsAsync(IdentityUser user)
    {
        var claims = new List<Claim>();
        
        // Add custom business logic claims
        var permissions = await GetUserPermissionsAsync(user.Id);
        foreach (var permission in permissions)
        {
            claims.Add(new Claim("permission", permission));
        }
        
        // Add tenant information
        var tenantId = await GetUserTenantAsync(user.Id);
        if (!string.IsNullOrEmpty(tenantId))
        {
            claims.Add(new Claim("tenant_id", tenantId));
        }
        
        // Add subscription level
        var subscriptionLevel = await GetUserSubscriptionLevelAsync(user.Id);
        claims.Add(new Claim("subscription_level", subscriptionLevel));
        
        return claims;
    }
    
    private async Task<List<string>> GetUserPermissionsAsync(string userId)
    {
        // Implement permission lookup logic
        return await Task.FromResult(new List<string> { "read", "write" });
    }
    
    private async Task<string> GetUserTenantAsync(string userId)
    {
        // Implement tenant lookup logic
        return await Task.FromResult("tenant123");
    }
    
    private async Task<string> GetUserSubscriptionLevelAsync(string userId)
    {
        // Implement subscription lookup logic
        return await Task.FromResult("premium");
    }
}
```

## Security Best Practices

### 1. Token Security
- **Use HTTPS**: Always transmit tokens over secure connections
- **Short expiry**: Keep access token lifetime short (15-30 minutes)
- **Secure storage**: Store tokens securely on client side
- **Token rotation**: Implement refresh token rotation
- **Signature verification**: Always verify token signatures

### 2. Configuration Security
```json
{
  "Jwt": {
    "SecretKey": "your-super-secret-key-that-is-at-least-256-bits-long",
    "Issuer": "your-app-name",
    "Audience": "your-app-users",
    "AccessTokenExpiryMinutes": 15,
    "RefreshTokenExpiryDays": 7
  }
}
```

### 3. Common Vulnerabilities
- **Weak secrets**: Use strong, random secret keys
- **Algorithm confusion**: Specify allowed algorithms
- **Token leakage**: Prevent tokens in URLs or logs
- **Cross-site scripting**: Protect against XSS attacks
- **Replay attacks**: Use short lifetimes and nonces

## Testing Strategies

### 1. Unit Tests
```csharp
[TestFixture]
public class JwtTokenServiceTests
{
    private JwtTokenService _service;
    private IConfiguration _configuration;
    
    [SetUp]
    public void Setup()
    {
        var configData = new Dictionary<string, string>
        {
            {"Jwt:SecretKey", "your-test-secret-key-that-is-at-least-256-bits-long"},
            {"Jwt:Issuer", "TestIssuer"},
            {"Jwt:Audience", "TestAudience"},
            {"Jwt:AccessTokenExpiryMinutes", "15"}
        };
        
        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();
            
        _service = new JwtTokenService(_configuration);
    }
    
    [Test]
    public void GenerateAccessToken_ShouldReturnValidToken()
    {
        var user = new IdentityUser { Id = "123", UserName = "testuser", Email = "test@example.com" };
        
        var token = _service.GenerateAccessToken(user);
        
        Assert.IsNotNull(token);
        Assert.IsTrue(_service.ValidateToken(token));
    }
    
    [Test]
    public void ValidateToken_WithExpiredToken_ShouldReturnFalse()
    {
        // Test with manually created expired token
        // Implementation depends on your token creation logic
    }
}
```

### 2. Integration Tests
```csharp
[Test]
public async Task Login_WithValidCredentials_ShouldReturnJwtToken()
{
    var loginRequest = new { Email = "test@example.com", Password = "TestPassword123!" };
    
    var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
    response.EnsureSuccessStatusCode();
    
    var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
    
    Assert.IsNotNull(result.AccessToken);
    Assert.IsNotNull(result.RefreshToken);
}
```

## Performance Considerations

### 1. Token Caching
```csharp
public class CachedTokenValidationService
{
    private readonly IMemoryCache _cache;
    private readonly IJwtTokenService _jwtService;
    
    public bool ValidateTokenCached(string token)
    {
        var cacheKey = $"jwt_valid_{token.GetHashCode()}";
        
        if (_cache.TryGetValue(cacheKey, out bool isValid))
            return isValid;
        
        isValid = _jwtService.ValidateToken(token);
        
        // Cache for a short time
        _cache.Set(cacheKey, isValid, TimeSpan.FromMinutes(5));
        
        return isValid;
    }
}
```

### 2. Background Token Cleanup
```csharp
public class TokenCleanupService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<TokenCleanupService> _logger;
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var refreshTokenService = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
                var blacklistService = scope.ServiceProvider.GetRequiredService<ITokenBlacklistService>();
                
                await refreshTokenService.CleanupExpiredTokensAsync();
                await blacklistService.CleanupExpiredTokensAsync();
                
                _logger.LogInformation("Token cleanup completed");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token cleanup");
            }
            
            await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
        }
    }
}
```

---
**Next**: Continue to `06-oauth2.md` to learn about OAuth 2.0 implementation