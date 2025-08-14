# Social Authentication

## Overview
Social authentication allows users to sign in using their existing social media accounts (Google, Facebook, Twitter, etc.) instead of creating new credentials. This improves user experience by reducing friction and leverages trusted identity providers for authentication.

## Core Concepts

### 1. Benefits of Social Authentication
- **Reduced friction**: No need to create new accounts
- **Trust factor**: Users trust established providers
- **Rich profile data**: Access to user profile information
- **Maintenance reduction**: No password management for users
- **Higher conversion rates**: Faster signup process

### 2. Common Social Providers
- **Google**: Most widely used, reliable OAuth 2.0 implementation
- **Facebook**: Large user base, rich profile data
- **Microsoft**: Enterprise-friendly, Azure AD integration
- **GitHub**: Developer-focused, repository access
- **Twitter**: Real-time data, public profile focus
- **LinkedIn**: Professional networking, business data
- **Apple**: Privacy-focused, iOS ecosystem

### 3. Technical Foundation
- Built on **OAuth 2.0** and **OpenID Connect**
- Uses **Authorization Code Flow** with PKCE
- Returns **access tokens** and **ID tokens**
- Provides **user profile** information via APIs

## .NET Social Authentication Implementation

### 1. Google Authentication

#### Installation
```bash
dotnet add package Microsoft.AspNetCore.Authentication.Google
```

#### Configuration
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
    {
        options.ClientId = Configuration["Authentication:Google:ClientId"];
        options.ClientSecret = Configuration["Authentication:Google:ClientSecret"];
        
        // Additional scopes for profile information
        options.Scope.Add("profile");
        options.Scope.Add("email");
        
        // Save tokens for API access
        options.SaveTokens = true;
        
        // Claim mappings
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
        options.ClaimActions.MapJsonKey(ClaimTypes.GivenName, "given_name");
        options.ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");
        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
        options.ClaimActions.MapJsonKey("picture", "picture");
        options.ClaimActions.MapJsonKey("locale", "locale");
        
        // Events for custom processing
        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async context =>
            {
                // Get additional user information from Google API
                var request = new HttpRequestMessage(HttpMethod.Get, "https://www.googleapis.com/oauth2/v2/userinfo");
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                
                var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                response.EnsureSuccessStatusCode();
                
                var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                
                // Add custom claims
                context.Identity.AddClaim(new Claim("google_id", user.RootElement.GetString("id")));
                context.Identity.AddClaim(new Claim("verified_email", user.RootElement.GetString("verified_email")));
                
                // Store or update user in database
                await HandleSocialLoginAsync(context, "Google");
            },
            
            OnRemoteFailure = context =>
            {
                context.Response.Redirect("/login-error");
                context.HandleResponse();
                return Task.CompletedTask;
            }
        };
    });
}
```

### 2. Facebook Authentication

#### Installation
```bash
dotnet add package Microsoft.AspNetCore.Authentication.Facebook
```

#### Configuration
```csharp
services.AddAuthentication()
    .AddFacebook(options =>
    {
        options.AppId = Configuration["Authentication:Facebook:AppId"];
        options.AppSecret = Configuration["Authentication:Facebook:AppSecret"];
        
        // Request additional permissions
        options.Scope.Add("email");
        options.Scope.Add("public_profile");
        options.Scope.Add("user_birthday");
        options.Scope.Add("user_location");
        
        // Custom fields to retrieve
        options.Fields.Add("name");
        options.Fields.Add("email");
        options.Fields.Add("picture");
        options.Fields.Add("birthday");
        options.Fields.Add("location");
        
        options.SaveTokens = true;
        
        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async context =>
            {
                // Facebook returns user data directly
                var identity = context.Identity;
                
                // Map Facebook-specific claims
                var facebookId = context.User.GetProperty("id").GetString();
                identity.AddClaim(new Claim("facebook_id", facebookId));
                
                if (context.User.TryGetProperty("picture", out var pictureElement) &&
                    pictureElement.TryGetProperty("data", out var dataElement) &&
                    dataElement.TryGetProperty("url", out var urlElement))
                {
                    identity.AddClaim(new Claim("picture", urlElement.GetString()));
                }
                
                await HandleSocialLoginAsync(context, "Facebook");
            }
        };
    });
```

### 3. Microsoft Authentication

#### Configuration
```csharp
services.AddAuthentication()
    .AddMicrosoftAccount(options =>
    {
        options.ClientId = Configuration["Authentication:Microsoft:ClientId"];
        options.ClientSecret = Configuration["Authentication:Microsoft:ClientSecret"];
        
        // Microsoft Graph scopes
        options.Scope.Add("https://graph.microsoft.com/user.read");
        options.Scope.Add("https://graph.microsoft.com/mail.read");
        
        options.SaveTokens = true;
        
        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async context =>
            {
                // Access Microsoft Graph API
                var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0/me");
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                
                var response = await context.Backchannel.SendAsync(request);
                response.EnsureSuccessStatusCode();
                
                var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                
                // Add Microsoft-specific claims
                context.Identity.AddClaim(new Claim("microsoft_id", user.RootElement.GetString("id")));
                context.Identity.AddClaim(new Claim("job_title", user.RootElement.GetString("jobTitle") ?? ""));
                context.Identity.AddClaim(new Claim("office_location", user.RootElement.GetString("officeLocation") ?? ""));
                
                await HandleSocialLoginAsync(context, "Microsoft");
            }
        };
    });
```

### 4. GitHub Authentication

#### Installation
```bash
dotnet add package AspNet.Security.OAuth.GitHub
```

#### Configuration
```csharp
services.AddAuthentication()
    .AddGitHub(options =>
    {
        options.ClientId = Configuration["Authentication:GitHub:ClientId"];
        options.ClientSecret = Configuration["Authentication:GitHub:ClientSecret"];
        
        // GitHub scopes
        options.Scope.Add("user:email");
        options.Scope.Add("read:user");
        
        options.SaveTokens = true;
        
        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async context =>
            {
                // Get user's public repositories
                var reposRequest = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user/repos?type=public&sort=updated");
                reposRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github.v3+json"));
                reposRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                reposRequest.Headers.UserAgent.Add(new ProductInfoHeaderValue("YourApp", "1.0"));
                
                var reposResponse = await context.Backchannel.SendAsync(reposRequest);
                if (reposResponse.IsSuccessStatusCode)
                {
                    var repos = JsonDocument.Parse(await reposResponse.Content.ReadAsStringAsync());
                    var repoCount = repos.RootElement.GetArrayLength();
                    context.Identity.AddClaim(new Claim("github_repos_count", repoCount.ToString()));
                }
                
                // Add GitHub-specific claims
                var githubId = context.User.GetProperty("id").GetInt32();
                context.Identity.AddClaim(new Claim("github_id", githubId.ToString()));
                context.Identity.AddClaim(new Claim("github_login", context.User.GetProperty("login").GetString()));
                
                await HandleSocialLoginAsync(context, "GitHub");
            }
        };
    });
```

### 5. Multi-Provider Authentication Service

```csharp
public interface ISocialAuthService
{
    Task<SocialUserInfo> GetUserInfoAsync(string provider, string accessToken);
    Task<ApplicationUser> CreateOrUpdateUserAsync(SocialUserInfo socialUser, string provider);
    Task LinkSocialAccountAsync(string userId, string provider, string providerUserId);
    Task<List<SocialAccount>> GetUserSocialAccountsAsync(string userId);
    Task UnlinkSocialAccountAsync(string userId, string provider);
}

public class SocialAuthService : ISocialAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SocialDbContext _context;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SocialAuthService> _logger;
    
    public SocialAuthService(
        UserManager<ApplicationUser> userManager,
        SocialDbContext context,
        IHttpClientFactory httpClientFactory,
        ILogger<SocialAuthService> logger)
    {
        _userManager = userManager;
        _context = context;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }
    
    public async Task<SocialUserInfo> GetUserInfoAsync(string provider, string accessToken)
    {
        var httpClient = _httpClientFactory.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        
        return provider.ToLower() switch
        {
            "google" => await GetGoogleUserInfoAsync(httpClient),
            "facebook" => await GetFacebookUserInfoAsync(httpClient),
            "microsoft" => await GetMicrosoftUserInfoAsync(httpClient),
            "github" => await GetGitHubUserInfoAsync(httpClient),
            _ => throw new NotSupportedException($"Provider {provider} is not supported")
        };
    }
    
    private async Task<SocialUserInfo> GetGoogleUserInfoAsync(HttpClient httpClient)
    {
        var response = await httpClient.GetAsync("https://www.googleapis.com/oauth2/v2/userinfo");
        response.EnsureSuccessStatusCode();
        
        var json = await response.Content.ReadAsStringAsync();
        var user = JsonSerializer.Deserialize<JsonElement>(json);
        
        return new SocialUserInfo
        {
            Provider = "Google",
            ProviderId = user.GetProperty("id").GetString(),
            Email = user.GetProperty("email").GetString(),
            Name = user.GetProperty("name").GetString(),
            FirstName = user.TryGetProperty("given_name", out var firstName) ? firstName.GetString() : null,
            LastName = user.TryGetProperty("family_name", out var lastName) ? lastName.GetString() : null,
            Picture = user.TryGetProperty("picture", out var picture) ? picture.GetString() : null,
            IsEmailVerified = user.TryGetProperty("verified_email", out var verified) && verified.GetBoolean()
        };
    }
    
    private async Task<SocialUserInfo> GetFacebookUserInfoAsync(HttpClient httpClient)
    {
        var fields = "id,name,email,first_name,last_name,picture.type(large)";
        var response = await httpClient.GetAsync($"https://graph.facebook.com/me?fields={fields}");
        response.EnsureSuccessStatusCode();
        
        var json = await response.Content.ReadAsStringAsync();
        var user = JsonSerializer.Deserialize<JsonElement>(json);
        
        string pictureUrl = null;
        if (user.TryGetProperty("picture", out var pictureElement) &&
            pictureElement.TryGetProperty("data", out var dataElement) &&
            dataElement.TryGetProperty("url", out var urlElement))
        {
            pictureUrl = urlElement.GetString();
        }
        
        return new SocialUserInfo
        {
            Provider = "Facebook",
            ProviderId = user.GetProperty("id").GetString(),
            Email = user.TryGetProperty("email", out var email) ? email.GetString() : null,
            Name = user.GetProperty("name").GetString(),
            FirstName = user.TryGetProperty("first_name", out var firstName) ? firstName.GetString() : null,
            LastName = user.TryGetProperty("last_name", out var lastName) ? lastName.GetString() : null,
            Picture = pictureUrl,
            IsEmailVerified = true // Facebook emails are pre-verified
        };
    }
    
    public async Task<ApplicationUser> CreateOrUpdateUserAsync(SocialUserInfo socialUser, string provider)
    {
        // Try to find existing user by email
        var existingUser = await _userManager.FindByEmailAsync(socialUser.Email);
        
        if (existingUser != null)
        {
            // Update existing user with social information
            await UpdateUserFromSocialInfoAsync(existingUser, socialUser);
            await LinkSocialAccountAsync(existingUser.Id, provider, socialUser.ProviderId);
            return existingUser;
        }
        
        // Create new user
        var newUser = new ApplicationUser
        {
            UserName = socialUser.Email,
            Email = socialUser.Email,
            EmailConfirmed = socialUser.IsEmailVerified,
            FirstName = socialUser.FirstName,
            LastName = socialUser.LastName,
            Picture = socialUser.Picture,
            CreatedAt = DateTime.UtcNow
        };
        
        var result = await _userManager.CreateAsync(newUser);
        
        if (result.Succeeded)
        {
            await LinkSocialAccountAsync(newUser.Id, provider, socialUser.ProviderId);
            _logger.LogInformation("Created new user {UserId} from {Provider}", newUser.Id, provider);
            return newUser;
        }
        
        _logger.LogError("Failed to create user from {Provider}: {Errors}", 
            provider, string.Join(", ", result.Errors.Select(e => e.Description)));
        throw new InvalidOperationException("Failed to create user");
    }
    
    public async Task LinkSocialAccountAsync(string userId, string provider, string providerUserId)
    {
        var existingLink = await _context.SocialAccounts
            .FirstOrDefaultAsync(s => s.UserId == userId && s.Provider == provider);
        
        if (existingLink != null)
        {
            existingLink.ProviderUserId = providerUserId;
            existingLink.UpdatedAt = DateTime.UtcNow;
        }
        else
        {
            _context.SocialAccounts.Add(new SocialAccount
            {
                UserId = userId,
                Provider = provider,
                ProviderUserId = providerUserId,
                CreatedAt = DateTime.UtcNow
            });
        }
        
        await _context.SaveChangesAsync();
    }
    
    public async Task<List<SocialAccount>> GetUserSocialAccountsAsync(string userId)
    {
        return await _context.SocialAccounts
            .Where(s => s.UserId == userId)
            .ToListAsync();
    }
    
    public async Task UnlinkSocialAccountAsync(string userId, string provider)
    {
        var account = await _context.SocialAccounts
            .FirstOrDefaultAsync(s => s.UserId == userId && s.Provider == provider);
        
        if (account != null)
        {
            _context.SocialAccounts.Remove(account);
            await _context.SaveChangesAsync();
        }
    }
    
    private async Task UpdateUserFromSocialInfoAsync(ApplicationUser user, SocialUserInfo socialUser)
    {
        var updated = false;
        
        if (string.IsNullOrEmpty(user.FirstName) && !string.IsNullOrEmpty(socialUser.FirstName))
        {
            user.FirstName = socialUser.FirstName;
            updated = true;
        }
        
        if (string.IsNullOrEmpty(user.LastName) && !string.IsNullOrEmpty(socialUser.LastName))
        {
            user.LastName = socialUser.LastName;
            updated = true;
        }
        
        if (string.IsNullOrEmpty(user.Picture) && !string.IsNullOrEmpty(socialUser.Picture))
        {
            user.Picture = socialUser.Picture;
            updated = true;
        }
        
        if (updated)
        {
            await _userManager.UpdateAsync(user);
        }
    }
    
    // Additional provider-specific methods...
    private async Task<SocialUserInfo> GetMicrosoftUserInfoAsync(HttpClient httpClient) { /* Implementation */ return new SocialUserInfo(); }
    private async Task<SocialUserInfo> GetGitHubUserInfoAsync(HttpClient httpClient) { /* Implementation */ return new SocialUserInfo(); }
}

// Data models
public class SocialUserInfo
{
    public string Provider { get; set; }
    public string ProviderId { get; set; }
    public string Email { get; set; }
    public string Name { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Picture { get; set; }
    public bool IsEmailVerified { get; set; }
    public Dictionary<string, object> AdditionalData { get; set; } = new();
}

public class SocialAccount
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public string Provider { get; set; }
    public string ProviderUserId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    
    // Navigation property
    public virtual ApplicationUser User { get; set; }
}
```

### 6. Social Authentication Controller

```csharp
[ApiController]
[Route("api/[controller]")]
public class SocialAuthController : ControllerBase
{
    private readonly ISocialAuthService _socialAuthService;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IJwtTokenService _jwtTokenService;
    
    public SocialAuthController(
        ISocialAuthService socialAuthService,
        SignInManager<ApplicationUser> signInManager,
        IJwtTokenService jwtTokenService)
    {
        _socialAuthService = socialAuthService;
        _signInManager = signInManager;
        _jwtTokenService = jwtTokenService;
    }
    
    [HttpGet("login/{provider}")]
    public IActionResult Login(string provider, string returnUrl = null)
    {
        var redirectUrl = Url.Action(nameof(LoginCallback), new { provider, returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        
        return Challenge(properties, provider);
    }
    
    [HttpGet("callback/{provider}")]
    public async Task<IActionResult> LoginCallback(string provider, string returnUrl = null)
    {
        try
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return BadRequest("External login information not available");
            }
            
            // Try to sign in with external login provider
            var result = await _signInManager.ExternalLoginSignInAsync(
                info.LoginProvider, 
                info.ProviderKey, 
                isPersistent: false, 
                bypassTwoFactor: true);
            
            if (result.Succeeded)
            {
                // Existing user signed in
                var user = await _signInManager.UserManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                var token = _jwtTokenService.GenerateAccessToken(user);
                
                return Ok(new SocialLoginResponse
                {
                    Success = true,
                    AccessToken = token,
                    User = new UserInfo
                    {
                        Id = user.Id,
                        Email = user.Email,
                        Name = $"{user.FirstName} {user.LastName}".Trim(),
                        Picture = user.Picture
                    }
                });
            }
            
            // New user - create account
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(email))
            {
                return BadRequest("Email claim not available from provider");
            }
            
            var socialUserInfo = ExtractSocialUserInfo(info, provider);
            var newUser = await _socialAuthService.CreateOrUpdateUserAsync(socialUserInfo, provider);
            
            // Add external login to user
            await _signInManager.UserManager.AddLoginAsync(newUser, info);
            
            // Sign in the new user
            await _signInManager.SignInAsync(newUser, isPersistent: false);
            
            var newUserToken = _jwtTokenService.GenerateAccessToken(newUser);
            
            return Ok(new SocialLoginResponse
            {
                Success = true,
                AccessToken = newUserToken,
                IsNewUser = true,
                User = new UserInfo
                {
                    Id = newUser.Id,
                    Email = newUser.Email,
                    Name = $"{newUser.FirstName} {newUser.LastName}".Trim(),
                    Picture = newUser.Picture
                }
            });
        }
        catch (Exception ex)
        {
            return BadRequest($"Social login failed: {ex.Message}");
        }
    }
    
    [HttpPost("link/{provider}")]
    [Authorize]
    public async Task<IActionResult> LinkAccount(string provider)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var redirectUrl = Url.Action(nameof(LinkCallback), new { provider });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, userId);
        
        return Challenge(properties, provider);
    }
    
    [HttpGet("link-callback/{provider}")]
    [Authorize]
    public async Task<IActionResult> LinkCallback(string provider)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var info = await _signInManager.GetExternalLoginInfoAsync(userId);
        
        if (info == null)
        {
            return BadRequest("External login information not available");
        }
        
        var user = await _signInManager.UserManager.FindByIdAsync(userId);
        var result = await _signInManager.UserManager.AddLoginAsync(user, info);
        
        if (result.Succeeded)
        {
            await _socialAuthService.LinkSocialAccountAsync(userId, provider, info.ProviderKey);
            return Ok(new { Message = "Account linked successfully" });
        }
        
        return BadRequest("Failed to link account");
    }
    
    [HttpDelete("unlink/{provider}")]
    [Authorize]
    public async Task<IActionResult> UnlinkAccount(string provider)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var user = await _signInManager.UserManager.FindByIdAsync(userId);
        
        var result = await _signInManager.UserManager.RemoveLoginAsync(user, provider, userId);
        
        if (result.Succeeded)
        {
            await _socialAuthService.UnlinkSocialAccountAsync(userId, provider);
            return Ok(new { Message = "Account unlinked successfully" });
        }
        
        return BadRequest("Failed to unlink account");
    }
    
    [HttpGet("linked-accounts")]
    [Authorize]
    public async Task<IActionResult> GetLinkedAccounts()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var accounts = await _socialAuthService.GetUserSocialAccountsAsync(userId);
        
        return Ok(accounts.Select(a => new
        {
            a.Provider,
            a.CreatedAt,
            a.UpdatedAt
        }));
    }
    
    private SocialUserInfo ExtractSocialUserInfo(ExternalLoginInfo info, string provider)
    {
        return new SocialUserInfo
        {
            Provider = provider,
            ProviderId = info.ProviderKey,
            Email = info.Principal.FindFirstValue(ClaimTypes.Email),
            Name = info.Principal.FindFirstValue(ClaimTypes.Name),
            FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName),
            LastName = info.Principal.FindFirstValue(ClaimTypes.Surname),
            Picture = info.Principal.FindFirstValue("picture"),
            IsEmailVerified = bool.Parse(info.Principal.FindFirstValue("verified_email") ?? "false")
        };
    }
}

public class SocialLoginResponse
{
    public bool Success { get; set; }
    public string AccessToken { get; set; }
    public bool IsNewUser { get; set; }
    public UserInfo User { get; set; }
    public string ErrorMessage { get; set; }
}

public class UserInfo
{
    public string Id { get; set; }
    public string Email { get; set; }
    public string Name { get; set; }
    public string Picture { get; set; }
}
```

## Security Best Practices

### 1. Provider Configuration Security
```csharp
public class SocialAuthSecurityService
{
    public void ValidateProviderConfiguration(string provider, IConfiguration configuration)
    {
        var clientId = configuration[$"Authentication:{provider}:ClientId"];
        var clientSecret = configuration[$"Authentication:{provider}:ClientSecret"];
        
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            throw new InvalidOperationException($"Missing configuration for {provider}");
        }
        
        // Validate redirect URIs are HTTPS in production
        if (!Environment.IsDevelopment())
        {
            var redirectUri = configuration[$"Authentication:{provider}:RedirectUri"];
            if (!string.IsNullOrEmpty(redirectUri) && !redirectUri.StartsWith("https://"))
            {
                throw new InvalidOperationException($"Redirect URI for {provider} must use HTTPS in production");
            }
        }
    }
}
```

### 2. State Validation
```csharp
public class SocialAuthStateValidator
{
    public string GenerateState(string userId = null)
    {
        var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        
        // Optionally encode user information in state
        if (!string.IsNullOrEmpty(userId))
        {
            var stateData = new { State = state, UserId = userId, Timestamp = DateTimeOffset.UtcNow };
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(stateData)));
        }
        
        return state;
    }
    
    public bool ValidateState(string receivedState, string expectedState)
    {
        return !string.IsNullOrEmpty(receivedState) && 
               !string.IsNullOrEmpty(expectedState) && 
               receivedState == expectedState;
    }
}
```

### 3. Account Linking Security
```csharp
public class AccountLinkingValidator
{
    public async Task<bool> ValidateAccountLinkingAsync(string userId, string provider, string providerUserId)
    {
        // Check if this social account is already linked to another user
        var existingLink = await _context.SocialAccounts
            .FirstOrDefaultAsync(s => s.Provider == provider && s.ProviderUserId == providerUserId && s.UserId != userId);
        
        if (existingLink != null)
        {
            throw new InvalidOperationException("This social account is already linked to another user");
        }
        
        // Check if user already has this provider linked
        var userExistingLink = await _context.SocialAccounts
            .FirstOrDefaultAsync(s => s.UserId == userId && s.Provider == provider);
        
        if (userExistingLink != null)
        {
            throw new InvalidOperationException($"User already has a {provider} account linked");
        }
        
        return true;
    }
}
```

## Testing Strategies

### 1. Unit Tests
```csharp
[TestFixture]
public class SocialAuthServiceTests
{
    private Mock<UserManager<ApplicationUser>> _mockUserManager;
    private Mock<IHttpClientFactory> _mockHttpClientFactory;
    private SocialAuthService _service;
    
    [SetUp]
    public void Setup()
    {
        // Setup mocks
        _mockUserManager = CreateMockUserManager();
        _mockHttpClientFactory = new Mock<IHttpClientFactory>();
        
        _service = new SocialAuthService(_mockUserManager.Object, null, _mockHttpClientFactory.Object, null);
    }
    
    [Test]
    public async Task CreateOrUpdateUserAsync_WithNewUser_ShouldCreateUser()
    {
        // Arrange
        var socialUser = new SocialUserInfo
        {
            Provider = "Google",
            ProviderId = "123456",
            Email = "test@example.com",
            Name = "Test User",
            IsEmailVerified = true
        };
        
        _mockUserManager.Setup(x => x.FindByEmailAsync(socialUser.Email))
            .ReturnsAsync((ApplicationUser)null);
        
        _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);
        
        // Act
        var result = await _service.CreateOrUpdateUserAsync(socialUser, "Google");
        
        // Assert
        Assert.IsNotNull(result);
        Assert.AreEqual(socialUser.Email, result.Email);
        _mockUserManager.Verify(x => x.CreateAsync(It.IsAny<ApplicationUser>()), Times.Once);
    }
}
```

### 2. Integration Tests
```csharp
[Test]
public async Task SocialLogin_GoogleFlow_ShouldAuthenticate()
{
    // This would require setting up a test Google OAuth app
    // and using WebDriver for browser automation
    
    var loginUrl = "/api/socialauth/login/google";
    var response = await _client.GetAsync(loginUrl);
    
    // Response should be a redirect to Google
    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    Assert.That(response.Headers.Location.Host, Is.EqualTo("accounts.google.com"));
}
```

## Frontend Integration

### 1. React Example
```javascript
const SocialLogin = () => {
    const handleSocialLogin = (provider) => {
        window.location.href = `/api/socialauth/login/${provider}`;
    };
    
    return (
        <div className="social-login">
            <button onClick={() => handleSocialLogin('google')}>
                <img src="/google-icon.svg" alt="Google" />
                Sign in with Google
            </button>
            
            <button onClick={() => handleSocialLogin('facebook')}>
                <img src="/facebook-icon.svg" alt="Facebook" />
                Sign in with Facebook
            </button>
            
            <button onClick={() => handleSocialLogin('github')}>
                <img src="/github-icon.svg" alt="GitHub" />
                Sign in with GitHub
            </button>
        </div>
    );
};
```

---
**Next**: Continue to `09-saml.md` to learn about SAML implementation