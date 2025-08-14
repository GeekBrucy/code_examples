# OAuth 2.0

## Overview
OAuth 2.0 is an authorization framework that enables applications to obtain limited access to user accounts. It works by delegating user authentication to the service that hosts the user account and authorizing third-party applications to access the user account.

## Core Concepts

### 1. Roles
- **Resource Owner**: The user who authorizes access to their account
- **Client**: The application requesting access to the user's account
- **Resource Server**: The server hosting the protected resources
- **Authorization Server**: The server issuing access tokens

### 2. Grant Types

#### Authorization Code Flow (Most Secure)
1. Client redirects user to authorization server
2. User authenticates and grants permission
3. Authorization server redirects back with authorization code
4. Client exchanges code for access token

#### Client Credentials Flow
1. Client authenticates directly with authorization server
2. Server returns access token
3. Used for server-to-server authentication

#### Implicit Flow (Deprecated)
1. Client gets access token directly from authorization endpoint
2. Less secure, not recommended

#### Resource Owner Password Credentials Flow
1. Client collects user credentials directly
2. Exchanges credentials for access token
3. Only for highly trusted clients

#### Device Authorization Flow
1. Device displays user code
2. User authorizes on separate device
3. Original device polls for token

### 3. PKCE (Proof Key for Code Exchange)
- Extension for public clients
- Prevents authorization code interception attacks
- Uses code challenge and code verifier

## .NET OAuth 2.0 Implementation

### 1. Authorization Server Implementation

#### Installation
```bash
dotnet add package OpenIddict.AspNetCore
dotnet add package OpenIddict.EntityFrameworkCore
```

#### Basic Authorization Server Setup
```csharp
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

public void ConfigureServices(IServiceCollection services)
{
    services.AddDbContext<ApplicationDbContext>(options =>
    {
        options.UseSqlServer(connectionString);
        options.UseOpenIddict();
    });
    
    services.AddOpenIddict()
        .AddCore(options =>
        {
            options.UseEntityFrameworkCore()
                   .UseDbContext<ApplicationDbContext>();
        })
        .AddServer(options =>
        {
            // Enable authorization code flow
            options.AllowAuthorizationCodeFlow()
                   .AllowClientCredentialsFlow()
                   .AllowRefreshTokenFlow();
            
            // Set endpoint URLs
            options.SetAuthorizationEndpointUris("/connect/authorize")
                   .SetTokenEndpointUris("/connect/token")
                   .SetUserinfoEndpointUris("/connect/userinfo");
            
            // Encryption and signing
            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate();
            
            // Register ASP.NET Core host
            options.UseAspNetCore()
                   .EnableAuthorizationEndpointPassthrough()
                   .EnableTokenEndpointPassthrough()
                   .EnableUserinfoEndpointPassthrough();
        })
        .AddValidation(options =>
        {
            options.UseLocalServer();
            options.UseAspNetCore();
        });
}
```

#### Authorization Controller
```csharp
[ApiController]
public class AuthorizationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        if (!result.Succeeded)
        {
            // Redirect to login page
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                });
        }

        // Retrieve the profile of the logged in user
        var user = await _userManager.GetUserAsync(result.Principal) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        // Retrieve the application details from the database
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Retrieve the permanent authorizations associated with the user and the calling client application
        var authorizations = await _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()).ToListAsync();

        switch (await _applicationManager.GetConsentTypeAsync(application))
        {
            case ConsentTypes.External when !authorizations.Any():
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }));

            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Any():
            case ConsentTypes.Explicit when authorizations.Any() && !request.HasPrompt(Prompts.Consent):
                break;

            case ConsentTypes.Explicit when request.HasPrompt(Prompts.Consent):
            case ConsentTypes.Explicit when !authorizations.Any():
                // Show consent page
                return View(new AuthorizeViewModel
                {
                    ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
                    Scope = request.Scope
                });

            default:
                throw new InvalidOperationException("The specified consent type is not valid.");
        }

        var principal = await _signInManager.CreateUserPrincipalAsync(user);

        // Set the list of scopes granted to the client application
        principal.SetScopes(request.GetScopes());
        principal.SetResources(await _scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

        // Automatically create a permanent authorization to avoid requiring explicit consent
        var authorization = authorizations.LastOrDefault();
        if (authorization is null)
        {
            authorization = await _authorizationManager.CreateAsync(
                principal: principal,
                subject: await _userManager.GetUserIdAsync(user),
                client: await _applicationManager.GetIdAsync(application),
                type: AuthorizationTypes.Permanent,
                scopes: principal.GetScopes());
        }

        principal.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            // Note: the client credentials are automatically validated by OpenIddict
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
            if (application == null)
            {
                throw new InvalidOperationException("The application cannot be found.");
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Use the client_id as the subject identifier
            identity.AddClaim(OpenIddictConstants.Claims.Subject,
                await _applicationManager.GetClientIdAsync(application),
                OpenIddictConstants.Destinations.AccessToken);

            identity.AddClaim(OpenIddictConstants.Claims.Name,
                await _applicationManager.GetDisplayNameAsync(application),
                OpenIddictConstants.Destinations.AccessToken);

            var principal = new ClaimsPrincipal(identity);

            principal.SetScopes(request.GetScopes());
            principal.SetResources(await _scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsAuthorizationCodeGrantType())
        {
            // Retrieve the claims principal stored in the authorization code
            var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            // Retrieve the user profile corresponding to the authorization code
            var user = await _userManager.FindByIdAsync(principal.GetClaim(OpenIddictConstants.Claims.Subject));
            if (user == null)
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }));
            }

            // Ensure the user is still allowed to sign in
            if (!await _signInManager.CanSignInAsync(user))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }));
            }

            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        switch (claim.Type)
        {
            case OpenIddictConstants.Claims.Name:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (principal.HasScope(OpenIddictConstants.Permissions.Scopes.Profile))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            case OpenIddictConstants.Claims.Email:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (principal.HasScope(OpenIddictConstants.Permissions.Scopes.Email))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            case OpenIddictConstants.Claims.Role:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (principal.HasScope(OpenIddictConstants.Permissions.Scopes.Roles))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield break;
        }
    }
}
```

### 2. OAuth Client Implementation

#### Client Registration
```csharp
public class ClientSeeder
{
    public static async Task SeedAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        
        // Web application client
        if (await applicationManager.FindByClientIdAsync("web-client") == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "web-client",
                ClientSecret = "web-client-secret",
                DisplayName = "Web Application",
                RedirectUris = { new Uri("https://localhost:5001/signin-oidc") },
                PostLogoutRedirectUris = { new Uri("https://localhost:5001/signout-callback-oidc") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles
                }
            });
        }
        
        // API client
        if (await applicationManager.FindByClientIdAsync("api-client") == null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "api-client",
                ClientSecret = "api-client-secret",
                DisplayName = "API Client",
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
                }
            });
        }
    }
}
```

#### OAuth Client Service
```csharp
public interface IOAuthClientService
{
    Task<string> GetAuthorizationUrlAsync(string clientId, string redirectUri, string state, string[] scopes);
    Task<TokenResponse> ExchangeCodeForTokenAsync(string clientId, string clientSecret, string code, string redirectUri);
    Task<TokenResponse> RefreshTokenAsync(string clientId, string clientSecret, string refreshToken);
    Task<UserInfoResponse> GetUserInfoAsync(string accessToken);
}

public class OAuthClientService : IOAuthClientService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    
    public OAuthClientService(HttpClient httpClient, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _configuration = configuration;
    }
    
    public async Task<string> GetAuthorizationUrlAsync(string clientId, string redirectUri, string state, string[] scopes)
    {
        var authorizationEndpoint = _configuration["OAuth:AuthorizationEndpoint"];
        
        var parameters = new Dictionary<string, string>
        {
            {"response_type", "code"},
            {"client_id", clientId},
            {"redirect_uri", redirectUri},
            {"scope", string.Join(" ", scopes)},
            {"state", state}
        };
        
        var queryString = string.Join("&", parameters.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));
        
        return $"{authorizationEndpoint}?{queryString}";
    }
    
    public async Task<TokenResponse> ExchangeCodeForTokenAsync(string clientId, string clientSecret, string code, string redirectUri)
    {
        var tokenEndpoint = _configuration["OAuth:TokenEndpoint"];
        
        var parameters = new Dictionary<string, string>
        {
            {"grant_type", "authorization_code"},
            {"client_id", clientId},
            {"client_secret", clientSecret},
            {"code", code},
            {"redirect_uri", redirectUri}
        };
        
        var requestBody = new FormUrlEncodedContent(parameters);
        var response = await _httpClient.PostAsync(tokenEndpoint, requestBody);
        
        if (response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<TokenResponse>(json);
        }
        
        throw new Exception($"Token exchange failed: {response.StatusCode}");
    }
    
    public async Task<TokenResponse> RefreshTokenAsync(string clientId, string clientSecret, string refreshToken)
    {
        var tokenEndpoint = _configuration["OAuth:TokenEndpoint"];
        
        var parameters = new Dictionary<string, string>
        {
            {"grant_type", "refresh_token"},
            {"client_id", clientId},
            {"client_secret", clientSecret},
            {"refresh_token", refreshToken}
        };
        
        var requestBody = new FormUrlEncodedContent(parameters);
        var response = await _httpClient.PostAsync(tokenEndpoint, requestBody);
        
        if (response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<TokenResponse>(json);
        }
        
        throw new Exception($"Token refresh failed: {response.StatusCode}");
    }
    
    public async Task<UserInfoResponse> GetUserInfoAsync(string accessToken)
    {
        var userInfoEndpoint = _configuration["OAuth:UserInfoEndpoint"];
        
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        
        var response = await _httpClient.GetAsync(userInfoEndpoint);
        
        if (response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<UserInfoResponse>(json);
        }
        
        throw new Exception($"UserInfo request failed: {response.StatusCode}");
    }
}

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }
    
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; }
    
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
    
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; }
    
    [JsonPropertyName("scope")]
    public string Scope { get; set; }
}

public class UserInfoResponse
{
    [JsonPropertyName("sub")]
    public string Sub { get; set; }
    
    [JsonPropertyName("name")]
    public string Name { get; set; }
    
    [JsonPropertyName("email")]
    public string Email { get; set; }
    
    [JsonPropertyName("email_verified")]
    public bool EmailVerified { get; set; }
}
```

### 3. PKCE Implementation

```csharp
public class PKCEService
{
    public PKCEChallenge GenerateChallenge()
    {
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        
        return new PKCEChallenge
        {
            CodeVerifier = codeVerifier,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = "S256"
        };
    }
    
    private string GenerateCodeVerifier()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
    
    private string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

public class PKCEChallenge
{
    public string CodeVerifier { get; set; }
    public string CodeChallenge { get; set; }
    public string CodeChallengeMethod { get; set; }
}
```

### 4. Resource Server Implementation

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.Authority = "https://your-auth-server.com";
            options.Audience = "your-api";
            options.RequireHttpsMetadata = true;
            
            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = async context =>
                {
                    // Additional token validation
                    var accessToken = context.SecurityToken as JwtSecurityToken;
                    var scopes = accessToken?.Claims
                        .Where(c => c.Type == "scope")
                        .SelectMany(c => c.Value.Split(' '))
                        .ToArray() ?? Array.Empty<string>();
                    
                    // Add scopes as claims
                    var identity = context.Principal.Identity as ClaimsIdentity;
                    foreach (var scope in scopes)
                    {
                        identity?.AddClaim(new Claim("scope", scope));
                    }
                }
            };
        });
    
    services.AddAuthorization(options =>
    {
        options.AddPolicy("RequireReadScope", policy =>
            policy.RequireClaim("scope", "read"));
            
        options.AddPolicy("RequireWriteScope", policy =>
            policy.RequireClaim("scope", "write"));
    });
}

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ResourceController : ControllerBase
{
    [HttpGet]
    [Authorize(Policy = "RequireReadScope")]
    public IActionResult GetResource()
    {
        var scopes = User.FindAll("scope").Select(c => c.Value);
        return Ok(new { Message = "Protected resource", Scopes = scopes });
    }
    
    [HttpPost]
    [Authorize(Policy = "RequireWriteScope")]
    public IActionResult CreateResource([FromBody] ResourceModel model)
    {
        return Ok(new { Message = "Resource created", Data = model });
    }
}
```

## Security Best Practices

### 1. Authorization Server Security
- **Use HTTPS**: Always encrypt OAuth communications
- **Validate redirect URIs**: Prevent open redirect attacks
- **Short-lived access tokens**: Limit token lifetime (15-30 minutes)
- **Secure client secrets**: Use strong, unique secrets
- **Rate limiting**: Prevent brute force attacks

### 2. Client Security
- **PKCE for public clients**: Always use PKCE for mobile/SPA apps
- **State parameter**: Prevent CSRF attacks
- **Secure token storage**: Store tokens securely
- **Token refresh**: Implement proper token refresh logic
- **Logout handling**: Properly revoke tokens on logout

### 3. Common Vulnerabilities
```csharp
public class OAuth2SecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<OAuth2SecurityMiddleware> _logger;
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Validate redirect URI
        if (context.Request.Path.StartsWithSegments("/connect/authorize"))
        {
            var redirectUri = context.Request.Query["redirect_uri"];
            if (!IsValidRedirectUri(redirectUri))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid redirect URI");
                return;
            }
        }
        
        // Add security headers
        context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Add("X-Frame-Options", "DENY");
        context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
        
        await _next(context);
    }
    
    private bool IsValidRedirectUri(string redirectUri)
    {
        // Implement redirect URI validation logic
        return Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri) && 
               uri.Scheme == "https";
    }
}
```

## Testing Strategies

### 1. Authorization Server Testing
```csharp
[TestFixture]
public class OAuth2AuthorizationTests
{
    private TestServer _server;
    private HttpClient _client;
    
    [SetUp]
    public void Setup()
    {
        var builder = new WebHostBuilder()
            .UseStartup<TestStartup>();
            
        _server = new TestServer(builder);
        _client = _server.CreateClient();
    }
    
    [Test]
    public async Task AuthorizeEndpoint_WithValidRequest_ShouldReturnAuthorizationCode()
    {
        // First, authenticate the user
        await AuthenticateUser();
        
        // Make authorization request
        var authUrl = "/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&scope=openid profile";
        
        var response = await _client.GetAsync(authUrl);
        
        // Should redirect with authorization code
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location.Query, Contains.Substring("code="));
    }
    
    private async Task AuthenticateUser()
    {
        // Implementation depends on your authentication setup
    }
}
```

### 2. Client Testing
```csharp
[Test]
public async Task ExchangeCodeForToken_WithValidCode_ShouldReturnToken()
{
    var oauthService = new OAuthClientService(_httpClient, _configuration);
    
    var tokenResponse = await oauthService.ExchangeCodeForTokenAsync(
        "test-client", 
        "test-secret", 
        "valid-auth-code", 
        "https://example.com/callback");
    
    Assert.IsNotNull(tokenResponse.AccessToken);
    Assert.That(tokenResponse.TokenType, Is.EqualTo("Bearer"));
}
```

---
**Next**: Continue to `07-openid-connect.md` to learn about OpenID Connect implementation