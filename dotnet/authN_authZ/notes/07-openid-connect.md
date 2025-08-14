# OpenID Connect (OIDC)

## Overview
OpenID Connect is an identity layer built on top of OAuth 2.0. While OAuth 2.0 provides authorization, OpenID Connect adds authentication capabilities, allowing clients to verify the identity of users and obtain basic profile information.

## Core Concepts

### 1. Key Differences from OAuth 2.0
- **OAuth 2.0**: Authorization framework (what you can access)
- **OpenID Connect**: Authentication protocol (who you are)
- **ID Token**: JWT containing user identity information
- **UserInfo Endpoint**: Additional user profile information

### 2. OIDC Components

#### ID Token
- JWT containing user identity claims
- Issued alongside access token
- Contains standard claims (sub, iss, aud, exp, iat)
- May contain additional profile information

#### UserInfo Endpoint
- OAuth 2.0 protected resource
- Returns claims about authenticated user
- Requires valid access token with openid scope

#### Discovery Document
- JSON document describing OIDC provider capabilities
- Found at `{issuer}/.well-known/openid_configuration`
- Contains endpoint URLs and supported features

### 3. OIDC Flows

#### Authorization Code Flow
1. Client redirects to authorization endpoint with `openid` scope
2. User authenticates and consents
3. Authorization server returns authorization code
4. Client exchanges code for access token + ID token

#### Implicit Flow (Deprecated)
1. Client receives ID token directly from authorization endpoint
2. Less secure, not recommended for production

#### Hybrid Flow
1. Combination of authorization code and implicit flows
2. Returns code + ID token from authorization endpoint
3. Client exchanges code for access token

## .NET OpenID Connect Implementation

### 1. OpenID Connect Provider (Building on OAuth 2.0)

#### Enhanced Authorization Server
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddOpenIddict()
        .AddCore(options =>
        {
            options.UseEntityFrameworkCore()
                   .UseDbContext<ApplicationDbContext>();
        })
        .AddServer(options =>
        {
            // Enable OpenID Connect flows
            options.AllowAuthorizationCodeFlow()
                   .AllowHybridFlow()
                   .AllowImplicitFlow()
                   .AllowRefreshTokenFlow();
            
            // Set endpoints
            options.SetAuthorizationEndpointUris("/connect/authorize")
                   .SetTokenEndpointUris("/connect/token")
                   .SetUserinfoEndpointUris("/connect/userinfo")
                   .SetLogoutEndpointUris("/connect/logout");
            
            // Enable OpenID Connect scopes
            options.RegisterScopes(
                OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Scopes.Email,
                OpenIddictConstants.Scopes.Profile,
                OpenIddictConstants.Scopes.Roles);
                
            // Configure signing and encryption
            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate();
            
            options.UseAspNetCore()
                   .EnableAuthorizationEndpointPassthrough()
                   .EnableTokenEndpointPassthrough()
                   .EnableUserinfoEndpointPassthrough()
                   .EnableLogoutEndpointPassthrough();
        });
}
```

#### UserInfo Endpoint Controller
```csharp
[ApiController]
public class UserInfoController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    
    public UserInfoController(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager;
    }
    
    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<IActionResult> Userinfo()
    {
        var user = await _userManager.FindByIdAsync(User.GetClaim(OpenIddictConstants.Claims.Subject));
        if (user == null)
        {
            return BadRequest(new
            {
                Error = OpenIddictConstants.Errors.InvalidGrant,
                ErrorDescription = "The user profile is no longer available."
            });
        }
        
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            // Always include the subject identifier
            [OpenIddictConstants.Claims.Subject] = await _userManager.GetUserIdAsync(user)
        };
        
        // Add profile claims if profile scope is granted
        if (User.HasScope(OpenIddictConstants.Scopes.Profile))
        {
            claims[OpenIddictConstants.Claims.Name] = await _userManager.GetUserNameAsync(user);
            claims[OpenIddictConstants.Claims.PreferredUsername] = await _userManager.GetUserNameAsync(user);
            
            // Add additional profile claims
            claims[OpenIddictConstants.Claims.GivenName] = user.FirstName;
            claims[OpenIddictConstants.Claims.FamilyName] = user.LastName;
            claims[OpenIddictConstants.Claims.UpdatedAt] = user.LastUpdated?.ToUnixTimeSeconds();
        }
        
        // Add email claims if email scope is granted
        if (User.HasScope(OpenIddictConstants.Scopes.Email))
        {
            claims[OpenIddictConstants.Claims.Email] = await _userManager.GetEmailAsync(user);
            claims[OpenIddictConstants.Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        }
        
        // Add role claims if roles scope is granted
        if (User.HasScope(OpenIddictConstants.Scopes.Roles))
        {
            claims[OpenIddictConstants.Claims.Role] = await _userManager.GetRolesAsync(user);
        }
        
        return Ok(claims);
    }
}
```

#### Discovery Document Endpoint
```csharp
[ApiController]
public class DiscoveryController : ControllerBase
{
    private readonly IConfiguration _configuration;
    
    public DiscoveryController(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    [HttpGet("~/.well-known/openid_configuration")]
    public IActionResult GetConfiguration()
    {
        var issuer = _configuration["OpenIdConnect:Issuer"];
        
        var configuration = new
        {
            issuer = issuer,
            authorization_endpoint = $"{issuer}/connect/authorize",
            token_endpoint = $"{issuer}/connect/token",
            userinfo_endpoint = $"{issuer}/connect/userinfo",
            jwks_uri = $"{issuer}/.well-known/jwks",
            end_session_endpoint = $"{issuer}/connect/logout",
            
            scopes_supported = new[]
            {
                "openid", "profile", "email", "roles"
            },
            
            response_types_supported = new[]
            {
                "code", "id_token", "token", "code id_token", "code token", "id_token token", "code id_token token"
            },
            
            response_modes_supported = new[]
            {
                "query", "fragment", "form_post"
            },
            
            grant_types_supported = new[]
            {
                "authorization_code", "implicit", "refresh_token", "client_credentials"
            },
            
            subject_types_supported = new[] { "public" },
            
            id_token_signing_alg_values_supported = new[] { "RS256" },
            
            code_challenge_methods_supported = new[] { "plain", "S256" },
            
            claims_supported = new[]
            {
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                "name", "given_name", "family_name", "preferred_username",
                "email", "email_verified", "role"
            }
        };
        
        return Ok(configuration);
    }
}
```

### 2. OpenID Connect Client Implementation

#### Client Configuration
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = "https://your-oidc-provider.com";
        options.ClientId = "your-client-id";
        options.ClientSecret = "your-client-secret";
        options.ResponseType = OpenIdConnectResponseType.Code;
        
        // Scopes
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("roles");
        
        // Token validation
        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = true;
        
        // PKCE
        options.UsePkce = true;
        
        // Custom claim mappings
        options.ClaimActions.MapJsonKey("role", "role");
        options.ClaimActions.MapJsonKey("email_verified", "email_verified");
        
        // Events
        options.Events = new OpenIdConnectEvents
        {
            OnAuthorizationCodeReceived = async context =>
            {
                // Custom logic when authorization code is received
                Console.WriteLine($"Authorization code received: {context.ProtocolMessage.Code}");
            },
            
            OnTokenValidated = async context =>
            {
                // Custom logic when ID token is validated
                var identity = context.Principal.Identity as ClaimsIdentity;
                
                // Add custom claims
                var userId = context.Principal.FindFirst("sub")?.Value;
                if (!string.IsNullOrEmpty(userId))
                {
                    // Fetch additional user data from your database
                    var customClaims = await GetCustomUserClaimsAsync(userId);
                    foreach (var claim in customClaims)
                    {
                        identity?.AddClaim(claim);
                    }
                }
            },
            
            OnUserInformationReceived = async context =>
            {
                // Custom logic when UserInfo is received
                Console.WriteLine($"UserInfo received: {context.User}");
            },
            
            OnRemoteFailure = async context =>
            {
                // Handle authentication failures
                Console.WriteLine($"Authentication failed: {context.Failure.Message}");
                context.Response.Redirect("/error");
                context.HandleResponse();
            }
        };
    });
}
```

#### OIDC Client Service
```csharp
public interface IOidcClientService
{
    Task<string> GetAuthorizationUrlAsync(OidcAuthRequest request);
    Task<OidcTokenResponse> ExchangeCodeForTokensAsync(string code, string state);
    Task<OidcUserInfo> GetUserInfoAsync(string accessToken);
    Task<OidcTokenResponse> RefreshTokenAsync(string refreshToken);
    Task LogoutAsync(string idToken);
}

public class OidcClientService : IOidcClientService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly IMemoryCache _cache;
    
    public OidcClientService(HttpClient httpClient, IConfiguration configuration, IMemoryCache cache)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _cache = cache;
    }
    
    public async Task<string> GetAuthorizationUrlAsync(OidcAuthRequest request)
    {
        var config = await GetDiscoveryDocumentAsync();
        
        var parameters = new Dictionary<string, string>
        {
            {"response_type", "code"},
            {"client_id", _configuration["OIDC:ClientId"]},
            {"redirect_uri", request.RedirectUri},
            {"scope", string.Join(" ", request.Scopes)},
            {"state", request.State},
            {"nonce", request.Nonce}
        };
        
        // Add PKCE parameters
        if (!string.IsNullOrEmpty(request.CodeChallenge))
        {
            parameters["code_challenge"] = request.CodeChallenge;
            parameters["code_challenge_method"] = "S256";
        }
        
        var queryString = string.Join("&", parameters.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));
        
        return $"{config.AuthorizationEndpoint}?{queryString}";
    }
    
    public async Task<OidcTokenResponse> ExchangeCodeForTokensAsync(string code, string state)
    {
        var config = await GetDiscoveryDocumentAsync();
        
        var parameters = new Dictionary<string, string>
        {
            {"grant_type", "authorization_code"},
            {"client_id", _configuration["OIDC:ClientId"]},
            {"client_secret", _configuration["OIDC:ClientSecret"]},
            {"code", code},
            {"redirect_uri", _configuration["OIDC:RedirectUri"]}
        };
        
        // Add PKCE code verifier if used
        var cacheKey = $"pkce_verifier_{state}";
        if (_cache.TryGetValue(cacheKey, out string codeVerifier))
        {
            parameters["code_verifier"] = codeVerifier;
            _cache.Remove(cacheKey);
        }
        
        var requestBody = new FormUrlEncodedContent(parameters);
        var response = await _httpClient.PostAsync(config.TokenEndpoint, requestBody);
        
        if (response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<OidcTokenResponse>(json);
            
            // Validate ID token
            await ValidateIdTokenAsync(tokenResponse.IdToken);
            
            return tokenResponse;
        }
        
        throw new Exception($"Token exchange failed: {response.StatusCode}");
    }
    
    public async Task<OidcUserInfo> GetUserInfoAsync(string accessToken)
    {
        var config = await GetDiscoveryDocumentAsync();
        
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        
        var response = await _httpClient.GetAsync(config.UserInfoEndpoint);
        
        if (response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<OidcUserInfo>(json);
        }
        
        throw new Exception($"UserInfo request failed: {response.StatusCode}");
    }
    
    public async Task<OidcTokenResponse> RefreshTokenAsync(string refreshToken)
    {
        var config = await GetDiscoveryDocumentAsync();
        
        var parameters = new Dictionary<string, string>
        {
            {"grant_type", "refresh_token"},
            {"client_id", _configuration["OIDC:ClientId"]},
            {"client_secret", _configuration["OIDC:ClientSecret"]},
            {"refresh_token", refreshToken}
        };
        
        var requestBody = new FormUrlEncodedContent(parameters);
        var response = await _httpClient.PostAsync(config.TokenEndpoint, requestBody);
        
        if (response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<OidcTokenResponse>(json);
        }
        
        throw new Exception($"Token refresh failed: {response.StatusCode}");
    }
    
    public async Task LogoutAsync(string idToken)
    {
        var config = await GetDiscoveryDocumentAsync();
        
        if (!string.IsNullOrEmpty(config.EndSessionEndpoint))
        {
            var logoutUrl = $"{config.EndSessionEndpoint}?id_token_hint={idToken}&post_logout_redirect_uri={Uri.EscapeDataString(_configuration["OIDC:PostLogoutRedirectUri"])}";
            
            // Redirect user to logout endpoint
            // Implementation depends on your application type
        }
    }
    
    private async Task<OidcDiscoveryDocument> GetDiscoveryDocumentAsync()
    {
        var cacheKey = "oidc_discovery_document";
        
        if (_cache.TryGetValue(cacheKey, out OidcDiscoveryDocument cachedDoc))
            return cachedDoc;
        
        var authority = _configuration["OIDC:Authority"];
        var discoveryUrl = $"{authority}/.well-known/openid_configuration";
        
        var response = await _httpClient.GetAsync(discoveryUrl);
        response.EnsureSuccessStatusCode();
        
        var json = await response.Content.ReadAsStringAsync();
        var document = JsonSerializer.Deserialize<OidcDiscoveryDocument>(json);
        
        // Cache for 1 hour
        _cache.Set(cacheKey, document, TimeSpan.FromHours(1));
        
        return document;
    }
    
    private async Task ValidateIdTokenAsync(string idToken)
    {
        // Implement ID token validation
        // - Verify signature using JWKS
        // - Validate issuer, audience, expiration
        // - Verify nonce if present
        
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadJwtToken(idToken);
        
        // Basic validation example
        if (jsonToken.Issuer != _configuration["OIDC:Authority"])
            throw new SecurityTokenInvalidIssuerException("Invalid issuer");
            
        if (!jsonToken.Audiences.Contains(_configuration["OIDC:ClientId"]))
            throw new SecurityTokenInvalidAudienceException("Invalid audience");
            
        if (jsonToken.ValidTo < DateTime.UtcNow)
            throw new SecurityTokenExpiredException("Token expired");
    }
}

// Data models
public class OidcAuthRequest
{
    public string RedirectUri { get; set; }
    public string[] Scopes { get; set; }
    public string State { get; set; }
    public string Nonce { get; set; }
    public string CodeChallenge { get; set; }
}

public class OidcTokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }
    
    [JsonPropertyName("id_token")]
    public string IdToken { get; set; }
    
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; }
    
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; }
    
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
    
    [JsonPropertyName("scope")]
    public string Scope { get; set; }
}

public class OidcUserInfo
{
    [JsonPropertyName("sub")]
    public string Sub { get; set; }
    
    [JsonPropertyName("name")]
    public string Name { get; set; }
    
    [JsonPropertyName("given_name")]
    public string GivenName { get; set; }
    
    [JsonPropertyName("family_name")]
    public string FamilyName { get; set; }
    
    [JsonPropertyName("preferred_username")]
    public string PreferredUsername { get; set; }
    
    [JsonPropertyName("email")]
    public string Email { get; set; }
    
    [JsonPropertyName("email_verified")]
    public bool EmailVerified { get; set; }
    
    [JsonPropertyName("role")]
    public string[] Roles { get; set; }
}

public class OidcDiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public string Issuer { get; set; }
    
    [JsonPropertyName("authorization_endpoint")]
    public string AuthorizationEndpoint { get; set; }
    
    [JsonPropertyName("token_endpoint")]
    public string TokenEndpoint { get; set; }
    
    [JsonPropertyName("userinfo_endpoint")]
    public string UserInfoEndpoint { get; set; }
    
    [JsonPropertyName("jwks_uri")]
    public string JwksUri { get; set; }
    
    [JsonPropertyName("end_session_endpoint")]
    public string EndSessionEndpoint { get; set; }
}
```

### 3. ID Token Processing

#### ID Token Validation
```csharp
public class IdTokenValidator
{
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;
    
    public async Task<ClaimsPrincipal> ValidateIdTokenAsync(string idToken)
    {
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadJwtToken(idToken);
        
        // Get JWKS from discovery document
        var jwks = await GetJwksAsync();
        
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _configuration["OIDC:Authority"],
            
            ValidateAudience = true,
            ValidAudience = _configuration["OIDC:ClientId"],
            
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5),
            
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = jwks.Keys,
            
            // Validate nonce if present
            NameClaimType = "name",
            RoleClaimType = "role"
        };
        
        var principal = handler.ValidateToken(idToken, validationParameters, out SecurityToken validatedToken);
        
        // Additional custom validation
        await ValidateCustomClaimsAsync(principal);
        
        return principal;
    }
    
    private async Task<JsonWebKeySet> GetJwksAsync()
    {
        var discoveryDoc = await GetDiscoveryDocumentAsync();
        var response = await _httpClient.GetAsync(discoveryDoc.JwksUri);
        var json = await response.Content.ReadAsStringAsync();
        
        return new JsonWebKeySet(json);
    }
    
    private async Task ValidateCustomClaimsAsync(ClaimsPrincipal principal)
    {
        // Custom validation logic
        var subject = principal.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(subject))
            throw new SecurityTokenValidationException("Missing subject claim");
        
        // Validate against your user database
        var userExists = await CheckUserExistsAsync(subject);
        if (!userExists)
            throw new SecurityTokenValidationException("User not found");
    }
}
```

### 4. Session Management

#### OIDC Session Controller
```csharp
[ApiController]
[Route("api/[controller]")]
public class SessionController : ControllerBase
{
    private readonly IOidcClientService _oidcClient;
    
    [HttpGet("login")]
    public async Task<IActionResult> Login([FromQuery] string returnUrl = "/")
    {
        var state = Guid.NewGuid().ToString();
        var nonce = Guid.NewGuid().ToString();
        
        // Store state and nonce for validation
        HttpContext.Session.SetString("oidc_state", state);
        HttpContext.Session.SetString("oidc_nonce", nonce);
        
        var authRequest = new OidcAuthRequest
        {
            RedirectUri = Url.Action("Callback", "Session", null, Request.Scheme),
            Scopes = new[] { "openid", "profile", "email", "roles" },
            State = state,
            Nonce = nonce
        };
        
        var authUrl = await _oidcClient.GetAuthorizationUrlAsync(authRequest);
        
        return Redirect(authUrl);
    }
    
    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string code, [FromQuery] string state, [FromQuery] string error)
    {
        if (!string.IsNullOrEmpty(error))
        {
            return BadRequest($"Authentication error: {error}");
        }
        
        // Validate state parameter
        var storedState = HttpContext.Session.GetString("oidc_state");
        if (state != storedState)
        {
            return BadRequest("Invalid state parameter");
        }
        
        try
        {
            var tokenResponse = await _oidcClient.ExchangeCodeForTokensAsync(code, state);
            
            // Create authentication cookie
            var claims = ExtractClaimsFromIdToken(tokenResponse.IdToken);
            var identity = new ClaimsIdentity(claims, "oidc");
            var principal = new ClaimsPrincipal(identity);
            
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
            
            // Store tokens for later use
            HttpContext.Session.SetString("access_token", tokenResponse.AccessToken);
            HttpContext.Session.SetString("refresh_token", tokenResponse.RefreshToken);
            
            return Redirect("/dashboard");
        }
        catch (Exception ex)
        {
            return BadRequest($"Token exchange failed: {ex.Message}");
        }
    }
    
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var idToken = HttpContext.Session.GetString("id_token");
        
        // Clear local session
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        HttpContext.Session.Clear();
        
        // Initiate logout at OIDC provider
        if (!string.IsNullOrEmpty(idToken))
        {
            await _oidcClient.LogoutAsync(idToken);
        }
        
        return Ok(new { Message = "Logged out successfully" });
    }
    
    private List<Claim> ExtractClaimsFromIdToken(string idToken)
    {
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadJwtToken(idToken);
        
        return jsonToken.Claims.ToList();
    }
}
```

## Security Best Practices

### 1. ID Token Security
- **Validate signatures**: Always verify ID token signatures
- **Check nonce**: Validate nonce to prevent replay attacks
- **Validate claims**: Verify issuer, audience, and expiration
- **Secure transmission**: Use HTTPS for all communications

### 2. Client Security
```csharp
public class OidcSecurityService
{
    public string GenerateSecureState()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
    
    public string GenerateNonce()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
    
    public bool ValidateState(string receivedState, string storedState)
    {
        return !string.IsNullOrEmpty(receivedState) && 
               !string.IsNullOrEmpty(storedState) && 
               receivedState == storedState;
    }
}
```

### 3. Token Storage
```csharp
public class SecureTokenStorage
{
    private readonly IDataProtector _protector;
    
    public SecureTokenStorage(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("OidcTokens");
    }
    
    public void StoreTokens(string userId, OidcTokenResponse tokens)
    {
        var tokenData = JsonSerializer.Serialize(tokens);
        var protectedData = _protector.Protect(tokenData);
        
        // Store in secure location (database, secure cookie, etc.)
        HttpContext.Session.SetString($"tokens_{userId}", protectedData);
    }
    
    public OidcTokenResponse RetrieveTokens(string userId)
    {
        var protectedData = HttpContext.Session.GetString($"tokens_{userId}");
        if (string.IsNullOrEmpty(protectedData))
            return null;
        
        var tokenData = _protector.Unprotect(protectedData);
        return JsonSerializer.Deserialize<OidcTokenResponse>(tokenData);
    }
}
```

## Testing Strategies

### 1. OIDC Provider Testing
```csharp
[TestFixture]
public class OidcProviderTests
{
    [Test]
    public async Task DiscoveryEndpoint_ShouldReturnValidConfiguration()
    {
        var response = await _client.GetAsync("/.well-known/openid_configuration");
        response.EnsureSuccessStatusCode();
        
        var json = await response.Content.ReadAsStringAsync();
        var config = JsonSerializer.Deserialize<OidcDiscoveryDocument>(json);
        
        Assert.IsNotNull(config.Issuer);
        Assert.IsNotNull(config.AuthorizationEndpoint);
        Assert.IsNotNull(config.TokenEndpoint);
        Assert.IsNotNull(config.UserInfoEndpoint);
    }
    
    [Test]
    public async Task UserInfoEndpoint_WithValidToken_ShouldReturnUserInfo()
    {
        var accessToken = await GetValidAccessTokenAsync();
        
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await _client.GetAsync("/connect/userinfo");
        
        response.EnsureSuccessStatusCode();
        var userInfo = await response.Content.ReadFromJsonAsync<OidcUserInfo>();
        
        Assert.IsNotNull(userInfo.Sub);
    }
}
```

### 2. OIDC Client Testing
```csharp
[Test]
public async Task AuthorizationCodeFlow_ShouldCompleteSuccessfully()
{
    var mockHandler = new Mock<HttpMessageHandler>();
    
    // Mock discovery document
    mockHandler.SetupRequest(HttpMethod.Get, "https://example.com/.well-known/openid_configuration")
        .ReturnsJsonResponse(new OidcDiscoveryDocument 
        { 
            TokenEndpoint = "https://example.com/token",
            UserInfoEndpoint = "https://example.com/userinfo"
        });
    
    // Mock token exchange
    mockHandler.SetupRequest(HttpMethod.Post, "https://example.com/token")
        .ReturnsJsonResponse(new OidcTokenResponse 
        { 
            AccessToken = "access_token",
            IdToken = CreateValidIdToken()
        });
    
    var client = new HttpClient(mockHandler.Object);
    var service = new OidcClientService(client, _configuration, _cache);
    
    var result = await service.ExchangeCodeForTokensAsync("test_code", "test_state");
    
    Assert.IsNotNull(result.AccessToken);
    Assert.IsNotNull(result.IdToken);
}
```

---
**Next**: Continue to `08-social-auth.md` to learn about social authentication implementation