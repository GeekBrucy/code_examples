# Enterprise Authentication Patterns

## Overview
Enterprise authentication encompasses the comprehensive authentication strategies used in large organizations to manage user identities across multiple systems, applications, and services. It combines various authentication methods, identity providers, and security policies to create a unified, secure, and scalable authentication architecture.

## Core Concepts

### 1. Enterprise Identity Architecture

#### Identity Provider (IdP) Hub
- Central identity authority for the organization
- Manages user identities, credentials, and attributes
- Provides authentication services to all applications
- Examples: Active Directory, Azure AD, Okta, Ping Identity

#### Service Provider (SP) Applications
- Business applications that consume identity services
- Rely on IdP for authentication and user attributes
- Implement federated authentication protocols
- Focus on business logic rather than identity management

#### Identity Federation
- Trust relationships between identity providers
- Enables cross-domain authentication
- Supports business partnerships and acquisitions
- Implements standards like SAML, OAuth 2.0, OpenID Connect

### 2. Enterprise Authentication Patterns

#### Single Sign-On (SSO)
- Users authenticate once to access multiple applications
- Reduces password fatigue and support costs
- Improves user experience and productivity
- Centralized session management

#### Identity Federation
- Enables authentication across organizational boundaries
- Supports B2B partnerships and collaborations
- Allows sharing of identity assertions
- Maintains security and privacy controls

#### Zero Trust Architecture
- "Never trust, always verify" security model
- Continuous authentication and authorization
- Context-aware access decisions
- Microsegmentation and least privilege

### 3. Enterprise Scale Considerations

#### High Availability
- Multiple IdP instances for redundancy
- Geographic distribution for performance
- Failover and disaster recovery procedures
- Load balancing and traffic management

#### Scalability
- Support for millions of users and applications
- Horizontal scaling capabilities
- Efficient caching and session management
- Database sharding and replication

#### Performance
- Sub-second authentication response times
- Optimized token validation and caching
- CDN integration for global performance
- Efficient protocol implementations

## .NET Enterprise Authentication Implementation

### 1. Multi-Protocol Authentication Service

```csharp
public interface IEnterpriseAuthenticationService
{
    Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request);
    Task<bool> ValidateTokenAsync(string token, string protocol);
    Task<UserContext> GetUserContextAsync(string userId);
    Task<List<string>> GetUserApplicationsAsync(string userId);
    Task LogoutUserFromAllApplicationsAsync(string userId);
}

public class EnterpriseAuthenticationService : IEnterpriseAuthenticationService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IUserService _userService;
    private readonly ISessionService _sessionService;
    private readonly ILogger<EnterpriseAuthenticationService> _logger;
    private readonly IMemoryCache _cache;
    
    private readonly Dictionary<string, IAuthenticationProtocol> _protocols;
    
    public EnterpriseAuthenticationService(
        IServiceProvider serviceProvider,
        IUserService userService,
        ISessionService sessionService,
        ILogger<EnterpriseAuthenticationService> logger,
        IMemoryCache cache)
    {
        _serviceProvider = serviceProvider;
        _userService = userService;
        _sessionService = sessionService;
        _logger = logger;
        _cache = cache;
        
        // Initialize supported protocols
        _protocols = new Dictionary<string, IAuthenticationProtocol>
        {
            ["saml2"] = serviceProvider.GetRequiredService<ISamlAuthenticationProtocol>(),
            ["oidc"] = serviceProvider.GetRequiredService<IOidcAuthenticationProtocol>(),
            ["oauth2"] = serviceProvider.GetRequiredService<IOAuth2AuthenticationProtocol>(),
            ["ws-federation"] = serviceProvider.GetRequiredService<IWsFederationProtocol>(),
            ["certificate"] = serviceProvider.GetRequiredService<ICertificateAuthenticationProtocol>(),
            ["kerberos"] = serviceProvider.GetRequiredService<IKerberosAuthenticationProtocol>()
        };
    }
    
    public async Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request)
    {
        try
        {
            _logger.LogInformation("Authentication attempt for user {Username} using protocol {Protocol}",
                request.Username, request.Protocol);
            
            // Validate request
            if (!ValidateAuthenticationRequest(request))
            {
                return AuthenticationResult.Failed("Invalid authentication request");
            }
            
            // Check if protocol is supported
            if (!_protocols.TryGetValue(request.Protocol.ToLower(), out var protocol))
            {
                return AuthenticationResult.Failed($"Unsupported protocol: {request.Protocol}");
            }
            
            // Pre-authentication checks
            var preAuthResult = await PerformPreAuthenticationChecksAsync(request);
            if (!preAuthResult.Success)
            {
                return preAuthResult;
            }
            
            // Perform protocol-specific authentication
            var authResult = await protocol.AuthenticateAsync(request);
            
            if (authResult.Success)
            {
                // Post-authentication processing
                await ProcessSuccessfulAuthenticationAsync(authResult);
            }
            else
            {
                // Log failed authentication
                await LogFailedAuthenticationAsync(request, authResult.Error);
            }
            
            return authResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during authentication for user {Username}", request.Username);
            return AuthenticationResult.Failed("Authentication service error");
        }
    }
    
    public async Task<bool> ValidateTokenAsync(string token, string protocol)
    {
        var cacheKey = $"token_validation_{protocol}_{ComputeHash(token)}";
        
        if (_cache.TryGetValue(cacheKey, out bool cachedResult))
            return cachedResult;
        
        try
        {
            if (!_protocols.TryGetValue(protocol.ToLower(), out var protocolHandler))
                return false;
            
            var isValid = await protocolHandler.ValidateTokenAsync(token);
            
            // Cache result for 5 minutes
            _cache.Set(cacheKey, isValid, TimeSpan.FromMinutes(5));
            
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating token for protocol {Protocol}", protocol);
            return false;
        }
    }
    
    public async Task<UserContext> GetUserContextAsync(string userId)
    {
        var cacheKey = $"user_context_{userId}";
        
        if (_cache.TryGetValue(cacheKey, out UserContext cachedContext))
            return cachedContext;
        
        try
        {
            var user = await _userService.GetUserByIdAsync(userId);
            if (user == null) return null;
            
            var roles = await _userService.GetUserRolesAsync(userId);
            var groups = await _userService.GetUserGroupsAsync(userId);
            var permissions = await _userService.GetUserPermissionsAsync(userId);
            var applications = await GetUserApplicationsAsync(userId);
            
            var context = new UserContext
            {
                UserId = user.Id,
                Username = user.UserName,
                Email = user.Email,
                DisplayName = user.DisplayName,
                Department = user.Department,
                Roles = roles,
                Groups = groups,
                Permissions = permissions,
                Applications = applications,
                LastLoginTime = user.LastLoginTime,
                SecurityClearance = user.SecurityClearance,
                IsActive = user.IsActive
            };
            
            // Cache for 15 minutes
            _cache.Set(cacheKey, context, TimeSpan.FromMinutes(15));
            
            return context;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user context for {UserId}", userId);
            return null;
        }
    }
    
    public async Task<List<string>> GetUserApplicationsAsync(string userId)
    {
        try
        {
            var userRoles = await _userService.GetUserRolesAsync(userId);
            var userGroups = await _userService.GetUserGroupsAsync(userId);
            
            // Get applications based on user's roles and groups
            var applications = new HashSet<string>();
            
            // Add applications for each role
            foreach (var role in userRoles)
            {
                var roleApps = await GetApplicationsForRoleAsync(role);
                foreach (var app in roleApps)
                {
                    applications.Add(app);
                }
            }
            
            // Add applications for each group
            foreach (var group in userGroups)
            {
                var groupApps = await GetApplicationsForGroupAsync(group);
                foreach (var app in groupApps)
                {
                    applications.Add(app);
                }
            }
            
            return applications.ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting applications for user {UserId}", userId);
            return new List<string>();
        }
    }
    
    public async Task LogoutUserFromAllApplicationsAsync(string userId)
    {
        try
        {
            _logger.LogInformation("Initiating global logout for user {UserId}", userId);
            
            // Get all active sessions for the user
            var sessions = await _sessionService.GetUserSessionsAsync(userId);
            
            // Terminate each session
            var logoutTasks = sessions.Select(async session =>
            {
                try
                {
                    if (_protocols.TryGetValue(session.Protocol, out var protocol))
                    {
                        await protocol.LogoutAsync(session);
                    }
                    
                    await _sessionService.TerminateSessionAsync(session.SessionId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error terminating session {SessionId}", session.SessionId);
                }
            });
            
            await Task.WhenAll(logoutTasks);
            
            // Invalidate user context cache
            _cache.Remove($"user_context_{userId}");
            
            _logger.LogInformation("Global logout completed for user {UserId}", userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during global logout for user {UserId}", userId);
            throw;
        }
    }
    
    private bool ValidateAuthenticationRequest(AuthenticationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Username))
            return false;
            
        if (string.IsNullOrWhiteSpace(request.Protocol))
            return false;
            
        // Additional validation based on protocol
        return request.Protocol switch
        {
            "saml2" => !string.IsNullOrWhiteSpace(request.SamlRequest),
            "oidc" => !string.IsNullOrWhiteSpace(request.ClientId),
            "certificate" => request.Certificate != null,
            _ => true
        };
    }
    
    private async Task<AuthenticationResult> PerformPreAuthenticationChecksAsync(AuthenticationRequest request)
    {
        // Check if user exists and is active
        var user = await _userService.FindByUsernameAsync(request.Username);
        if (user == null)
        {
            _logger.LogWarning("Authentication attempt for non-existent user {Username}", request.Username);
            return AuthenticationResult.Failed("Invalid credentials");
        }
        
        if (!user.IsActive)
        {
            _logger.LogWarning("Authentication attempt for inactive user {Username}", request.Username);
            return AuthenticationResult.Failed("Account is disabled");
        }
        
        // Check for account lockout
        if (await _userService.IsUserLockedOutAsync(user.Id))
        {
            _logger.LogWarning("Authentication attempt for locked out user {Username}", request.Username);
            return AuthenticationResult.Failed("Account is locked");
        }
        
        // Check for suspicious activity
        if (await DetectSuspiciousActivityAsync(request))
        {
            _logger.LogWarning("Suspicious authentication activity detected for user {Username}", request.Username);
            return AuthenticationResult.Failed("Authentication blocked due to suspicious activity");
        }
        
        return AuthenticationResult.Success(user);
    }
    
    private async Task ProcessSuccessfulAuthenticationAsync(AuthenticationResult result)
    {
        // Update last login time
        await _userService.UpdateLastLoginTimeAsync(result.User.Id);
        
        // Create session
        var session = new UserSession
        {
            SessionId = Guid.NewGuid().ToString(),
            UserId = result.User.Id,
            Protocol = result.Protocol,
            LoginTime = DateTime.UtcNow,
            LastActivityTime = DateTime.UtcNow,
            IpAddress = result.IpAddress,
            UserAgent = result.UserAgent
        };
        
        await _sessionService.CreateSessionAsync(session);
        
        // Log successful authentication
        _logger.LogInformation("Successful authentication for user {Username} using protocol {Protocol}",
            result.User.UserName, result.Protocol);
        
        // Invalidate cached user context to refresh data
        _cache.Remove($"user_context_{result.User.Id}");
    }
    
    private async Task LogFailedAuthenticationAsync(AuthenticationRequest request, string error)
    {
        _logger.LogWarning("Failed authentication for user {Username}: {Error}", request.Username, error);
        
        // Increment failed login count
        await _userService.IncrementFailedLoginCountAsync(request.Username);
        
        // Check if account should be locked
        var failedCount = await _userService.GetFailedLoginCountAsync(request.Username);
        var maxAttempts = 5; // Configuration value
        
        if (failedCount >= maxAttempts)
        {
            await _userService.LockUserAccountAsync(request.Username, TimeSpan.FromMinutes(30));
            _logger.LogWarning("User account {Username} locked due to too many failed attempts", request.Username);
        }
    }
    
    private async Task<bool> DetectSuspiciousActivityAsync(AuthenticationRequest request)
    {
        // Implement suspicious activity detection logic
        // - Multiple failed attempts from same IP
        // - Login attempts from unusual locations
        // - Authentication outside normal hours
        // - Rapid authentication attempts
        
        return false; // Simplified for example
    }
    
    private async Task<List<string>> GetApplicationsForRoleAsync(string role)
    {
        // Get applications accessible by this role
        return new List<string>(); // Simplified
    }
    
    private async Task<List<string>> GetApplicationsForGroupAsync(string group)
    {
        // Get applications accessible by this group
        return new List<string>(); // Simplified
    }
    
    private string ComputeHash(string input)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hashBytes);
    }
}
```

### 2. Protocol Abstraction Layer

```csharp
public interface IAuthenticationProtocol
{
    string ProtocolName { get; }
    Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request);
    Task<bool> ValidateTokenAsync(string token);
    Task LogoutAsync(UserSession session);
    Task<string> GenerateAuthenticationUrlAsync(string returnUrl, Dictionary<string, string> parameters = null);
}

// SAML Protocol Implementation
public class SamlAuthenticationProtocol : IAuthenticationProtocol
{
    public string ProtocolName => "SAML2";
    
    private readonly ISamlService _samlService;
    private readonly ILogger<SamlAuthenticationProtocol> _logger;
    
    public SamlAuthenticationProtocol(ISamlService samlService, ILogger<SamlAuthenticationProtocol> logger)
    {
        _samlService = samlService;
        _logger = logger;
    }
    
    public async Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request)
    {
        try
        {
            // Decode and validate SAML response
            var samlResponse = DecodeSamlResponse(request.SamlRequest);
            var samlUser = await _samlService.ProcessSamlResponseAsync(samlResponse);
            
            if (samlUser == null)
                return AuthenticationResult.Failed("SAML authentication failed");
            
            var user = new ApplicationUser
            {
                Id = samlUser.NameIdentifier,
                UserName = samlUser.Email,
                Email = samlUser.Email,
                DisplayName = samlUser.DisplayName
            };
            
            return AuthenticationResult.Success(user)
            {
                Protocol = ProtocolName,
                Attributes = samlUser.Attributes
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SAML authentication error");
            return AuthenticationResult.Failed("SAML authentication error");
        }
    }
    
    public async Task<bool> ValidateTokenAsync(string token)
    {
        // SAML doesn't use tokens in the same way as JWT
        // This might validate SAML assertions or session tokens
        return await _samlService.ValidateAssertionAsync(token);
    }
    
    public async Task LogoutAsync(UserSession session)
    {
        await _samlService.InitiateSingleLogoutAsync(session.SessionId);
    }
    
    public async Task<string> GenerateAuthenticationUrlAsync(string returnUrl, Dictionary<string, string> parameters = null)
    {
        return await _samlService.GenerateAuthenticationRequestAsync(returnUrl, parameters);
    }
    
    private string DecodeSamlResponse(string samlRequest)
    {
        var bytes = Convert.FromBase64String(samlRequest);
        return Encoding.UTF8.GetString(bytes);
    }
}

// OpenID Connect Protocol Implementation
public class OidcAuthenticationProtocol : IAuthenticationProtocol
{
    public string ProtocolName => "OIDC";
    
    private readonly IOidcService _oidcService;
    private readonly ILogger<OidcAuthenticationProtocol> _logger;
    
    public OidcAuthenticationProtocol(IOidcService oidcService, ILogger<OidcAuthenticationProtocol> logger)
    {
        _oidcService = oidcService;
        _logger = logger;
    }
    
    public async Task<AuthenticationResult> AuthenticateAsync(AuthenticationRequest request)
    {
        try
        {
            var tokenResponse = await _oidcService.ExchangeCodeForTokensAsync(request.Code, request.RedirectUri);
            var userInfo = await _oidcService.GetUserInfoAsync(tokenResponse.AccessToken);
            
            var user = new ApplicationUser
            {
                Id = userInfo.Subject,
                UserName = userInfo.PreferredUsername ?? userInfo.Email,
                Email = userInfo.Email,
                DisplayName = userInfo.Name
            };
            
            return AuthenticationResult.Success(user)
            {
                Protocol = ProtocolName,
                AccessToken = tokenResponse.AccessToken,
                RefreshToken = tokenResponse.RefreshToken,
                IdToken = tokenResponse.IdToken
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "OIDC authentication error");
            return AuthenticationResult.Failed("OIDC authentication error");
        }
    }
    
    public async Task<bool> ValidateTokenAsync(string token)
    {
        return await _oidcService.ValidateTokenAsync(token);
    }
    
    public async Task LogoutAsync(UserSession session)
    {
        await _oidcService.RevokeTokenAsync(session.RefreshToken);
    }
    
    public async Task<string> GenerateAuthenticationUrlAsync(string returnUrl, Dictionary<string, string> parameters = null)
    {
        return await _oidcService.GenerateAuthorizationUrlAsync(returnUrl, parameters);
    }
}
```

### 3. Enterprise Session Management

```csharp
public interface ISessionService
{
    Task<UserSession> CreateSessionAsync(UserSession session);
    Task<UserSession> GetSessionAsync(string sessionId);
    Task<List<UserSession>> GetUserSessionsAsync(string userId);
    Task UpdateSessionActivityAsync(string sessionId);
    Task TerminateSessionAsync(string sessionId);
    Task TerminateAllUserSessionsAsync(string userId);
    Task<int> GetActiveSessionCountAsync();
    Task CleanupExpiredSessionsAsync();
}

public class EnterpriseSessionService : ISessionService
{
    private readonly IDistributedCache _cache;
    private readonly ISessionRepository _repository;
    private readonly IConfiguration _configuration;
    private readonly ILogger<EnterpriseSessionService> _logger;
    
    private readonly TimeSpan _sessionTimeout;
    private readonly TimeSpan _maxSessionDuration;
    
    public EnterpriseSessionService(
        IDistributedCache cache,
        ISessionRepository repository,
        IConfiguration configuration,
        ILogger<EnterpriseSessionService> logger)
    {
        _cache = cache;
        _repository = repository;
        _configuration = configuration;
        _logger = logger;
        
        _sessionTimeout = TimeSpan.FromMinutes(configuration.GetValue<int>("Session:TimeoutMinutes", 30));
        _maxSessionDuration = TimeSpan.FromHours(configuration.GetValue<int>("Session:MaxDurationHours", 8));
    }
    
    public async Task<UserSession> CreateSessionAsync(UserSession session)
    {
        try
        {
            session.CreatedTime = DateTime.UtcNow;
            session.LastActivityTime = DateTime.UtcNow;
            session.ExpiresAt = DateTime.UtcNow.Add(_sessionTimeout);
            session.MaxExpiresAt = DateTime.UtcNow.Add(_maxSessionDuration);
            
            // Store in distributed cache for fast access
            var cacheKey = $"session:{session.SessionId}";
            await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(session), new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _maxSessionDuration
            });
            
            // Store in database for persistence
            await _repository.CreateSessionAsync(session);
            
            _logger.LogInformation("Created session {SessionId} for user {UserId}", session.SessionId, session.UserId);
            
            return session;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating session for user {UserId}", session.UserId);
            throw;
        }
    }
    
    public async Task<UserSession> GetSessionAsync(string sessionId)
    {
        try
        {
            var cacheKey = $"session:{sessionId}";
            var cachedSession = await _cache.GetStringAsync(cacheKey);
            
            if (!string.IsNullOrEmpty(cachedSession))
            {
                var session = JsonSerializer.Deserialize<UserSession>(cachedSession);
                
                // Check if session is still valid
                if (IsSessionValid(session))
                {
                    return session;
                }
                else
                {
                    // Remove expired session
                    await TerminateSessionAsync(sessionId);
                    return null;
                }
            }
            
            // Try to get from database
            var dbSession = await _repository.GetSessionAsync(sessionId);
            if (dbSession != null && IsSessionValid(dbSession))
            {
                // Restore to cache
                await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(dbSession));
                return dbSession;
            }
            
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving session {SessionId}", sessionId);
            return null;
        }
    }
    
    public async Task<List<UserSession>> GetUserSessionsAsync(string userId)
    {
        try
        {
            var sessions = await _repository.GetUserSessionsAsync(userId);
            
            // Filter out expired sessions
            var validSessions = sessions.Where(IsSessionValid).ToList();
            
            // Remove expired sessions from storage
            var expiredSessions = sessions.Except(validSessions);
            foreach (var expiredSession in expiredSessions)
            {
                await TerminateSessionAsync(expiredSession.SessionId);
            }
            
            return validSessions;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving sessions for user {UserId}", userId);
            return new List<UserSession>();
        }
    }
    
    public async Task UpdateSessionActivityAsync(string sessionId)
    {
        try
        {
            var session = await GetSessionAsync(sessionId);
            if (session == null) return;
            
            session.LastActivityTime = DateTime.UtcNow;
            session.ExpiresAt = DateTime.UtcNow.Add(_sessionTimeout);
            
            // Update cache
            var cacheKey = $"session:{sessionId}";
            await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(session));
            
            // Update database (could be done async/batched for performance)
            await _repository.UpdateSessionActivityAsync(sessionId, session.LastActivityTime, session.ExpiresAt);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating session activity for {SessionId}", sessionId);
        }
    }
    
    public async Task TerminateSessionAsync(string sessionId)
    {
        try
        {
            // Remove from cache
            var cacheKey = $"session:{sessionId}";
            await _cache.RemoveAsync(cacheKey);
            
            // Mark as terminated in database
            await _repository.TerminateSessionAsync(sessionId);
            
            _logger.LogInformation("Terminated session {SessionId}", sessionId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error terminating session {SessionId}", sessionId);
        }
    }
    
    public async Task TerminateAllUserSessionsAsync(string userId)
    {
        try
        {
            var sessions = await GetUserSessionsAsync(userId);
            
            var terminationTasks = sessions.Select(session => TerminateSessionAsync(session.SessionId));
            await Task.WhenAll(terminationTasks);
            
            _logger.LogInformation("Terminated all sessions for user {UserId}", userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error terminating all sessions for user {UserId}", userId);
        }
    }
    
    public async Task<int> GetActiveSessionCountAsync()
    {
        try
        {
            return await _repository.GetActiveSessionCountAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active session count");
            return 0;
        }
    }
    
    public async Task CleanupExpiredSessionsAsync()
    {
        try
        {
            var expiredSessions = await _repository.GetExpiredSessionsAsync();
            
            foreach (var session in expiredSessions)
            {
                await TerminateSessionAsync(session.SessionId);
            }
            
            _logger.LogInformation("Cleaned up {Count} expired sessions", expiredSessions.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during session cleanup");
        }
    }
    
    private bool IsSessionValid(UserSession session)
    {
        var now = DateTime.UtcNow;
        
        // Check if session has expired due to inactivity
        if (now > session.ExpiresAt)
            return false;
        
        // Check if session has exceeded maximum duration
        if (now > session.MaxExpiresAt)
            return false;
        
        return true;
    }
}
```

### 4. Enterprise Identity Controller

```csharp
[ApiController]
[Route("api/enterprise")]
[Authorize]
public class EnterpriseIdentityController : ControllerBase
{
    private readonly IEnterpriseAuthenticationService _authService;
    private readonly ISessionService _sessionService;
    private readonly IUserService _userService;
    
    public EnterpriseIdentityController(
        IEnterpriseAuthenticationService authService,
        ISessionService sessionService,
        IUserService userService)
    {
        _authService = authService;
        _sessionService = sessionService;
        _userService = userService;
    }
    
    [HttpPost("authenticate")]
    [AllowAnonymous]
    public async Task<IActionResult> Authenticate([FromBody] AuthenticationRequest request)
    {
        var result = await _authService.AuthenticateAsync(request);
        
        if (result.Success)
        {
            return Ok(new
            {
                Success = true,
                Token = result.Token,
                RefreshToken = result.RefreshToken,
                ExpiresIn = result.ExpiresIn,
                User = new
                {
                    result.User.Id,
                    result.User.UserName,
                    result.User.Email,
                    result.User.DisplayName
                }
            });
        }
        
        return Unauthorized(new { Success = false, Error = result.Error });
    }
    
    [HttpGet("context")]
    public async Task<IActionResult> GetUserContext()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
            return BadRequest("User ID not found");
        
        var context = await _authService.GetUserContextAsync(userId);
        
        if (context == null)
            return NotFound("User context not found");
        
        return Ok(context);
    }
    
    [HttpGet("applications")]
    public async Task<IActionResult> GetUserApplications()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
            return BadRequest("User ID not found");
        
        var applications = await _authService.GetUserApplicationsAsync(userId);
        
        return Ok(new { Applications = applications });
    }
    
    [HttpGet("sessions")]
    public async Task<IActionResult> GetUserSessions()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
            return BadRequest("User ID not found");
        
        var sessions = await _sessionService.GetUserSessionsAsync(userId);
        
        var sessionInfo = sessions.Select(s => new
        {
            s.SessionId,
            s.Protocol,
            s.LoginTime,
            s.LastActivityTime,
            s.IpAddress,
            s.UserAgent,
            IsCurrentSession = s.SessionId == HttpContext.Session.Id
        });
        
        return Ok(new { Sessions = sessionInfo });
    }
    
    [HttpPost("sessions/{sessionId}/terminate")]
    public async Task<IActionResult> TerminateSession(string sessionId)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        // Verify session belongs to current user
        var userSessions = await _sessionService.GetUserSessionsAsync(userId);
        var session = userSessions.FirstOrDefault(s => s.SessionId == sessionId);
        
        if (session == null)
            return NotFound("Session not found or does not belong to current user");
        
        await _sessionService.TerminateSessionAsync(sessionId);
        
        return Ok(new { Message = "Session terminated successfully" });
    }
    
    [HttpPost("logout-all")]
    public async Task<IActionResult> LogoutFromAllApplications()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
            return BadRequest("User ID not found");
        
        await _authService.LogoutUserFromAllApplicationsAsync(userId);
        
        return Ok(new { Message = "Logged out from all applications successfully" });
    }
    
    [HttpGet("admin/sessions")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> GetActiveSessionCount()
    {
        var count = await _sessionService.GetActiveSessionCountAsync();
        
        return Ok(new { ActiveSessions = count });
    }
    
    [HttpPost("admin/cleanup-sessions")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> CleanupExpiredSessions()
    {
        await _sessionService.CleanupExpiredSessionsAsync();
        
        return Ok(new { Message = "Session cleanup completed" });
    }
}
```

## Security Best Practices

### 1. Zero Trust Implementation

```csharp
public class ZeroTrustAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IZeroTrustService _zeroTrustService;
    private readonly ILogger<ZeroTrustAuthenticationMiddleware> _logger;
    
    public ZeroTrustAuthenticationMiddleware(
        RequestDelegate next,
        IZeroTrustService zeroTrustService,
        ILogger<ZeroTrustAuthenticationMiddleware> logger)
    {
        _next = next;
        _zeroTrustService = zeroTrustService;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Skip for authentication endpoints
        if (context.Request.Path.StartsWithSegments("/api/enterprise/authenticate"))
        {
            await _next(context);
            return;
        }
        
        if (context.User.Identity.IsAuthenticated)
        {
            var trustEvaluation = await _zeroTrustService.EvaluateTrustAsync(context);
            
            if (!trustEvaluation.IsTrusted)
            {
                _logger.LogWarning("Zero Trust evaluation failed for user {User}: {Reason}",
                    context.User.Identity.Name, trustEvaluation.Reason);
                
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Access denied - trust evaluation failed");
                return;
            }
            
            // Add trust score to context
            context.Items["TrustScore"] = trustEvaluation.TrustScore;
        }
        
        await _next(context);
    }
}

public interface IZeroTrustService
{
    Task<TrustEvaluation> EvaluateTrustAsync(HttpContext context);
}

public class ZeroTrustService : IZeroTrustService
{
    public async Task<TrustEvaluation> EvaluateTrustAsync(HttpContext context)
    {
        var factors = new List<TrustFactor>();
        
        // Device trust
        factors.Add(await EvaluateDeviceTrustAsync(context));
        
        // Location trust
        factors.Add(await EvaluateLocationTrustAsync(context));
        
        // Behavioral trust
        factors.Add(await EvaluateBehavioralTrustAsync(context));
        
        // Time-based trust
        factors.Add(EvaluateTimeTrust(context));
        
        // Calculate overall trust score
        var trustScore = CalculateTrustScore(factors);
        var isTrusted = trustScore >= 0.7; // Configurable threshold
        
        return new TrustEvaluation
        {
            IsTrusted = isTrusted,
            TrustScore = trustScore,
            Factors = factors,
            Reason = isTrusted ? "Trust evaluation passed" : "Trust score below threshold"
        };
    }
    
    private async Task<TrustFactor> EvaluateDeviceTrustAsync(HttpContext context)
    {
        // Check device certificate, managed device status, etc.
        return new TrustFactor { Name = "Device", Score = 0.8, Weight = 0.3 };
    }
    
    private async Task<TrustFactor> EvaluateLocationTrustAsync(HttpContext context)
    {
        // Check IP geolocation, known networks, etc.
        return new TrustFactor { Name = "Location", Score = 0.9, Weight = 0.2 };
    }
    
    private async Task<TrustFactor> EvaluateBehavioralTrustAsync(HttpContext context)
    {
        // Check user behavior patterns, access patterns, etc.
        return new TrustFactor { Name = "Behavior", Score = 0.7, Weight = 0.3 };
    }
    
    private TrustFactor EvaluateTimeTrust(HttpContext context)
    {
        // Check if access is during normal business hours
        var now = DateTime.UtcNow;
        var isBusinessHours = now.DayOfWeek >= DayOfWeek.Monday && 
                             now.DayOfWeek <= DayOfWeek.Friday && 
                             now.Hour >= 9 && now.Hour < 17;
        
        return new TrustFactor 
        { 
            Name = "Time", 
            Score = isBusinessHours ? 1.0 : 0.5, 
            Weight = 0.2 
        };
    }
    
    private double CalculateTrustScore(List<TrustFactor> factors)
    {
        return factors.Sum(f => f.Score * f.Weight) / factors.Sum(f => f.Weight);
    }
}

public class TrustEvaluation
{
    public bool IsTrusted { get; set; }
    public double TrustScore { get; set; }
    public List<TrustFactor> Factors { get; set; }
    public string Reason { get; set; }
}

public class TrustFactor
{
    public string Name { get; set; }
    public double Score { get; set; }
    public double Weight { get; set; }
}
```

### 2. Enterprise Audit Logging

```csharp
public class EnterpriseAuditLogger
{
    private readonly ILogger<EnterpriseAuditLogger> _logger;
    private readonly IAuditRepository _auditRepository;
    
    public async Task LogAuthenticationEventAsync(AuthenticationEvent authEvent)
    {
        var auditEntry = new AuditEntry
        {
            EventType = "Authentication",
            EventSubType = authEvent.EventType,
            UserId = authEvent.UserId,
            Username = authEvent.Username,
            IpAddress = authEvent.IpAddress,
            UserAgent = authEvent.UserAgent,
            Success = authEvent.Success,
            ErrorMessage = authEvent.ErrorMessage,
            AdditionalData = JsonSerializer.Serialize(authEvent.AdditionalData),
            Timestamp = DateTime.UtcNow
        };
        
        await _auditRepository.CreateAuditEntryAsync(auditEntry);
        
        _logger.LogInformation("Authentication event logged: {EventType} for user {Username} - Success: {Success}",
            authEvent.EventType, authEvent.Username, authEvent.Success);
    }
    
    public async Task LogSessionEventAsync(SessionEvent sessionEvent)
    {
        var auditEntry = new AuditEntry
        {
            EventType = "Session",
            EventSubType = sessionEvent.EventType,
            UserId = sessionEvent.UserId,
            SessionId = sessionEvent.SessionId,
            IpAddress = sessionEvent.IpAddress,
            AdditionalData = JsonSerializer.Serialize(sessionEvent.AdditionalData),
            Timestamp = DateTime.UtcNow
        };
        
        await _auditRepository.CreateAuditEntryAsync(auditEntry);
    }
}
```

## Testing Strategies

### 1. Load Testing

```csharp
[TestFixture]
public class EnterpriseAuthenticationLoadTests
{
    [Test]
    public async Task AuthenticateAsync_Under_Load_Should_Maintain_Performance()
    {
        // Simulate high load authentication scenarios
        var tasks = new List<Task<AuthenticationResult>>();
        
        for (int i = 0; i < 1000; i++)
        {
            tasks.Add(SimulateAuthenticationAsync($"user{i}"));
        }
        
        var stopwatch = Stopwatch.StartNew();
        var results = await Task.WhenAll(tasks);
        stopwatch.Stop();
        
        // Assert performance metrics
        Assert.That(stopwatch.ElapsedMilliseconds, Is.LessThan(5000)); // 5 seconds max
        Assert.That(results.Count(r => r.Success), Is.GreaterThan(950)); // 95% success rate
    }
    
    private async Task<AuthenticationResult> SimulateAuthenticationAsync(string username)
    {
        // Simulate authentication request
        return AuthenticationResult.Success(new ApplicationUser { UserName = username });
    }
}
```

---
**Next**: Continue with API security patterns