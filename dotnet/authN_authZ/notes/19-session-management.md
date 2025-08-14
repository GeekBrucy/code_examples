# Session Management

## Overview
Session management is the process of securely handling user sessions from login to logout, including session creation, validation, storage, expiration, and termination. Proper session management is critical for maintaining security and user experience in web applications.

## Core Concepts

### 1. Session Fundamentals

#### Session Lifecycle
- **Creation**: Session established upon successful authentication
- **Validation**: Session verified on each request
- **Renewal**: Session extended based on activity
- **Expiration**: Session invalidated after timeout or max duration
- **Termination**: Session explicitly ended by user or system

#### Session Storage Options
- **In-Memory**: Fast but not scalable or persistent
- **Database**: Persistent and scalable but slower
- **Distributed Cache**: Fast, scalable, and persistent (Redis, Memcached)
- **Cookies**: Client-side storage with security considerations
- **JWT Tokens**: Stateless sessions with encoded claims

#### Session Security Considerations
- **Session Fixation**: Regenerate session ID after authentication
- **Session Hijacking**: Secure transmission and validation
- **Session Timeout**: Balance security with user experience
- **Concurrent Sessions**: Manage multiple active sessions
- **Cross-Site Attacks**: CSRF and XSS protection

### 2. Session Types

#### Server-Side Sessions
- Session data stored on server
- Client receives session identifier
- Full control over session data
- Requires server-side storage

#### Client-Side Sessions
- Session data stored in client (cookies/tokens)
- Stateless from server perspective
- Scalability benefits
- Security challenges with client storage

#### Hybrid Sessions
- Combination of server and client storage
- Critical data on server, non-sensitive on client
- Balance between security and performance

## .NET Session Management Implementation

### 1. Advanced Session Service

```csharp
public interface IAdvancedSessionService
{
    Task<SessionContext> CreateSessionAsync(string userId, SessionOptions options = null);
    Task<SessionContext> GetSessionAsync(string sessionId);
    Task<SessionContext> ValidateSessionAsync(string sessionId);
    Task<bool> RefreshSessionAsync(string sessionId);
    Task<bool> TerminateSessionAsync(string sessionId);
    Task<List<SessionContext>> GetUserSessionsAsync(string userId);
    Task<bool> TerminateAllUserSessionsAsync(string userId);
    Task<bool> TerminateAllSessionsExceptCurrentAsync(string userId, string currentSessionId);
    Task<SessionStatistics> GetSessionStatisticsAsync();
    Task CleanupExpiredSessionsAsync();
}

public class AdvancedSessionService : IAdvancedSessionService
{
    private readonly IDistributedCache _cache;
    private readonly ISessionRepository _repository;
    private readonly ISessionSecurityService _securityService;
    private readonly ISessionEventService _eventService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AdvancedSessionService> _logger;
    
    private readonly SessionConfiguration _config;
    
    public AdvancedSessionService(
        IDistributedCache cache,
        ISessionRepository repository,
        ISessionSecurityService securityService,
        ISessionEventService eventService,
        IConfiguration configuration,
        ILogger<AdvancedSessionService> logger)
    {
        _cache = cache;
        _repository = repository;
        _securityService = securityService;
        _eventService = eventService;
        _configuration = configuration;
        _logger = logger;
        _config = configuration.GetSection("SessionManagement").Get<SessionConfiguration>() ?? new SessionConfiguration();
    }
    
    public async Task<SessionContext> CreateSessionAsync(string userId, SessionOptions options = null)
    {
        try
        {
            options ??= new SessionOptions();
            
            // Check concurrent session limits
            var existingSessions = await GetActiveUserSessionsAsync(userId);
            if (existingSessions.Count >= _config.MaxConcurrentSessions)
            {
                await HandleConcurrentSessionLimitAsync(userId, existingSessions);
            }
            
            // Create new session
            var session = new SessionContext
            {
                SessionId = GenerateSessionId(),
                UserId = userId,
                CreatedAt = DateTime.UtcNow,
                LastAccessedAt = DateTime.UtcNow,
                ExpiresAt = CalculateExpirationTime(options),
                MaxExpiresAt = CalculateMaxExpirationTime(options),
                IpAddress = options.IpAddress,
                UserAgent = options.UserAgent,
                DeviceFingerprint = options.DeviceFingerprint,
                IsSecure = options.IsSecure,
                IsHttpOnly = options.IsHttpOnly,
                SameSite = options.SameSite,
                AuthenticationMethod = options.AuthenticationMethod,
                SecurityLevel = options.SecurityLevel,
                Metadata = options.Metadata ?? new Dictionary<string, object>()
            };
            
            // Apply security enhancements
            await _securityService.EnhanceSessionSecurityAsync(session);
            
            // Store session
            await StoreSessionAsync(session);
            
            // Log session creation
            await _eventService.LogSessionEventAsync(new SessionEvent
            {
                SessionId = session.SessionId,
                UserId = userId,
                EventType = SessionEventType.Created,
                IpAddress = options.IpAddress,
                UserAgent = options.UserAgent,
                Timestamp = DateTime.UtcNow
            });
            
            _logger.LogInformation("Session created for user {UserId}: {SessionId}", userId, session.SessionId);
            
            return session;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating session for user {UserId}", userId);
            throw new SessionManagementException("Failed to create session", ex);
        }
    }
    
    public async Task<SessionContext> GetSessionAsync(string sessionId)
    {
        try
        {
            if (string.IsNullOrEmpty(sessionId))
                return null;
            
            // Try cache first
            var cacheKey = GetSessionCacheKey(sessionId);
            var cachedSession = await _cache.GetStringAsync(cacheKey);
            
            if (!string.IsNullOrEmpty(cachedSession))
            {
                var session = JsonSerializer.Deserialize<SessionContext>(cachedSession);
                
                // Validate session integrity
                if (await _securityService.ValidateSessionIntegrityAsync(session))
                {
                    return session;
                }
                else
                {
                    _logger.LogWarning("Session integrity validation failed for {SessionId}", sessionId);
                    await InvalidateSessionAsync(sessionId);
                    return null;
                }
            }
            
            // Try database
            var dbSession = await _repository.GetSessionAsync(sessionId);
            if (dbSession != null)
            {
                // Restore to cache
                await CacheSessionAsync(dbSession);
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
    
    public async Task<SessionContext> ValidateSessionAsync(string sessionId)
    {
        try
        {
            var session = await GetSessionAsync(sessionId);
            
            if (session == null)
            {
                _logger.LogDebug("Session not found: {SessionId}", sessionId);
                return null;
            }
            
            var now = DateTime.UtcNow;
            
            // Check if session has expired
            if (now > session.ExpiresAt)
            {
                _logger.LogInformation("Session expired: {SessionId}", sessionId);
                await InvalidateSessionAsync(sessionId);
                return null;
            }
            
            // Check if session has exceeded maximum duration
            if (now > session.MaxExpiresAt)
            {
                _logger.LogInformation("Session exceeded maximum duration: {SessionId}", sessionId);
                await InvalidateSessionAsync(sessionId);
                return null;
            }
            
            // Check for suspicious activity
            if (await _securityService.DetectSuspiciousActivityAsync(session))
            {
                _logger.LogWarning("Suspicious activity detected for session: {SessionId}", sessionId);
                await InvalidateSessionAsync(sessionId);
                return null;
            }
            
            // Update last accessed time
            session.LastAccessedAt = now;
            
            // Extend session if needed
            if (_config.SlidingExpiration)
            {
                session.ExpiresAt = now.Add(_config.SessionTimeout);
            }
            
            // Update session
            await StoreSessionAsync(session);
            
            return session;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating session {SessionId}", sessionId);
            return null;
        }
    }
    
    public async Task<bool> RefreshSessionAsync(string sessionId)
    {
        try
        {
            var session = await GetSessionAsync(sessionId);
            if (session == null)
                return false;
            
            var now = DateTime.UtcNow;
            
            // Check if session can be refreshed
            if (now > session.MaxExpiresAt)
            {
                _logger.LogInformation("Cannot refresh session past maximum duration: {SessionId}", sessionId);
                return false;
            }
            
            // Refresh session
            session.LastAccessedAt = now;
            session.ExpiresAt = now.Add(_config.SessionTimeout);
            
            // Optionally rotate session ID for security
            if (_config.RotateSessionIdOnRefresh)
            {
                var oldSessionId = session.SessionId;
                session.SessionId = GenerateSessionId();
                
                // Remove old session
                await InvalidateSessionAsync(oldSessionId);
                
                _logger.LogInformation("Session ID rotated from {OldSessionId} to {NewSessionId}", 
                    oldSessionId, session.SessionId);
            }
            
            await StoreSessionAsync(session);
            
            // Log refresh event
            await _eventService.LogSessionEventAsync(new SessionEvent
            {
                SessionId = session.SessionId,
                UserId = session.UserId,
                EventType = SessionEventType.Refreshed,
                Timestamp = now
            });
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing session {SessionId}", sessionId);
            return false;
        }
    }
    
    public async Task<bool> TerminateSessionAsync(string sessionId)
    {
        try
        {
            var session = await GetSessionAsync(sessionId);
            if (session == null)
                return false;
            
            // Remove from cache
            var cacheKey = GetSessionCacheKey(sessionId);
            await _cache.RemoveAsync(cacheKey);
            
            // Mark as terminated in database
            await _repository.TerminateSessionAsync(sessionId);
            
            // Log termination event
            await _eventService.LogSessionEventAsync(new SessionEvent
            {
                SessionId = sessionId,
                UserId = session.UserId,
                EventType = SessionEventType.Terminated,
                Timestamp = DateTime.UtcNow
            });
            
            _logger.LogInformation("Session terminated: {SessionId}", sessionId);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error terminating session {SessionId}", sessionId);
            return false;
        }
    }
    
    public async Task<List<SessionContext>> GetUserSessionsAsync(string userId)
    {
        try
        {
            var sessions = await _repository.GetUserSessionsAsync(userId);
            
            // Filter out expired sessions
            var now = DateTime.UtcNow;
            var validSessions = sessions.Where(s => s.ExpiresAt > now && s.MaxExpiresAt > now).ToList();
            
            // Remove expired sessions
            var expiredSessions = sessions.Except(validSessions);
            foreach (var expiredSession in expiredSessions)
            {
                await InvalidateSessionAsync(expiredSession.SessionId);
            }
            
            return validSessions;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving sessions for user {UserId}", userId);
            return new List<SessionContext>();
        }
    }
    
    public async Task<bool> TerminateAllUserSessionsAsync(string userId)
    {
        try
        {
            var sessions = await GetUserSessionsAsync(userId);
            
            var terminationTasks = sessions.Select(session => TerminateSessionAsync(session.SessionId));
            await Task.WhenAll(terminationTasks);
            
            _logger.LogInformation("All sessions terminated for user {UserId}", userId);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error terminating all sessions for user {UserId}", userId);
            return false;
        }
    }
    
    public async Task<bool> TerminateAllSessionsExceptCurrentAsync(string userId, string currentSessionId)
    {
        try
        {
            var sessions = await GetUserSessionsAsync(userId);
            var sessionsToTerminate = sessions.Where(s => s.SessionId != currentSessionId);
            
            var terminationTasks = sessionsToTerminate.Select(session => TerminateSessionAsync(session.SessionId));
            await Task.WhenAll(terminationTasks);
            
            _logger.LogInformation("All sessions except current terminated for user {UserId}", userId);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error terminating other sessions for user {UserId}", userId);
            return false;
        }
    }
    
    public async Task<SessionStatistics> GetSessionStatisticsAsync()
    {
        try
        {
            return await _repository.GetSessionStatisticsAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving session statistics");
            return new SessionStatistics();
        }
    }
    
    public async Task CleanupExpiredSessionsAsync()
    {
        try
        {
            var expiredSessions = await _repository.GetExpiredSessionsAsync();
            
            var cleanupTasks = expiredSessions.Select(async session =>
            {
                try
                {
                    await InvalidateSessionAsync(session.SessionId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error cleaning up expired session {SessionId}", session.SessionId);
                }
            });
            
            await Task.WhenAll(cleanupTasks);
            
            _logger.LogInformation("Cleaned up {Count} expired sessions", expiredSessions.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during session cleanup");
        }
    }
    
    private async Task<List<SessionContext>> GetActiveUserSessionsAsync(string userId)
    {
        return await GetUserSessionsAsync(userId);
    }
    
    private async Task HandleConcurrentSessionLimitAsync(string userId, List<SessionContext> existingSessions)
    {
        switch (_config.ConcurrentSessionPolicy)
        {
            case ConcurrentSessionPolicy.TerminateOldest:
                var oldestSession = existingSessions.OrderBy(s => s.CreatedAt).First();
                await TerminateSessionAsync(oldestSession.SessionId);
                _logger.LogInformation("Terminated oldest session for user {UserId} due to limit", userId);
                break;
                
            case ConcurrentSessionPolicy.TerminateAll:
                await TerminateAllUserSessionsAsync(userId);
                _logger.LogInformation("Terminated all sessions for user {UserId} due to limit", userId);
                break;
                
            case ConcurrentSessionPolicy.RejectNew:
                throw new SessionLimitExceededException($"User {userId} has reached maximum concurrent sessions");
                
            default:
                // Allow new session
                break;
        }
    }
    
    private string GenerateSessionId()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
    
    private DateTime CalculateExpirationTime(SessionOptions options)
    {
        var timeout = options.SessionTimeout ?? _config.SessionTimeout;
        return DateTime.UtcNow.Add(timeout);
    }
    
    private DateTime CalculateMaxExpirationTime(SessionOptions options)
    {
        var maxDuration = options.MaxSessionDuration ?? _config.MaxSessionDuration;
        return DateTime.UtcNow.Add(maxDuration);
    }
    
    private async Task StoreSessionAsync(SessionContext session)
    {
        // Store in cache
        await CacheSessionAsync(session);
        
        // Store in database
        await _repository.SaveSessionAsync(session);
    }
    
    private async Task CacheSessionAsync(SessionContext session)
    {
        var cacheKey = GetSessionCacheKey(session.SessionId);
        var serializedSession = JsonSerializer.Serialize(session);
        
        var cacheOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = session.MaxExpiresAt,
            SlidingExpiration = TimeSpan.FromMinutes(30) // Keep hot sessions in cache
        };
        
        await _cache.SetStringAsync(cacheKey, serializedSession, cacheOptions);
    }
    
    private async Task InvalidateSessionAsync(string sessionId)
    {
        // Remove from cache
        var cacheKey = GetSessionCacheKey(sessionId);
        await _cache.RemoveAsync(cacheKey);
        
        // Mark as invalid in database
        await _repository.InvalidateSessionAsync(sessionId);
    }
    
    private string GetSessionCacheKey(string sessionId)
    {
        return $"session:{sessionId}";
    }
}
```

### 2. Session Security Service

```csharp
public interface ISessionSecurityService
{
    Task EnhanceSessionSecurityAsync(SessionContext session);
    Task<bool> ValidateSessionIntegrityAsync(SessionContext session);
    Task<bool> DetectSuspiciousActivityAsync(SessionContext session);
    Task<string> GenerateSessionTokenAsync(SessionContext session);
    Task<bool> ValidateSessionTokenAsync(string token);
}

public class SessionSecurityService : ISessionSecurityService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<SessionSecurityService> _logger;
    private readonly IMemoryCache _cache;
    private readonly IGeolocationService _geolocationService;
    
    private readonly byte[] _encryptionKey;
    private readonly byte[] _signingKey;
    
    public SessionSecurityService(
        IConfiguration configuration,
        ILogger<SessionSecurityService> logger,
        IMemoryCache cache,
        IGeolocationService geolocationService)
    {
        _configuration = configuration;
        _logger = logger;
        _cache = cache;
        _geolocationService = geolocationService;
        
        _encryptionKey = Convert.FromBase64String(configuration["SessionSecurity:EncryptionKey"]);
        _signingKey = Convert.FromBase64String(configuration["SessionSecurity:SigningKey"]);
    }
    
    public async Task EnhanceSessionSecurityAsync(SessionContext session)
    {
        // Generate session signature
        session.Signature = GenerateSessionSignature(session);
        
        // Add entropy for session ID
        session.Entropy = GenerateEntropy();
        
        // Encrypt sensitive metadata
        if (session.Metadata.Any())
        {
            session.EncryptedMetadata = await EncryptMetadataAsync(session.Metadata);
            session.Metadata.Clear(); // Remove plain text
        }
        
        // Store security context
        session.SecurityContext = new SessionSecurityContext
        {
            CreationFingerprint = GenerateSecurityFingerprint(session),
            RiskScore = await CalculateRiskScoreAsync(session),
            RequiredSecurityLevel = DetermineRequiredSecurityLevel(session)
        };
    }
    
    public async Task<bool> ValidateSessionIntegrityAsync(SessionContext session)
    {
        try
        {
            // Validate session signature
            var expectedSignature = GenerateSessionSignature(session);
            if (session.Signature != expectedSignature)
            {
                _logger.LogWarning("Session signature validation failed for {SessionId}", session.SessionId);
                return false;
            }
            
            // Validate session hasn't been tampered with
            if (!ValidateSessionData(session))
            {
                _logger.LogWarning("Session data validation failed for {SessionId}", session.SessionId);
                return false;
            }
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating session integrity for {SessionId}", session.SessionId);
            return false;
        }
    }
    
    public async Task<bool> DetectSuspiciousActivityAsync(SessionContext session)
    {
        var suspiciousIndicators = new List<string>();
        
        // Check for IP address changes
        if (await DetectIpAddressAnomalyAsync(session))
        {
            suspiciousIndicators.Add("IP address anomaly");
        }
        
        // Check for user agent changes
        if (DetectUserAgentChange(session))
        {
            suspiciousIndicators.Add("User agent change");
        }
        
        // Check for geographical anomalies
        if (await DetectGeographicalAnomalyAsync(session))
        {
            suspiciousIndicators.Add("Geographical anomaly");
        }
        
        // Check for unusual access patterns
        if (await DetectUnusualAccessPatternsAsync(session))
        {
            suspiciousIndicators.Add("Unusual access patterns");
        }
        
        // Check for session replay attacks
        if (DetectSessionReplayAttack(session))
        {
            suspiciousIndicators.Add("Potential session replay");
        }
        
        if (suspiciousIndicators.Any())
        {
            _logger.LogWarning("Suspicious activity detected for session {SessionId}: {Indicators}",
                session.SessionId, string.Join(", ", suspiciousIndicators));
            
            return true;
        }
        
        return false;
    }
    
    public async Task<string> GenerateSessionTokenAsync(SessionContext session)
    {
        try
        {
            var tokenPayload = new
            {
                SessionId = session.SessionId,
                UserId = session.UserId,
                IssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ExpiresAt = new DateTimeOffset(session.ExpiresAt).ToUnixTimeSeconds(),
                Signature = session.Signature
            };
            
            var jsonPayload = JsonSerializer.Serialize(tokenPayload);
            var encryptedPayload = await EncryptStringAsync(jsonPayload);
            
            return Convert.ToBase64String(encryptedPayload);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating session token for {SessionId}", session.SessionId);
            throw;
        }
    }
    
    public async Task<bool> ValidateSessionTokenAsync(string token)
    {
        try
        {
            var encryptedBytes = Convert.FromBase64String(token);
            var decryptedJson = await DecryptStringAsync(encryptedBytes);
            var tokenPayload = JsonSerializer.Deserialize<SessionTokenPayload>(decryptedJson);
            
            // Validate expiration
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now > tokenPayload.ExpiresAt)
            {
                return false;
            }
            
            // Additional validation logic...
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating session token");
            return false;
        }
    }
    
    private string GenerateSessionSignature(SessionContext session)
    {
        var dataToSign = $"{session.SessionId}:{session.UserId}:{session.CreatedAt:O}:{session.IpAddress}";
        
        using var hmac = new HMACSHA256(_signingKey);
        var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
        
        return Convert.ToBase64String(signatureBytes);
    }
    
    private string GenerateEntropy()
    {
        using var rng = RandomNumberGenerator.Create();
        var entropyBytes = new byte[16];
        rng.GetBytes(entropyBytes);
        return Convert.ToBase64String(entropyBytes);
    }
    
    private async Task<byte[]> EncryptMetadataAsync(Dictionary<string, object> metadata)
    {
        var json = JsonSerializer.Serialize(metadata);
        return await EncryptStringAsync(json);
    }
    
    private async Task<byte[]> EncryptStringAsync(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor();
        using var msEncrypt = new MemoryStream();
        
        // Write IV first
        await msEncrypt.WriteAsync(aes.IV, 0, aes.IV.Length);
        
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            await swEncrypt.WriteAsync(plainText);
        }
        
        return msEncrypt.ToArray();
    }
    
    private async Task<string> DecryptStringAsync(byte[] cipherText)
    {
        using var aes = Aes.Create();
        aes.Key = _encryptionKey;
        
        // Extract IV
        var iv = new byte[16];
        Array.Copy(cipherText, 0, iv, 0, iv.Length);
        aes.IV = iv;
        
        using var decryptor = aes.CreateDecryptor();
        using var msDecrypt = new MemoryStream(cipherText, iv.Length, cipherText.Length - iv.Length);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        
        return await srDecrypt.ReadToEndAsync();
    }
    
    private string GenerateSecurityFingerprint(SessionContext session)
    {
        var fingerprintData = $"{session.UserAgent}:{session.IpAddress}:{session.DeviceFingerprint}";
        
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(fingerprintData));
        
        return Convert.ToBase64String(hashBytes);
    }
    
    private async Task<double> CalculateRiskScoreAsync(SessionContext session)
    {
        var riskFactors = new List<RiskFactor>();
        
        // IP reputation
        var ipRisk = await GetIpReputationRiskAsync(session.IpAddress);
        riskFactors.Add(new RiskFactor { Name = "IP Reputation", Score = ipRisk, Weight = 0.3 });
        
        // Time-based risk
        var timeRisk = CalculateTimeBasedRisk(session.CreatedAt);
        riskFactors.Add(new RiskFactor { Name = "Time-based", Score = timeRisk, Weight = 0.2 });
        
        // Device risk
        var deviceRisk = CalculateDeviceRisk(session.DeviceFingerprint);
        riskFactors.Add(new RiskFactor { Name = "Device", Score = deviceRisk, Weight = 0.3 });
        
        // Geographic risk
        var geoRisk = await CalculateGeographicRiskAsync(session.IpAddress, session.UserId);
        riskFactors.Add(new RiskFactor { Name = "Geographic", Score = geoRisk, Weight = 0.2 });
        
        // Calculate weighted average
        var totalWeight = riskFactors.Sum(rf => rf.Weight);
        var weightedScore = riskFactors.Sum(rf => rf.Score * rf.Weight) / totalWeight;
        
        return Math.Max(0, Math.Min(1, weightedScore));
    }
    
    private SecurityLevel DetermineRequiredSecurityLevel(SessionContext session)
    {
        if (session.SecurityContext.RiskScore > 0.8)
            return SecurityLevel.High;
        else if (session.SecurityContext.RiskScore > 0.5)
            return SecurityLevel.Medium;
        else
            return SecurityLevel.Low;
    }
    
    private bool ValidateSessionData(SessionContext session)
    {
        // Validate required fields
        if (string.IsNullOrEmpty(session.SessionId) || 
            string.IsNullOrEmpty(session.UserId) ||
            session.CreatedAt == DateTime.MinValue)
        {
            return false;
        }
        
        // Validate timestamps
        if (session.CreatedAt > DateTime.UtcNow ||
            session.ExpiresAt <= session.CreatedAt ||
            session.MaxExpiresAt <= session.ExpiresAt)
        {
            return false;
        }
        
        return true;
    }
    
    private async Task<bool> DetectIpAddressAnomalyAsync(SessionContext session)
    {
        var cacheKey = $"user_ips:{session.UserId}";
        var knownIps = await GetCachedUserIpsAsync(cacheKey);
        
        if (!knownIps.Contains(session.IpAddress))
        {
            // New IP address - check if it's suspicious
            var ipInfo = await _geolocationService.GetIpInfoAsync(session.IpAddress);
            
            if (ipInfo.IsProxy || ipInfo.IsTor || ipInfo.IsSuspicious)
            {
                return true;
            }
            
            // Add to known IPs
            knownIps.Add(session.IpAddress);
            await CacheUserIpsAsync(cacheKey, knownIps);
        }
        
        return false;
    }
    
    private bool DetectUserAgentChange(SessionContext session)
    {
        // In a real implementation, you'd check against previous user agents
        // This is a simplified version
        return false;
    }
    
    private async Task<bool> DetectGeographicalAnomalyAsync(SessionContext session)
    {
        try
        {
            var currentLocation = await _geolocationService.GetLocationAsync(session.IpAddress);
            var lastKnownLocation = await GetLastKnownLocationAsync(session.UserId);
            
            if (lastKnownLocation != null)
            {
                var distance = CalculateDistance(currentLocation, lastKnownLocation);
                var timeDiff = DateTime.UtcNow - session.CreatedAt;
                
                // Check if travel time is physically impossible
                var maxPossibleSpeed = 1000; // km/h (commercial flight)
                var maxPossibleDistance = maxPossibleSpeed * timeDiff.TotalHours;
                
                if (distance > maxPossibleDistance)
                {
                    return true;
                }
            }
            
            await UpdateLastKnownLocationAsync(session.UserId, currentLocation);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error detecting geographical anomaly");
            return false;
        }
    }
    
    private async Task<bool> DetectUnusualAccessPatternsAsync(SessionContext session)
    {
        // Implement behavioral analysis
        // Check for unusual times, frequency, etc.
        return false;
    }
    
    private bool DetectSessionReplayAttack(SessionContext session)
    {
        var cacheKey = $"session_nonce:{session.SessionId}";
        
        if (_cache.TryGetValue(cacheKey, out _))
        {
            return true; // Potential replay
        }
        
        _cache.Set(cacheKey, true, TimeSpan.FromMinutes(5));
        return false;
    }
    
    // Helper methods would be implemented here...
    private async Task<double> GetIpReputationRiskAsync(string ipAddress) => 0.1;
    private double CalculateTimeBasedRisk(DateTime createdAt) => 0.1;
    private double CalculateDeviceRisk(string deviceFingerprint) => 0.1;
    private async Task<double> CalculateGeographicRiskAsync(string ipAddress, string userId) => 0.1;
    private async Task<HashSet<string>> GetCachedUserIpsAsync(string cacheKey) => new HashSet<string>();
    private async Task CacheUserIpsAsync(string cacheKey, HashSet<string> ips) { }
    private async Task<GeoLocation> GetLastKnownLocationAsync(string userId) => null;
    private async Task UpdateLastKnownLocationAsync(string userId, GeoLocation location) { }
    private double CalculateDistance(GeoLocation loc1, GeoLocation loc2) => 0;
}
```

### 3. Session Middleware

```csharp
public class SessionManagementMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IAdvancedSessionService _sessionService;
    private readonly ILogger<SessionManagementMiddleware> _logger;
    private readonly SessionConfiguration _config;
    
    public SessionManagementMiddleware(
        RequestDelegate next,
        IAdvancedSessionService sessionService,
        ILogger<SessionManagementMiddleware> logger,
        IOptions<SessionConfiguration> config)
    {
        _next = next;
        _sessionService = sessionService;
        _logger = logger;
        _config = config.Value;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Skip session validation for certain paths
        if (ShouldSkipSessionValidation(context.Request.Path))
        {
            await _next(context);
            return;
        }
        
        var sessionId = ExtractSessionId(context);
        
        if (!string.IsNullOrEmpty(sessionId))
        {
            var session = await _sessionService.ValidateSessionAsync(sessionId);
            
            if (session != null)
            {
                // Attach session to context
                context.Items["Session"] = session;
                context.Items["SessionId"] = session.SessionId;
                context.Items["UserId"] = session.UserId;
                
                // Update session activity
                await UpdateSessionActivity(context, session);
                
                // Check for session warnings
                await CheckSessionWarnings(context, session);
            }
            else
            {
                // Session invalid - clear session cookie
                ClearSessionCookie(context);
                
                // Redirect to login if required
                if (RequiresAuthentication(context.Request.Path))
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Session expired or invalid");
                    return;
                }
            }
        }
        else if (RequiresAuthentication(context.Request.Path))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Authentication required");
            return;
        }
        
        await _next(context);
    }
    
    private string ExtractSessionId(HttpContext context)
    {
        // Try multiple sources for session ID
        
        // 1. Authorization header (Bearer token)
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
        {
            return authHeader.Substring("Bearer ".Length);
        }
        
        // 2. Session cookie
        if (context.Request.Cookies.TryGetValue(_config.SessionCookieName, out var cookieValue))
        {
            return cookieValue;
        }
        
        // 3. Custom header
        var sessionHeader = context.Request.Headers["X-Session-Id"].FirstOrDefault();
        if (!string.IsNullOrEmpty(sessionHeader))
        {
            return sessionHeader;
        }
        
        return null;
    }
    
    private async Task UpdateSessionActivity(HttpContext context, SessionContext session)
    {
        // Update last accessed time and other activity metrics
        session.LastAccessedAt = DateTime.UtcNow;
        session.RequestCount++;
        
        // Track endpoint access
        var endpoint = $"{context.Request.Method} {context.Request.Path}";
        if (session.Metadata.ContainsKey("last_endpoints"))
        {
            var endpoints = (List<string>)session.Metadata["last_endpoints"];
            endpoints.Insert(0, endpoint);
            if (endpoints.Count > 10) // Keep last 10 endpoints
            {
                endpoints.RemoveAt(10);
            }
        }
        else
        {
            session.Metadata["last_endpoints"] = new List<string> { endpoint };
        }
        
        // Update session in background
        _ = Task.Run(async () =>
        {
            try
            {
                await _sessionService.RefreshSessionAsync(session.SessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating session activity for {SessionId}", session.SessionId);
            }
        });
    }
    
    private async Task CheckSessionWarnings(HttpContext context, SessionContext session)
    {
        var now = DateTime.UtcNow;
        
        // Check if session is close to expiring
        var timeToExpiration = session.ExpiresAt - now;
        if (timeToExpiration.TotalMinutes <= _config.ExpirationWarningMinutes)
        {
            context.Response.Headers.Add("X-Session-Warning", "Session expiring soon");
            context.Response.Headers.Add("X-Session-Expires-In", timeToExpiration.TotalSeconds.ToString());
        }
        
        // Check if session is close to maximum duration
        var timeToMaxExpiration = session.MaxExpiresAt - now;
        if (timeToMaxExpiration.TotalMinutes <= _config.MaxDurationWarningMinutes)
        {
            context.Response.Headers.Add("X-Session-Max-Warning", "Session approaching maximum duration");
        }
        
        // Check for concurrent sessions
        var userSessions = await _sessionService.GetUserSessionsAsync(session.UserId);
        if (userSessions.Count > 1)
        {
            context.Response.Headers.Add("X-Concurrent-Sessions", userSessions.Count.ToString());
        }
    }
    
    private void ClearSessionCookie(HttpContext context)
    {
        context.Response.Cookies.Delete(_config.SessionCookieName);
    }
    
    private bool ShouldSkipSessionValidation(PathString path)
    {
        var skipPaths = new[] { "/health", "/metrics", "/api/auth/login", "/api/auth/register" };
        return skipPaths.Any(skipPath => path.StartsWithSegments(skipPath));
    }
    
    private bool RequiresAuthentication(PathString path)
    {
        var publicPaths = new[] { "/health", "/metrics", "/api/public", "/api/auth" };
        return !publicPaths.Any(publicPath => path.StartsWithSegments(publicPath));
    }
}
```

### 4. Session Management Controller

```csharp
[ApiController]
[Route("api/session")]
[Authorize]
public class SessionManagementController : ControllerBase
{
    private readonly IAdvancedSessionService _sessionService;
    private readonly ILogger<SessionManagementController> _logger;
    
    public SessionManagementController(
        IAdvancedSessionService sessionService,
        ILogger<SessionManagementController> logger)
    {
        _sessionService = sessionService;
        _logger = logger;
    }
    
    [HttpGet("current")]
    public async Task<IActionResult> GetCurrentSession()
    {
        var sessionId = HttpContext.Items["SessionId"]?.ToString();
        
        if (string.IsNullOrEmpty(sessionId))
            return BadRequest("No active session");
        
        var session = await _sessionService.GetSessionAsync(sessionId);
        
        if (session == null)
            return NotFound("Session not found");
        
        var sessionInfo = new
        {
            session.SessionId,
            session.CreatedAt,
            session.LastAccessedAt,
            session.ExpiresAt,
            session.MaxExpiresAt,
            session.IpAddress,
            session.UserAgent,
            session.AuthenticationMethod,
            session.SecurityLevel,
            session.RequestCount,
            IsExpiringSoon = (session.ExpiresAt - DateTime.UtcNow).TotalMinutes <= 30
        };
        
        return Ok(sessionInfo);
    }
    
    [HttpGet("all")]
    public async Task<IActionResult> GetAllUserSessions()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
            return BadRequest("User ID not found");
        
        var sessions = await _sessionService.GetUserSessionsAsync(userId);
        
        var sessionInfos = sessions.Select(s => new
        {
            s.SessionId,
            s.CreatedAt,
            s.LastAccessedAt,
            s.IpAddress,
            s.UserAgent,
            s.AuthenticationMethod,
            IsCurrent = s.SessionId == HttpContext.Items["SessionId"]?.ToString()
        });
        
        return Ok(new { Sessions = sessionInfos });
    }
    
    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshSession()
    {
        var sessionId = HttpContext.Items["SessionId"]?.ToString();
        
        if (string.IsNullOrEmpty(sessionId))
            return BadRequest("No active session");
        
        var result = await _sessionService.RefreshSessionAsync(sessionId);
        
        if (result)
        {
            var session = await _sessionService.GetSessionAsync(sessionId);
            return Ok(new 
            { 
                Message = "Session refreshed successfully",
                ExpiresAt = session?.ExpiresAt
            });
        }
        
        return BadRequest("Failed to refresh session");
    }
    
    [HttpPost("terminate/{sessionId}")]
    public async Task<IActionResult> TerminateSession(string sessionId)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        // Verify session belongs to current user
        var userSessions = await _sessionService.GetUserSessionsAsync(userId);
        var sessionToTerminate = userSessions.FirstOrDefault(s => s.SessionId == sessionId);
        
        if (sessionToTerminate == null)
            return NotFound("Session not found or does not belong to current user");
        
        var result = await _sessionService.TerminateSessionAsync(sessionId);
        
        if (result)
            return Ok(new { Message = "Session terminated successfully" });
        
        return BadRequest("Failed to terminate session");
    }
    
    [HttpPost("terminate-all-others")]
    public async Task<IActionResult> TerminateAllOtherSessions()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var currentSessionId = HttpContext.Items["SessionId"]?.ToString();
        
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(currentSessionId))
            return BadRequest("Invalid session context");
        
        var result = await _sessionService.TerminateAllSessionsExceptCurrentAsync(userId, currentSessionId);
        
        if (result)
            return Ok(new { Message = "All other sessions terminated successfully" });
        
        return BadRequest("Failed to terminate other sessions");
    }
    
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var sessionId = HttpContext.Items["SessionId"]?.ToString();
        
        if (!string.IsNullOrEmpty(sessionId))
        {
            await _sessionService.TerminateSessionAsync(sessionId);
        }
        
        // Clear session cookie
        Response.Cookies.Delete("SessionId");
        
        return Ok(new { Message = "Logged out successfully" });
    }
    
    [HttpGet("statistics")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> GetSessionStatistics()
    {
        var statistics = await _sessionService.GetSessionStatisticsAsync();
        return Ok(statistics);
    }
    
    [HttpPost("cleanup")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> CleanupExpiredSessions()
    {
        await _sessionService.CleanupExpiredSessionsAsync();
        return Ok(new { Message = "Session cleanup completed" });
    }
}
```

## Security Best Practices

### 1. Session Configuration

```csharp
public class SessionConfiguration
{
    public TimeSpan SessionTimeout { get; set; } = TimeSpan.FromMinutes(30);
    public TimeSpan MaxSessionDuration { get; set; } = TimeSpan.FromHours(8);
    public bool SlidingExpiration { get; set; } = true;
    public int MaxConcurrentSessions { get; set; } = 5;
    public ConcurrentSessionPolicy ConcurrentSessionPolicy { get; set; } = ConcurrentSessionPolicy.TerminateOldest;
    public bool RotateSessionIdOnRefresh { get; set; } = true;
    public string SessionCookieName { get; set; } = "SessionId";
    public bool SecureCookiesOnly { get; set; } = true;
    public bool HttpOnlyCookies { get; set; } = true;
    public SameSiteMode SameSiteMode { get; set; } = SameSiteMode.Strict;
    public int ExpirationWarningMinutes { get; set; } = 5;
    public int MaxDurationWarningMinutes { get; set; } = 30;
}

public enum ConcurrentSessionPolicy
{
    Allow,
    TerminateOldest,
    TerminateAll,
    RejectNew
}

public enum SecurityLevel
{
    Low,
    Medium,
    High,
    Critical
}
```

### 2. Session Models

```csharp
public class SessionContext
{
    public string SessionId { get; set; }
    public string UserId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime LastAccessedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime MaxExpiresAt { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public string DeviceFingerprint { get; set; }
    public bool IsSecure { get; set; }
    public bool IsHttpOnly { get; set; }
    public SameSiteMode SameSite { get; set; }
    public string AuthenticationMethod { get; set; }
    public SecurityLevel SecurityLevel { get; set; }
    public int RequestCount { get; set; }
    public string Signature { get; set; }
    public string Entropy { get; set; }
    public byte[] EncryptedMetadata { get; set; }
    public Dictionary<string, object> Metadata { get; set; } = new();
    public SessionSecurityContext SecurityContext { get; set; }
}

public class SessionSecurityContext
{
    public string CreationFingerprint { get; set; }
    public double RiskScore { get; set; }
    public SecurityLevel RequiredSecurityLevel { get; set; }
}

public class SessionOptions
{
    public TimeSpan? SessionTimeout { get; set; }
    public TimeSpan? MaxSessionDuration { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public string DeviceFingerprint { get; set; }
    public bool IsSecure { get; set; } = true;
    public bool IsHttpOnly { get; set; } = true;
    public SameSiteMode SameSite { get; set; } = SameSiteMode.Strict;
    public string AuthenticationMethod { get; set; }
    public SecurityLevel SecurityLevel { get; set; } = SecurityLevel.Medium;
    public Dictionary<string, object> Metadata { get; set; }
}

public class SessionStatistics
{
    public int ActiveSessions { get; set; }
    public int TotalSessions { get; set; }
    public int ExpiredSessions { get; set; }
    public double AverageSessionDuration { get; set; }
    public int ConcurrentUsers { get; set; }
    public Dictionary<string, int> SessionsBySecurityLevel { get; set; } = new();
}
```

## Testing Strategies

### 1. Session Security Tests

```csharp
[TestFixture]
public class SessionSecurityTests
{
    private IAdvancedSessionService _sessionService;
    private Mock<ISessionSecurityService> _mockSecurityService;
    
    [SetUp]
    public void Setup()
    {
        _mockSecurityService = new Mock<ISessionSecurityService>();
        // Setup session service with mocked dependencies
    }
    
    [Test]
    public async Task CreateSession_ShouldGenerateSecureSessionId()
    {
        var session = await _sessionService.CreateSessionAsync("user123");
        
        Assert.That(session.SessionId, Is.Not.Null);
        Assert.That(session.SessionId.Length, Is.GreaterThan(32));
        Assert.That(session.Signature, Is.Not.Null);
    }
    
    [Test]
    public async Task ValidateSession_WithTamperedSignature_ShouldFail()
    {
        var session = await _sessionService.CreateSessionAsync("user123");
        session.Signature = "tampered_signature";
        
        _mockSecurityService.Setup(x => x.ValidateSessionIntegrityAsync(It.IsAny<SessionContext>()))
                          .ReturnsAsync(false);
        
        var validatedSession = await _sessionService.ValidateSessionAsync(session.SessionId);
        
        Assert.That(validatedSession, Is.Null);
    }
}
```

---
**Next**: Continue with security best practices