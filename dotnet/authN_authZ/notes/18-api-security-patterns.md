# API Security Patterns

## Overview
API security patterns encompass the comprehensive strategies, techniques, and implementations used to secure REST APIs, GraphQL APIs, and other web services. This includes authentication, authorization, input validation, rate limiting, encryption, and monitoring patterns specifically designed for API endpoints.

## Core Concepts

### 1. API Security Fundamentals

#### Authentication Patterns
- **Bearer Token Authentication**: JWT, opaque tokens
- **API Key Authentication**: Simple key-based access
- **OAuth 2.0 Flows**: Client credentials, authorization code
- **Mutual TLS (mTLS)**: Certificate-based authentication
- **HMAC Signatures**: Request signing for integrity

#### Authorization Patterns
- **Scope-based Authorization**: OAuth 2.0 scopes
- **Resource-based Authorization**: Per-resource permissions
- **Role-based API Access**: Role-driven endpoint access
- **Attribute-based Policies**: Context-aware decisions

#### Security Headers
- **CORS (Cross-Origin Resource Sharing)**: Cross-domain access control
- **Content Security Policy**: XSS prevention
- **HSTS (HTTP Strict Transport Security)**: HTTPS enforcement
- **Rate Limiting Headers**: Usage quotas and limits

### 2. API Threat Landscape

#### Common API Vulnerabilities
- **Broken Authentication**: Weak or missing authentication
- **Excessive Data Exposure**: Over-permissive responses
- **Injection Attacks**: SQL, NoSQL, command injection
- **Broken Authorization**: Missing or flawed access controls
- **Security Misconfiguration**: Default or weak configurations
- **Rate Limiting Issues**: DoS and resource exhaustion

#### OWASP API Security Top 10
1. Broken Object Level Authorization
2. Broken User Authentication
3. Excessive Data Exposure
4. Lack of Resources & Rate Limiting
5. Broken Function Level Authorization
6. Mass Assignment
7. Security Misconfiguration
8. Injection
9. Improper Assets Management
10. Insufficient Logging & Monitoring

## .NET API Security Implementation

### 1. Comprehensive API Security Middleware

```csharp
public class ApiSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IApiSecurityService _securityService;
    private readonly ILogger<ApiSecurityMiddleware> _logger;
    private readonly ApiSecurityOptions _options;
    
    public ApiSecurityMiddleware(
        RequestDelegate next,
        IApiSecurityService securityService,
        ILogger<ApiSecurityMiddleware> logger,
        IOptions<ApiSecurityOptions> options)
    {
        _next = next;
        _securityService = securityService;
        _logger = logger;
        _options = options.Value;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        var securityContext = new ApiSecurityContext(context);
        
        try
        {
            // 1. Request validation and sanitization
            if (!await ValidateRequestAsync(securityContext))
            {
                await WriteSecurityErrorResponse(context, "Invalid request", 400);
                return;
            }
            
            // 2. Rate limiting
            if (!await CheckRateLimitAsync(securityContext))
            {
                await WriteSecurityErrorResponse(context, "Rate limit exceeded", 429);
                return;
            }
            
            // 3. Authentication validation
            if (!await ValidateAuthenticationAsync(securityContext))
            {
                await WriteSecurityErrorResponse(context, "Authentication required", 401);
                return;
            }
            
            // 4. Authorization checks
            if (!await ValidateAuthorizationAsync(securityContext))
            {
                await WriteSecurityErrorResponse(context, "Access denied", 403);
                return;
            }
            
            // 5. Input validation and sanitization
            await SanitizeInputAsync(securityContext);
            
            // 6. Add security headers
            AddSecurityHeaders(context);
            
            // 7. Log security event
            await LogSecurityEventAsync(securityContext, "API_ACCESS_GRANTED");
            
            // Continue to next middleware
            await _next(context);
            
            // 8. Response filtering (after processing)
            await FilterResponseAsync(securityContext);
        }
        catch (SecurityException ex)
        {
            _logger.LogWarning(ex, "API security violation from {IP}", context.Connection.RemoteIpAddress);
            await WriteSecurityErrorResponse(context, "Security violation", 403);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "API security middleware error");
            await WriteSecurityErrorResponse(context, "Security processing error", 500);
        }
    }
    
    private async Task<bool> ValidateRequestAsync(ApiSecurityContext securityContext)
    {
        var request = securityContext.HttpContext.Request;
        
        // Validate HTTP method
        if (!_options.AllowedMethods.Contains(request.Method.ToUpper()))
        {
            _logger.LogWarning("Blocked request with method {Method}", request.Method);
            return false;
        }
        
        // Validate Content-Type for POST/PUT requests
        if ((request.Method == "POST" || request.Method == "PUT") && 
            !string.IsNullOrEmpty(request.ContentType))
        {
            var contentType = request.ContentType.Split(';')[0].Trim();
            if (!_options.AllowedContentTypes.Contains(contentType))
            {
                _logger.LogWarning("Blocked request with Content-Type {ContentType}", contentType);
                return false;
            }
        }
        
        // Validate request size
        if (request.ContentLength > _options.MaxRequestSize)
        {
            _logger.LogWarning("Blocked oversized request: {Size} bytes", request.ContentLength);
            return false;
        }
        
        // Check for suspicious patterns in URL
        if (ContainsSuspiciousPatterns(request.Path.Value))
        {
            _logger.LogWarning("Blocked request with suspicious URL pattern: {Path}", request.Path);
            return false;
        }
        
        return true;
    }
    
    private async Task<bool> CheckRateLimitAsync(ApiSecurityContext securityContext)
    {
        return await _securityService.CheckRateLimitAsync(securityContext);
    }
    
    private async Task<bool> ValidateAuthenticationAsync(ApiSecurityContext securityContext)
    {
        var context = securityContext.HttpContext;
        
        // Skip authentication for public endpoints
        if (IsPublicEndpoint(context.Request.Path))
            return true;
        
        return await _securityService.ValidateAuthenticationAsync(securityContext);
    }
    
    private async Task<bool> ValidateAuthorizationAsync(ApiSecurityContext securityContext)
    {
        return await _securityService.ValidateAuthorizationAsync(securityContext);
    }
    
    private async Task SanitizeInputAsync(ApiSecurityContext securityContext)
    {
        await _securityService.SanitizeInputAsync(securityContext);
    }
    
    private void AddSecurityHeaders(HttpContext context)
    {
        var response = context.Response;
        
        // Security headers
        response.Headers.Add("X-Content-Type-Options", "nosniff");
        response.Headers.Add("X-Frame-Options", "DENY");
        response.Headers.Add("X-XSS-Protection", "1; mode=block");
        response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
        response.Headers.Add("Cache-Control", "no-store, no-cache, must-revalidate");
        
        // API versioning header
        response.Headers.Add("API-Version", _options.ApiVersion);
        
        // Rate limiting headers
        if (context.Items.ContainsKey("RateLimit-Remaining"))
        {
            response.Headers.Add("X-RateLimit-Remaining", context.Items["RateLimit-Remaining"].ToString());
            response.Headers.Add("X-RateLimit-Reset", context.Items["RateLimit-Reset"].ToString());
        }
        
        // CORS headers (if enabled)
        if (_options.EnableCors)
        {
            response.Headers.Add("Access-Control-Allow-Origin", _options.AllowedOrigins);
            response.Headers.Add("Access-Control-Allow-Methods", string.Join(", ", _options.AllowedMethods));
            response.Headers.Add("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept");
        }
    }
    
    private async Task FilterResponseAsync(ApiSecurityContext securityContext)
    {
        await _securityService.FilterResponseAsync(securityContext);
    }
    
    private async Task LogSecurityEventAsync(ApiSecurityContext securityContext, string eventType)
    {
        await _securityService.LogSecurityEventAsync(securityContext, eventType);
    }
    
    private bool ContainsSuspiciousPatterns(string path)
    {
        var suspiciousPatterns = new[]
        {
            "../", "./", "\\", "%2e%2e", "%2f", "%5c",
            "<script", "javascript:", "vbscript:",
            "union select", "drop table", "exec(",
            "cmd.exe", "powershell"
        };
        
        var lowerPath = path.ToLowerInvariant();
        return suspiciousPatterns.Any(pattern => lowerPath.Contains(pattern));
    }
    
    private bool IsPublicEndpoint(PathString path)
    {
        var publicPaths = new[] { "/health", "/metrics", "/swagger", "/api/public" };
        return publicPaths.Any(publicPath => path.StartsWithSegments(publicPath));
    }
    
    private async Task WriteSecurityErrorResponse(HttpContext context, string message, int statusCode)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        
        var errorResponse = new
        {
            Error = message,
            StatusCode = statusCode,
            Timestamp = DateTime.UtcNow,
            RequestId = context.TraceIdentifier
        };
        
        await context.Response.WriteAsync(JsonSerializer.Serialize(errorResponse));
    }
}

public class ApiSecurityContext
{
    public HttpContext HttpContext { get; }
    public string ClientId { get; set; }
    public string UserId { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public string Endpoint { get; set; }
    public Dictionary<string, object> Metadata { get; set; } = new();
    
    public ApiSecurityContext(HttpContext httpContext)
    {
        HttpContext = httpContext;
        IpAddress = httpContext.Connection.RemoteIpAddress?.ToString();
        UserAgent = httpContext.Request.Headers["User-Agent"].FirstOrDefault();
        Endpoint = $"{httpContext.Request.Method} {httpContext.Request.Path}";
        
        // Extract client/user info from claims
        if (httpContext.User.Identity.IsAuthenticated)
        {
            UserId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            ClientId = httpContext.User.FindFirst("client_id")?.Value;
        }
    }
}

public class ApiSecurityOptions
{
    public string ApiVersion { get; set; } = "1.0";
    public List<string> AllowedMethods { get; set; } = new() { "GET", "POST", "PUT", "DELETE", "PATCH" };
    public List<string> AllowedContentTypes { get; set; } = new() { "application/json", "application/xml" };
    public long MaxRequestSize { get; set; } = 1_000_000; // 1MB
    public bool EnableCors { get; set; } = false;
    public string AllowedOrigins { get; set; } = "*";
    public bool EnableRateLimit { get; set; } = true;
    public bool EnableInputSanitization { get; set; } = true;
}
```

### 2. Advanced Rate Limiting Service

```csharp
public interface IRateLimitingService
{
    Task<RateLimitResult> CheckRateLimitAsync(string identifier, string endpoint, RateLimitPolicy policy);
    Task<RateLimitResult> CheckRateLimitAsync(ApiSecurityContext context);
    Task ResetRateLimitAsync(string identifier, string endpoint);
    Task<Dictionary<string, RateLimitStatus>> GetRateLimitStatusAsync(string identifier);
}

public class AdvancedRateLimitingService : IRateLimitingService
{
    private readonly IDistributedCache _cache;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AdvancedRateLimitingService> _logger;
    private readonly Dictionary<string, RateLimitPolicy> _policies;
    
    public AdvancedRateLimitingService(
        IDistributedCache cache,
        IConfiguration configuration,
        ILogger<AdvancedRateLimitingService> logger)
    {
        _cache = cache;
        _configuration = configuration;
        _logger = logger;
        _policies = LoadRateLimitPolicies();
    }
    
    public async Task<RateLimitResult> CheckRateLimitAsync(ApiSecurityContext context)
    {
        var identifier = GetRateLimitIdentifier(context);
        var policy = GetRateLimitPolicy(context);
        
        return await CheckRateLimitAsync(identifier, context.Endpoint, policy);
    }
    
    public async Task<RateLimitResult> CheckRateLimitAsync(string identifier, string endpoint, RateLimitPolicy policy)
    {
        try
        {
            var windows = new List<Task<bool>>();
            
            // Check each time window
            foreach (var window in policy.Windows)
            {
                windows.Add(CheckWindowAsync(identifier, endpoint, window));
            }
            
            var results = await Task.WhenAll(windows);
            
            if (results.Any(r => !r))
            {
                _logger.LogWarning("Rate limit exceeded for {Identifier} on {Endpoint}", identifier, endpoint);
                
                return new RateLimitResult
                {
                    IsAllowed = false,
                    RetryAfter = GetRetryAfter(policy),
                    RemainingRequests = 0
                };
            }
            
            // All windows passed, increment counters
            var remainingRequests = await IncrementCountersAsync(identifier, endpoint, policy);
            
            return new RateLimitResult
            {
                IsAllowed = true,
                RemainingRequests = remainingRequests,
                RetryAfter = null
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking rate limit for {Identifier}", identifier);
            
            // Fail open in case of errors (configurable)
            return new RateLimitResult { IsAllowed = true };
        }
    }
    
    private async Task<bool> CheckWindowAsync(string identifier, string endpoint, RateLimitWindow window)
    {
        var key = $"ratelimit:{identifier}:{endpoint}:{window.Duration.TotalSeconds}";
        var currentCount = await GetCurrentCountAsync(key);
        
        return currentCount < window.MaxRequests;
    }
    
    private async Task<int> IncrementCountersAsync(string identifier, string endpoint, RateLimitPolicy policy)
    {
        var minRemaining = int.MaxValue;
        
        foreach (var window in policy.Windows)
        {
            var key = $"ratelimit:{identifier}:{endpoint}:{window.Duration.TotalSeconds}";
            var newCount = await IncrementCounterAsync(key, window.Duration);
            var remaining = window.MaxRequests - newCount;
            
            if (remaining < minRemaining)
                minRemaining = remaining;
        }
        
        return Math.Max(0, minRemaining);
    }
    
    private async Task<int> GetCurrentCountAsync(string key)
    {
        var value = await _cache.GetStringAsync(key);
        return int.TryParse(value, out var count) ? count : 0;
    }
    
    private async Task<int> IncrementCounterAsync(string key, TimeSpan duration)
    {
        var script = @"
            local current = redis.call('GET', KEYS[1])
            if current == false then
                redis.call('SET', KEYS[1], 1)
                redis.call('EXPIRE', KEYS[1], ARGV[1])
                return 1
            else
                return redis.call('INCR', KEYS[1])
            end
        ";
        
        // This would require Redis with Lua scripting
        // For simplicity, using basic increment
        var currentValue = await GetCurrentCountAsync(key);
        var newValue = currentValue + 1;
        
        await _cache.SetStringAsync(key, newValue.ToString(), new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = duration
        });
        
        return newValue;
    }
    
    private string GetRateLimitIdentifier(ApiSecurityContext context)
    {
        // Composite identifier based on user, client, and IP
        var identifiers = new List<string>();
        
        if (!string.IsNullOrEmpty(context.UserId))
            identifiers.Add($"user:{context.UserId}");
        
        if (!string.IsNullOrEmpty(context.ClientId))
            identifiers.Add($"client:{context.ClientId}");
        
        if (!string.IsNullOrEmpty(context.IpAddress))
            identifiers.Add($"ip:{context.IpAddress}");
        
        return identifiers.Any() ? string.Join(",", identifiers) : $"anonymous:{context.IpAddress}";
    }
    
    private RateLimitPolicy GetRateLimitPolicy(ApiSecurityContext context)
    {
        // Get policy based on endpoint pattern
        foreach (var kvp in _policies)
        {
            if (context.Endpoint.Contains(kvp.Key))
                return kvp.Value;
        }
        
        // Default policy
        return _policies.GetValueOrDefault("default", new RateLimitPolicy
        {
            Windows = new List<RateLimitWindow>
            {
                new() { Duration = TimeSpan.FromMinutes(1), MaxRequests = 100 },
                new() { Duration = TimeSpan.FromHours(1), MaxRequests = 1000 }
            }
        });
    }
    
    private Dictionary<string, RateLimitPolicy> LoadRateLimitPolicies()
    {
        return new Dictionary<string, RateLimitPolicy>
        {
            ["default"] = new()
            {
                Windows = new List<RateLimitWindow>
                {
                    new() { Duration = TimeSpan.FromMinutes(1), MaxRequests = 100 },
                    new() { Duration = TimeSpan.FromHours(1), MaxRequests = 1000 }
                }
            },
            ["/api/auth"] = new()
            {
                Windows = new List<RateLimitWindow>
                {
                    new() { Duration = TimeSpan.FromMinutes(1), MaxRequests = 5 },
                    new() { Duration = TimeSpan.FromHours(1), MaxRequests = 20 }
                }
            },
            ["/api/upload"] = new()
            {
                Windows = new List<RateLimitWindow>
                {
                    new() { Duration = TimeSpan.FromMinutes(1), MaxRequests = 10 },
                    new() { Duration = TimeSpan.FromHours(1), MaxRequests = 100 }
                }
            }
        };
    }
    
    private TimeSpan GetRetryAfter(RateLimitPolicy policy)
    {
        return policy.Windows.Min(w => w.Duration);
    }
    
    public async Task ResetRateLimitAsync(string identifier, string endpoint)
    {
        // Implementation to reset rate limits for debugging/admin purposes
        _logger.LogInformation("Rate limit reset for {Identifier} on {Endpoint}", identifier, endpoint);
    }
    
    public async Task<Dictionary<string, RateLimitStatus>> GetRateLimitStatusAsync(string identifier)
    {
        // Implementation to get current rate limit status
        return new Dictionary<string, RateLimitStatus>();
    }
}

public class RateLimitPolicy
{
    public List<RateLimitWindow> Windows { get; set; } = new();
}

public class RateLimitWindow
{
    public TimeSpan Duration { get; set; }
    public int MaxRequests { get; set; }
}

public class RateLimitResult
{
    public bool IsAllowed { get; set; }
    public int RemainingRequests { get; set; }
    public TimeSpan? RetryAfter { get; set; }
}

public class RateLimitStatus
{
    public int CurrentRequests { get; set; }
    public int MaxRequests { get; set; }
    public TimeSpan WindowDuration { get; set; }
    public DateTime ResetTime { get; set; }
}
```

### 3. Input Validation and Sanitization Service

```csharp
public interface IApiInputValidationService
{
    Task<ValidationResult> ValidateRequestAsync(HttpContext context);
    Task<SanitizationResult> SanitizeInputAsync(HttpContext context);
    Task<bool> ValidateJsonSchemaAsync(string json, string schemaName);
}

public class ApiInputValidationService : IApiInputValidationService
{
    private readonly ILogger<ApiInputValidationService> _logger;
    private readonly Dictionary<string, JsonSchema> _schemas;
    private readonly List<IInputValidator> _validators;
    private readonly List<IInputSanitizer> _sanitizers;
    
    public ApiInputValidationService(ILogger<ApiInputValidationService> logger)
    {
        _logger = logger;
        _schemas = LoadJsonSchemas();
        _validators = InitializeValidators();
        _sanitizers = InitializeSanitizers();
    }
    
    public async Task<ValidationResult> ValidateRequestAsync(HttpContext context)
    {
        var validationResult = new ValidationResult { IsValid = true };
        
        try
        {
            // Validate headers
            var headerValidation = ValidateHeaders(context.Request.Headers);
            if (!headerValidation.IsValid)
            {
                validationResult.IsValid = false;
                validationResult.Errors.AddRange(headerValidation.Errors);
            }
            
            // Validate query parameters
            var queryValidation = ValidateQueryParameters(context.Request.Query);
            if (!queryValidation.IsValid)
            {
                validationResult.IsValid = false;
                validationResult.Errors.AddRange(queryValidation.Errors);
            }
            
            // Validate request body
            if (HasRequestBody(context.Request))
            {
                var bodyValidation = await ValidateRequestBodyAsync(context);
                if (!bodyValidation.IsValid)
                {
                    validationResult.IsValid = false;
                    validationResult.Errors.AddRange(bodyValidation.Errors);
                }
            }
            
            // Custom validation rules
            foreach (var validator in _validators)
            {
                var customValidation = await validator.ValidateAsync(context);
                if (!customValidation.IsValid)
                {
                    validationResult.IsValid = false;
                    validationResult.Errors.AddRange(customValidation.Errors);
                }
            }
            
            return validationResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during request validation");
            return new ValidationResult 
            { 
                IsValid = false, 
                Errors = new List<string> { "Validation error occurred" } 
            };
        }
    }
    
    public async Task<SanitizationResult> SanitizeInputAsync(HttpContext context)
    {
        var sanitizationResult = new SanitizationResult { Success = true };
        
        try
        {
            // Sanitize headers
            SanitizeHeaders(context.Request.Headers);
            
            // Sanitize query parameters
            // Note: Query parameters are read-only, so we'd store sanitized values separately
            var sanitizedQuery = SanitizeQueryParameters(context.Request.Query);
            context.Items["SanitizedQuery"] = sanitizedQuery;
            
            // Sanitize request body
            if (HasRequestBody(context.Request))
            {
                var sanitizedBody = await SanitizeRequestBodyAsync(context);
                context.Items["SanitizedBody"] = sanitizedBody;
            }
            
            // Apply custom sanitizers
            foreach (var sanitizer in _sanitizers)
            {
                await sanitizer.SanitizeAsync(context);
            }
            
            return sanitizationResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during input sanitization");
            return new SanitizationResult 
            { 
                Success = false, 
                Error = "Sanitization error occurred" 
            };
        }
    }
    
    private ValidationResult ValidateHeaders(IHeaderDictionary headers)
    {
        var result = new ValidationResult { IsValid = true };
        
        // Check for suspicious header values
        foreach (var header in headers)
        {
            if (ContainsMaliciousContent(header.Value))
            {
                result.IsValid = false;
                result.Errors.Add($"Malicious content detected in header: {header.Key}");
                _logger.LogWarning("Malicious header detected: {HeaderName}", header.Key);
            }
            
            // Validate header length
            if (header.Value.ToString().Length > 8192) // 8KB limit
            {
                result.IsValid = false;
                result.Errors.Add($"Header too long: {header.Key}");
            }
        }
        
        return result;
    }
    
    private ValidationResult ValidateQueryParameters(IQueryCollection query)
    {
        var result = new ValidationResult { IsValid = true };
        
        foreach (var param in query)
        {
            // Check parameter name
            if (ContainsMaliciousContent(param.Key))
            {
                result.IsValid = false;
                result.Errors.Add($"Malicious parameter name: {param.Key}");
                continue;
            }
            
            // Check parameter values
            foreach (var value in param.Value)
            {
                if (ContainsMaliciousContent(value))
                {
                    result.IsValid = false;
                    result.Errors.Add($"Malicious parameter value in: {param.Key}");
                    break;
                }
                
                // Validate parameter length
                if (value.Length > 1000)
                {
                    result.IsValid = false;
                    result.Errors.Add($"Parameter value too long: {param.Key}");
                    break;
                }
            }
        }
        
        return result;
    }
    
    private async Task<ValidationResult> ValidateRequestBodyAsync(HttpContext context)
    {
        var result = new ValidationResult { IsValid = true };
        
        try
        {
            // Read body content
            context.Request.EnableBuffering();
            var body = await ReadRequestBodyAsync(context.Request);
            
            if (string.IsNullOrEmpty(body))
                return result;
            
            // Check for malicious content
            if (ContainsMaliciousContent(body))
            {
                result.IsValid = false;
                result.Errors.Add("Malicious content detected in request body");
                return result;
            }
            
            // Validate JSON structure if applicable
            if (IsJsonContent(context.Request))
            {
                if (!IsValidJson(body))
                {
                    result.IsValid = false;
                    result.Errors.Add("Invalid JSON format");
                    return result;
                }
                
                // Schema validation
                var endpoint = context.Request.Path.Value;
                if (_schemas.ContainsKey(endpoint))
                {
                    var schemaValidation = await ValidateJsonSchemaAsync(body, endpoint);
                    if (!schemaValidation)
                    {
                        result.IsValid = false;
                        result.Errors.Add("JSON schema validation failed");
                    }
                }
            }
            
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating request body");
            result.IsValid = false;
            result.Errors.Add("Body validation error");
            return result;
        }
    }
    
    private void SanitizeHeaders(IHeaderDictionary headers)
    {
        var headersToRemove = new List<string>();
        var headersToUpdate = new Dictionary<string, StringValues>();
        
        foreach (var header in headers)
        {
            var sanitizedValue = SanitizeString(header.Value);
            if (sanitizedValue != header.Value)
            {
                headersToUpdate[header.Key] = sanitizedValue;
            }
        }
        
        // Apply updates
        foreach (var update in headersToUpdate)
        {
            headers[update.Key] = update.Value;
        }
    }
    
    private Dictionary<string, StringValues> SanitizeQueryParameters(IQueryCollection query)
    {
        var sanitized = new Dictionary<string, StringValues>();
        
        foreach (var param in query)
        {
            var sanitizedValues = param.Value.Select(SanitizeString).ToArray();
            sanitized[SanitizeString(param.Key)] = new StringValues(sanitizedValues);
        }
        
        return sanitized;
    }
    
    private async Task<string> SanitizeRequestBodyAsync(HttpContext context)
    {
        var body = await ReadRequestBodyAsync(context.Request);
        
        if (string.IsNullOrEmpty(body))
            return body;
        
        if (IsJsonContent(context.Request))
        {
            return SanitizeJsonString(body);
        }
        
        return SanitizeString(body);
    }
    
    private string SanitizeString(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;
        
        // HTML encode
        input = System.Web.HttpUtility.HtmlEncode(input);
        
        // Remove or escape dangerous characters
        input = input.Replace("<script", "&lt;script")
                    .Replace("javascript:", "")
                    .Replace("vbscript:", "")
                    .Replace("onload=", "")
                    .Replace("onerror=", "")
                    .Replace("eval(", "")
                    .Replace("exec(", "");
        
        // SQL injection prevention
        input = Regex.Replace(input, @"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)", 
                             "", RegexOptions.IgnoreCase);
        
        return input;
    }
    
    private string SanitizeJsonString(string json)
    {
        try
        {
            // Parse and re-serialize to ensure clean JSON
            var jsonDoc = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(jsonDoc, new JsonSerializerOptions 
            { 
                WriteIndented = false,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
        }
        catch
        {
            return SanitizeString(json);
        }
    }
    
    private bool ContainsMaliciousContent(string content)
    {
        if (string.IsNullOrEmpty(content))
            return false;
        
        var maliciousPatterns = new[]
        {
            @"<script[^>]*>.*?</script>",
            @"javascript:",
            @"vbscript:",
            @"on\w+\s*=",
            @"eval\s*\(",
            @"exec\s*\(",
            @"union\s+select",
            @"drop\s+table",
            @"insert\s+into",
            @"update\s+set",
            @"delete\s+from",
            @"--\s*$",
            @"/\*.*?\*/",
            @"xp_cmdshell",
            @"sp_executesql"
        };
        
        var lowerContent = content.ToLowerInvariant();
        return maliciousPatterns.Any(pattern => 
            Regex.IsMatch(lowerContent, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline));
    }
    
    private bool HasRequestBody(HttpRequest request)
    {
        return request.ContentLength > 0 && 
               (request.Method == "POST" || request.Method == "PUT" || request.Method == "PATCH");
    }
    
    private bool IsJsonContent(HttpRequest request)
    {
        return request.ContentType?.StartsWith("application/json") == true;
    }
    
    private bool IsValidJson(string json)
    {
        try
        {
            JsonDocument.Parse(json);
            return true;
        }
        catch
        {
            return false;
        }
    }
    
    private async Task<string> ReadRequestBodyAsync(HttpRequest request)
    {
        request.Body.Position = 0;
        using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        request.Body.Position = 0;
        return body;
    }
    
    public async Task<bool> ValidateJsonSchemaAsync(string json, string schemaName)
    {
        if (!_schemas.TryGetValue(schemaName, out var schema))
            return true; // No schema defined, assume valid
        
        try
        {
            var jsonDoc = JsonDocument.Parse(json);
            var validationResults = schema.Validate(jsonDoc.RootElement);
            return validationResults.IsValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating JSON schema for {SchemaName}", schemaName);
            return false;
        }
    }
    
    private Dictionary<string, JsonSchema> LoadJsonSchemas()
    {
        // Load JSON schemas for different endpoints
        return new Dictionary<string, JsonSchema>();
    }
    
    private List<IInputValidator> InitializeValidators()
    {
        return new List<IInputValidator>();
    }
    
    private List<IInputSanitizer> InitializeSanitizers()
    {
        return new List<IInputSanitizer>();
    }
}

public class ValidationResult
{
    public bool IsValid { get; set; }
    public List<string> Errors { get; set; } = new();
}

public class SanitizationResult
{
    public bool Success { get; set; }
    public string Error { get; set; }
}

public interface IInputValidator
{
    Task<ValidationResult> ValidateAsync(HttpContext context);
}

public interface IInputSanitizer
{
    Task SanitizeAsync(HttpContext context);
}
```

### 4. API Response Security Filter

```csharp
public class ApiResponseSecurityFilter : IAsyncActionFilter
{
    private readonly IApiResponseFilterService _responseFilter;
    private readonly ILogger<ApiResponseSecurityFilter> _logger;
    
    public ApiResponseSecurityFilter(
        IApiResponseFilterService responseFilter,
        ILogger<ApiResponseSecurityFilter> logger)
    {
        _responseFilter = responseFilter;
        _logger = logger;
    }
    
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var executedContext = await next();
        
        if (executedContext.Result is ObjectResult objectResult)
        {
            try
            {
                // Filter sensitive data from response
                var filteredData = await _responseFilter.FilterResponseDataAsync(
                    objectResult.Value, 
                    context.HttpContext.User,
                    context.ActionDescriptor.AttributeRouteInfo?.Template);
                
                objectResult.Value = filteredData;
                
                // Add response security headers
                AddResponseSecurityHeaders(context.HttpContext);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error filtering API response");
                // Don't fail the request, but log the error
            }
        }
    }
    
    private void AddResponseSecurityHeaders(HttpContext context)
    {
        var response = context.Response;
        
        // Prevent caching of sensitive data
        if (IsSensitiveEndpoint(context.Request.Path))
        {
            response.Headers.Add("Cache-Control", "no-store, no-cache, must-revalidate, private");
            response.Headers.Add("Pragma", "no-cache");
            response.Headers.Add("Expires", "0");
        }
        
        // Content type protection
        response.Headers.Add("X-Content-Type-Options", "nosniff");
        
        // Frame protection
        response.Headers.Add("X-Frame-Options", "DENY");
    }
    
    private bool IsSensitiveEndpoint(PathString path)
    {
        var sensitivePaths = new[] { "/api/users", "/api/admin", "/api/financial" };
        return sensitivePaths.Any(p => path.StartsWithSegments(p));
    }
}

public interface IApiResponseFilterService
{
    Task<object> FilterResponseDataAsync(object data, ClaimsPrincipal user, string endpoint);
}

public class ApiResponseFilterService : IApiResponseFilterService
{
    private readonly ILogger<ApiResponseFilterService> _logger;
    private readonly Dictionary<string, List<string>> _fieldFilters;
    
    public ApiResponseFilterService(ILogger<ApiResponseFilterService> logger)
    {
        _logger = logger;
        _fieldFilters = InitializeFieldFilters();
    }
    
    public async Task<object> FilterResponseDataAsync(object data, ClaimsPrincipal user, string endpoint)
    {
        if (data == null) return null;
        
        try
        {
            // Convert to JSON for manipulation
            var json = JsonSerializer.Serialize(data);
            var jsonDoc = JsonDocument.Parse(json);
            
            // Apply field-level filtering based on user permissions and endpoint
            var filteredJson = FilterJsonData(jsonDoc, user, endpoint);
            
            // Convert back to object
            return JsonSerializer.Deserialize<object>(filteredJson);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error filtering response data for endpoint {Endpoint}", endpoint);
            return data; // Return original data if filtering fails
        }
    }
    
    private string FilterJsonData(JsonDocument jsonDoc, ClaimsPrincipal user, string endpoint)
    {
        // Get fields to filter for this endpoint
        var fieldsToFilter = GetFieldsToFilter(endpoint, user);
        
        if (!fieldsToFilter.Any())
            return jsonDoc.RootElement.GetRawText();
        
        // Create filtered JSON
        var filteredObject = FilterJsonElement(jsonDoc.RootElement, fieldsToFilter);
        
        return JsonSerializer.Serialize(filteredObject);
    }
    
    private object FilterJsonElement(JsonElement element, HashSet<string> fieldsToFilter)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var filteredObj = new Dictionary<string, object>();
                foreach (var property in element.EnumerateObject())
                {
                    if (!fieldsToFilter.Contains(property.Name.ToLowerInvariant()))
                    {
                        filteredObj[property.Name] = FilterJsonElement(property.Value, fieldsToFilter);
                    }
                }
                return filteredObj;
                
            case JsonValueKind.Array:
                var filteredArray = new List<object>();
                foreach (var item in element.EnumerateArray())
                {
                    filteredArray.Add(FilterJsonElement(item, fieldsToFilter));
                }
                return filteredArray;
                
            default:
                return element.GetRawText();
        }
    }
    
    private HashSet<string> GetFieldsToFilter(string endpoint, ClaimsPrincipal user)
    {
        var fieldsToFilter = new HashSet<string>();
        
        // Get base fields to filter for this endpoint
        if (_fieldFilters.TryGetValue(endpoint, out var baseFields))
        {
            foreach (var field in baseFields)
            {
                fieldsToFilter.Add(field.ToLowerInvariant());
            }
        }
        
        // Apply role-based filtering
        if (!user.IsInRole("Administrator"))
        {
            // Non-admin users don't see internal fields
            fieldsToFilter.Add("internalid");
            fieldsToFilter.Add("createdat");
            fieldsToFilter.Add("updatedat");
            fieldsToFilter.Add("version");
        }
        
        if (!user.IsInRole("HR"))
        {
            // Non-HR users don't see personal information
            fieldsToFilter.Add("ssn");
            fieldsToFilter.Add("salary");
            fieldsToFilter.Add("personalphone");
        }
        
        // Apply user-specific filtering
        var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(userId))
        {
            // Users can only see their own sensitive data
            // This logic would depend on the specific data structure
        }
        
        return fieldsToFilter;
    }
    
    private Dictionary<string, List<string>> InitializeFieldFilters()
    {
        return new Dictionary<string, List<string>>
        {
            ["/api/users"] = new List<string> { "password", "passwordhash", "securitystamp" },
            ["/api/financial"] = new List<string> { "accountnumber", "routingnumber", "ssn" },
            ["/api/admin"] = new List<string>(), // Admin endpoints show all data
            ["default"] = new List<string> { "password", "passwordhash", "securitystamp", "internalnotes" }
        };
    }
}
```

### 5. API Security Configuration and Startup

```csharp
public class ApiSecurityStartup
{
    public void ConfigureServices(IServiceCollection services)
    {
        // API Security Services
        services.Configure<ApiSecurityOptions>(Configuration.GetSection("ApiSecurity"));
        services.AddScoped<IApiSecurityService, ApiSecurityService>();
        services.AddScoped<IRateLimitingService, AdvancedRateLimitingService>();
        services.AddScoped<IApiInputValidationService, ApiInputValidationService>();
        services.AddScoped<IApiResponseFilterService, ApiResponseFilterService>();
        
        // Distributed caching for rate limiting
        services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = Configuration.GetConnectionString("Redis");
        });
        
        // Authentication
        services.AddAuthentication("Bearer")
            .AddJwtBearer("Bearer", options =>
            {
                options.Authority = Configuration["Auth:Authority"];
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidAudience = Configuration["Auth:Audience"],
                    ValidateIssuer = true,
                    ValidIssuer = Configuration["Auth:Issuer"],
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };
            });
        
        // Authorization
        services.AddAuthorization(options =>
        {
            options.AddPolicy("ApiAccess", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("scope", "api.read");
            });
            
            options.AddPolicy("ApiWrite", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("scope", "api.write");
            });
        });
        
        // CORS
        services.AddCors(options =>
        {
            options.AddPolicy("ApiPolicy", builder =>
            {
                builder.WithOrigins(Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>())
                       .WithMethods("GET", "POST", "PUT", "DELETE")
                       .WithHeaders("Authorization", "Content-Type", "Accept")
                       .SetPreflightMaxAge(TimeSpan.FromHours(1));
            });
        });
        
        // Add MVC with security filters
        services.AddControllers(options =>
        {
            options.Filters.Add<ApiResponseSecurityFilter>();
        });
        
        // API versioning
        services.AddApiVersioning(options =>
        {
            options.AssumeDefaultVersionWhenUnspecified = true;
            options.DefaultApiVersion = new ApiVersion(1, 0);
            options.ApiVersionReader = ApiVersionReader.Combine(
                new QueryStringApiVersionReader("version"),
                new HeaderApiVersionReader("X-API-Version"));
        });
        
        // Health checks
        services.AddHealthChecks()
            .AddCheck<ApiSecurityHealthCheck>("api-security");
    }
    
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }
        
        // Security middleware pipeline order is important
        app.UseHttpsRedirection();
        app.UseMiddleware<ApiSecurityMiddleware>();
        app.UseCors("ApiPolicy");
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRouting();
        
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers().RequireAuthorization("ApiAccess");
            endpoints.MapHealthChecks("/health");
        });
    }
}

public class ApiSecurityHealthCheck : IHealthCheck
{
    private readonly IRateLimitingService _rateLimitService;
    
    public ApiSecurityHealthCheck(IRateLimitingService rateLimitService)
    {
        _rateLimitService = rateLimitService;
    }
    
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            // Test rate limiting service
            var testResult = await _rateLimitService.CheckRateLimitAsync("health-check", "/test", new RateLimitPolicy
            {
                Windows = new List<RateLimitWindow> { new() { Duration = TimeSpan.FromMinutes(1), MaxRequests = 1000 } }
            });
            
            return testResult.IsAllowed ? HealthCheckResult.Healthy("API security services operational") 
                                       : HealthCheckResult.Degraded("Rate limiting issues detected");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("API security services failure", ex);
        }
    }
}
```

## Testing Strategies

### 1. Security Testing

```csharp
[TestFixture]
public class ApiSecurityTests
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
                services.AddSingleton<IApiSecurityService, TestApiSecurityService>();
            });
        
        _server = new TestServer(builder);
        _client = _server.CreateClient();
    }
    
    [Test]
    public async Task Api_WithMaliciousInput_ShouldBlock()
    {
        var maliciousPayload = new
        {
            name = "<script>alert('xss')</script>",
            description = "'; DROP TABLE users; --"
        };
        
        var response = await _client.PostAsJsonAsync("/api/test", maliciousPayload);
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }
    
    [Test]
    public async Task Api_ExceedingRateLimit_ShouldReturnTooManyRequests()
    {
        // Send requests exceeding rate limit
        var tasks = Enumerable.Range(0, 150)
            .Select(_ => _client.GetAsync("/api/test"));
        
        var responses = await Task.WhenAll(tasks);
        
        var tooManyRequestsCount = responses.Count(r => r.StatusCode == HttpStatusCode.TooManyRequests);
        Assert.That(tooManyRequestsCount, Is.GreaterThan(0));
    }
    
    [Test]
    public async Task Api_WithoutAuthentication_ShouldReturnUnauthorized()
    {
        _client.DefaultRequestHeaders.Authorization = null;
        
        var response = await _client.GetAsync("/api/protected");
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }
}
```

---
**Next**: Continue with session management patterns