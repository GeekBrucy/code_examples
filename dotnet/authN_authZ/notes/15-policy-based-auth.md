# Policy-Based Authorization

## Overview
Policy-based authorization in .NET provides a flexible, declarative approach to authorization that goes beyond simple role-based checks. It allows you to define complex authorization logic using requirements, handlers, and policies that can evaluate multiple factors to make authorization decisions.

## Core Concepts

### 1. Authorization Components

#### Policies
- Named authorization rules
- Combine multiple requirements
- Reusable across controllers and actions
- Can be complex logical expressions

#### Requirements
- Specific conditions that must be met
- Implement `IAuthorizationRequirement` interface
- Can be simple or complex business rules
- Evaluated by authorization handlers

#### Handlers
- Logic that evaluates requirements
- Implement `AuthorizationHandler<TRequirement>`
- Can succeed, fail, or neither
- Support dependency injection

#### Resources
- Optional context for authorization decisions
- Can be any object type
- Passed to handlers for context-aware decisions

### 2. Policy Evaluation Process
1. Policy contains one or more requirements
2. Each requirement is evaluated by its handler(s)
3. All requirements must succeed for policy to succeed
4. Handlers can access user context and resource

## .NET Policy-Based Implementation

### 1. Basic Policy Configuration

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthorization(options =>
    {
        // Simple policies
        options.AddPolicy("RequireAdminRole", policy =>
            policy.RequireRole("Administrator"));
        
        options.AddPolicy("RequireEmailConfirmed", policy =>
            policy.RequireClaim("email_verified", "true"));
        
        // Complex policies with multiple requirements
        options.AddPolicy("RequireHighSecurity", policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireRole("Manager", "Administrator");
            policy.RequireClaim("security_clearance", "High", "Top Secret");
            policy.RequireAssertion(context =>
                context.User.HasClaim("mfa_verified", "true"));
        });
        
        // Custom requirement policies
        options.AddPolicy("CanEditDocument", policy =>
            policy.Requirements.Add(new DocumentEditRequirement()));
        
        options.AddPolicy("WorkingHours", policy =>
            policy.Requirements.Add(new WorkingHoursRequirement()));
        
        options.AddPolicy("MinimumAge", policy =>
            policy.Requirements.Add(new MinimumAgeRequirement(18)));
    });
    
    // Register authorization handlers
    services.AddScoped<IAuthorizationHandler, DocumentEditHandler>();
    services.AddScoped<IAuthorizationHandler, WorkingHoursHandler>();
    services.AddScoped<IAuthorizationHandler, MinimumAgeHandler>();
    services.AddScoped<IAuthorizationHandler, GeolocationHandler>();
}
```

### 2. Custom Authorization Requirements

```csharp
// Simple requirement
public class WorkingHoursRequirement : IAuthorizationRequirement
{
    public TimeSpan StartTime { get; }
    public TimeSpan EndTime { get; }
    
    public WorkingHoursRequirement(TimeSpan startTime, TimeSpan endTime)
    {
        StartTime = startTime;
        EndTime = endTime;
    }
}

// Parameterized requirement
public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public int MinimumAge { get; }
    
    public MinimumAgeRequirement(int minimumAge)
    {
        MinimumAge = minimumAge;
    }
}

// Resource-based requirement
public class DocumentEditRequirement : IAuthorizationRequirement
{
    public string Permission { get; }
    
    public DocumentEditRequirement(string permission = "edit")
    {
        Permission = permission;
    }
}

// Complex business requirement
public class GeolocationRequirement : IAuthorizationRequirement
{
    public List<string> AllowedCountries { get; }
    public List<string> BlockedCountries { get; }
    
    public GeolocationRequirement(List<string> allowedCountries = null, List<string> blockedCountries = null)
    {
        AllowedCountries = allowedCountries ?? new List<string>();
        BlockedCountries = blockedCountries ?? new List<string>();
    }
}

// Time-based requirement
public class TimeLimitRequirement : IAuthorizationRequirement
{
    public TimeSpan TimeLimit { get; }
    public string ClaimType { get; }
    
    public TimeLimitRequirement(TimeSpan timeLimit, string claimType = "iat")
    {
        TimeLimit = timeLimit;
        ClaimType = claimType;
    }
}
```

### 3. Authorization Handlers

```csharp
public class WorkingHoursHandler : AuthorizationHandler<WorkingHoursRequirement>
{
    private readonly ILogger<WorkingHoursHandler> _logger;
    
    public WorkingHoursHandler(ILogger<WorkingHoursHandler> logger)
    {
        _logger = logger;
    }
    
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        WorkingHoursRequirement requirement)
    {
        var currentTime = DateTime.UtcNow.TimeOfDay;
        
        if (currentTime >= requirement.StartTime && currentTime <= requirement.EndTime)
        {
            _logger.LogInformation("Access granted during working hours");
            context.Succeed(requirement);
        }
        else
        {
            _logger.LogWarning("Access denied outside working hours");
        }
        
        return Task.CompletedTask;
    }
}

public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        var dateOfBirthClaim = context.User.FindFirst("date_of_birth");
        
        if (dateOfBirthClaim != null && DateTime.TryParse(dateOfBirthClaim.Value, out var dateOfBirth))
        {
            var age = DateTime.Today.Year - dateOfBirth.Year;
            if (dateOfBirth.Date > DateTime.Today.AddYears(-age))
                age--;
            
            if (age >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }
        }
        
        return Task.CompletedTask;
    }
}

// Resource-based handler
public class DocumentEditHandler : AuthorizationHandler<DocumentEditRequirement, Document>
{
    private readonly IDocumentService _documentService;
    private readonly ILogger<DocumentEditHandler> _logger;
    
    public DocumentEditHandler(IDocumentService documentService, ILogger<DocumentEditHandler> logger)
    {
        _documentService = documentService;
        _logger = logger;
    }
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DocumentEditRequirement requirement,
        Document resource)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("No user identifier found");
            return;
        }
        
        // Check if user is document owner
        if (resource.OwnerId == userId)
        {
            context.Succeed(requirement);
            return;
        }
        
        // Check if user has edit permission
        var hasEditPermission = context.User.HasClaim("permission", "document_edit");
        if (hasEditPermission)
        {
            // Additional business logic
            if (await CanUserEditDocumentTypeAsync(userId, resource.Type))
            {
                context.Succeed(requirement);
            }
        }
        
        // Check if user is in same department
        var userDepartment = context.User.FindFirst("department")?.Value;
        if (!string.IsNullOrEmpty(userDepartment) && userDepartment == resource.Department)
        {
            var hasManagerRole = context.User.IsInRole("Manager");
            if (hasManagerRole)
            {
                context.Succeed(requirement);
            }
        }
    }
    
    private async Task<bool> CanUserEditDocumentTypeAsync(string userId, string documentType)
    {
        // Complex business logic
        var userPermissions = await _documentService.GetUserDocumentPermissionsAsync(userId);
        return userPermissions.Any(p => p.DocumentType == documentType && p.CanEdit);
    }
}

// Advanced handler with multiple requirements
public class GeolocationHandler : AuthorizationHandler<GeolocationRequirement>
{
    private readonly IGeolocationService _geolocationService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    
    public GeolocationHandler(IGeolocationService geolocationService, IHttpContextAccessor httpContextAccessor)
    {
        _geolocationService = geolocationService;
        _httpContextAccessor = httpContextAccessor;
    }
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        GeolocationRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        var ipAddress = GetClientIpAddress(httpContext);
        
        if (string.IsNullOrEmpty(ipAddress))
        {
            // Can't determine location, fail safe
            return;
        }
        
        var country = await _geolocationService.GetCountryFromIpAsync(ipAddress);
        
        if (string.IsNullOrEmpty(country))
        {
            return;
        }
        
        // Check blocked countries first
        if (requirement.BlockedCountries.Any() && 
            requirement.BlockedCountries.Contains(country, StringComparer.OrdinalIgnoreCase))
        {
            // Explicitly blocked
            return;
        }
        
        // Check allowed countries
        if (requirement.AllowedCountries.Any())
        {
            if (requirement.AllowedCountries.Contains(country, StringComparer.OrdinalIgnoreCase))
            {
                context.Succeed(requirement);
            }
        }
        else
        {
            // No specific allowed countries, succeed if not blocked
            context.Succeed(requirement);
        }
    }
    
    private string GetClientIpAddress(HttpContext httpContext)
    {
        // Handle various proxy scenarios
        var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }
        
        var realIp = httpContext.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp))
        {
            return realIp;
        }
        
        return httpContext.Connection.RemoteIpAddress?.ToString();
    }
}
```

### 4. Advanced Policy Combinations

```csharp
public class AdvancedPolicyService
{
    public void ConfigureAdvancedPolicies(AuthorizationOptions options)
    {
        // Conditional policies
        options.AddPolicy("ConditionalAccess", policy =>
        {
            policy.RequireAssertion(context =>
            {
                var userRisk = context.User.FindFirst("risk_level")?.Value;
                var deviceTrust = context.User.FindFirst("device_trusted")?.Value;
                
                return userRisk switch
                {
                    "Low" => true,
                    "Medium" => deviceTrust == "true",
                    "High" => context.User.HasClaim("mfa_verified", "true") && deviceTrust == "true",
                    _ => false
                };
            });
        });
        
        // Time-based policies
        options.AddPolicy("BusinessHoursOnly", policy =>
        {
            policy.RequireAssertion(context =>
            {
                var now = DateTime.UtcNow;
                var userTimezone = context.User.FindFirst("timezone")?.Value ?? "UTC";
                
                // Convert to user's timezone
                var userTime = TimeZoneInfo.ConvertTimeBySystemTimeZoneId(now, userTimezone);
                
                return userTime.DayOfWeek >= DayOfWeek.Monday &&
                       userTime.DayOfWeek <= DayOfWeek.Friday &&
                       userTime.Hour >= 9 && userTime.Hour < 17;
            });
        });
        
        // Data classification policy
        options.AddPolicy("AccessClassifiedData", policy =>
        {
            policy.Requirements.Add(new DataClassificationRequirement("Classified"));
        });
        
        // Composite policy with multiple handlers
        options.AddPolicy("HighSecurityAccess", policy =>
        {
            policy.Requirements.Add(new MinimumAgeRequirement(21));
            policy.Requirements.Add(new SecurityClearanceRequirement("Secret"));
            policy.Requirements.Add(new BackgroundCheckRequirement(TimeSpan.FromDays(180)));
            policy.Requirements.Add(new GeolocationRequirement(
                allowedCountries: new List<string> { "US", "CA", "GB" }));
        });
    }
}

// Additional requirement classes
public class DataClassificationRequirement : IAuthorizationRequirement
{
    public string RequiredClearance { get; }
    
    public DataClassificationRequirement(string requiredClearance)
    {
        RequiredClearance = requiredClearance;
    }
}

public class SecurityClearanceRequirement : IAuthorizationRequirement
{
    public string Level { get; }
    
    public SecurityClearanceRequirement(string level)
    {
        Level = level;
    }
}

public class BackgroundCheckRequirement : IAuthorizationRequirement
{
    public TimeSpan MaxAge { get; }
    
    public BackgroundCheckRequirement(TimeSpan maxAge)
    {
        MaxAge = maxAge;
    }
}
```

### 5. Policy-Based Controllers

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class DocumentsController : ControllerBase
{
    private readonly IAuthorizationService _authorizationService;
    private readonly IDocumentService _documentService;
    
    public DocumentsController(IAuthorizationService authorizationService, IDocumentService documentService)
    {
        _authorizationService = authorizationService;
        _documentService = documentService;
    }
    
    [HttpGet]
    [Authorize(Policy = "RequireEmailConfirmed")]
    public async Task<IActionResult> GetDocuments()
    {
        var documents = await _documentService.GetUserDocumentsAsync(User.Identity.Name);
        return Ok(documents);
    }
    
    [HttpGet("{id}")]
    public async Task<IActionResult> GetDocument(int id)
    {
        var document = await _documentService.GetDocumentAsync(id);
        
        if (document == null)
            return NotFound();
        
        // Resource-based authorization
        var authResult = await _authorizationService.AuthorizeAsync(
            User, document, "CanViewDocument");
        
        if (!authResult.Succeeded)
            return Forbid();
        
        return Ok(document);
    }
    
    [HttpPost]
    [Authorize(Policy = "BusinessHoursOnly")]
    public async Task<IActionResult> CreateDocument([FromBody] CreateDocumentRequest request)
    {
        var document = await _documentService.CreateDocumentAsync(request, User.Identity.Name);
        return CreatedAtAction(nameof(GetDocument), new { id = document.Id }, document);
    }
    
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateDocument(int id, [FromBody] UpdateDocumentRequest request)
    {
        var document = await _documentService.GetDocumentAsync(id);
        
        if (document == null)
            return NotFound();
        
        var authResult = await _authorizationService.AuthorizeAsync(
            User, document, new DocumentEditRequirement());
        
        if (!authResult.Succeeded)
            return Forbid();
        
        await _documentService.UpdateDocumentAsync(id, request);
        return Ok();
    }
    
    [HttpDelete("{id}")]
    [Authorize(Policy = "RequireHighSecurity")]
    public async Task<IActionResult> DeleteDocument(int id)
    {
        var document = await _documentService.GetDocumentAsync(id);
        
        if (document == null)
            return NotFound();
        
        // Multiple authorization checks
        var editAuth = await _authorizationService.AuthorizeAsync(
            User, document, new DocumentEditRequirement());
        
        var deleteAuth = await _authorizationService.AuthorizeAsync(
            User, document, "CanDeleteDocument");
        
        if (!editAuth.Succeeded || !deleteAuth.Succeeded)
            return Forbid();
        
        await _documentService.DeleteDocumentAsync(id);
        return Ok();
    }
    
    [HttpGet("classified")]
    [Authorize(Policy = "AccessClassifiedData")]
    public async Task<IActionResult> GetClassifiedDocuments()
    {
        var documents = await _documentService.GetClassifiedDocumentsAsync();
        return Ok(documents);
    }
}
```

### 6. Dynamic Policy Creation

```csharp
public interface IDynamicPolicyService
{
    Task<AuthorizationPolicy> CreatePolicyAsync(string policyName, PolicyDefinition definition);
    Task<bool> EvaluatePolicyAsync(ClaimsPrincipal user, string policyName, object resource = null);
    Task UpdatePolicyAsync(string policyName, PolicyDefinition definition);
}

public class DynamicPolicyService : IDynamicPolicyService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IMemoryCache _cache;
    private readonly ConcurrentDictionary<string, AuthorizationPolicy> _policies;
    
    public DynamicPolicyService(IServiceProvider serviceProvider, IMemoryCache cache)
    {
        _serviceProvider = serviceProvider;
        _cache = cache;
        _policies = new ConcurrentDictionary<string, AuthorizationPolicy>();
    }
    
    public async Task<AuthorizationPolicy> CreatePolicyAsync(string policyName, PolicyDefinition definition)
    {
        var policyBuilder = new AuthorizationPolicyBuilder();
        
        // Add requirements based on definition
        foreach (var requirement in definition.Requirements)
        {
            switch (requirement.Type)
            {
                case "Role":
                    policyBuilder.RequireRole(requirement.Values);
                    break;
                    
                case "Claim":
                    policyBuilder.RequireClaim(requirement.ClaimType, requirement.Values);
                    break;
                    
                case "CustomRequirement":
                    var customReq = CreateCustomRequirement(requirement);
                    if (customReq != null)
                        policyBuilder.Requirements.Add(customReq);
                    break;
                    
                case "Assertion":
                    policyBuilder.RequireAssertion(CreateAssertionFunc(requirement));
                    break;
            }
        }
        
        var policy = policyBuilder.Build();
        _policies.TryAdd(policyName, policy);
        
        return policy;
    }
    
    public async Task<bool> EvaluatePolicyAsync(ClaimsPrincipal user, string policyName, object resource = null)
    {
        if (!_policies.TryGetValue(policyName, out var policy))
            return false;
        
        using var scope = _serviceProvider.CreateScope();
        var authService = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        
        var result = await authService.AuthorizeAsync(user, resource, policy);
        return result.Succeeded;
    }
    
    private IAuthorizationRequirement CreateCustomRequirement(RequirementDefinition requirement)
    {
        return requirement.CustomType switch
        {
            "MinimumAge" => new MinimumAgeRequirement(int.Parse(requirement.Values.First())),
            "WorkingHours" => new WorkingHoursRequirement(
                TimeSpan.Parse(requirement.Values[0]),
                TimeSpan.Parse(requirement.Values[1])),
            "Geolocation" => new GeolocationRequirement(
                allowedCountries: requirement.Values.ToList()),
            _ => null
        };
    }
    
    private Func<AuthorizationHandlerContext, bool> CreateAssertionFunc(RequirementDefinition requirement)
    {
        return requirement.Assertion switch
        {
            "MfaVerified" => context => context.User.HasClaim("mfa_verified", "true"),
            "EmailVerified" => context => context.User.HasClaim("email_verified", "true"),
            "AccountActive" => context => !context.User.HasClaim("account_status", "suspended"),
            _ => context => false
        };
    }
    
    public async Task UpdatePolicyAsync(string policyName, PolicyDefinition definition)
    {
        var policy = await CreatePolicyAsync(policyName, definition);
        _policies.AddOrUpdate(policyName, policy, (key, oldValue) => policy);
        
        // Invalidate cache
        _cache.Remove($"policy_evaluation_{policyName}");
    }
}

public class PolicyDefinition
{
    public List<RequirementDefinition> Requirements { get; set; } = new();
}

public class RequirementDefinition
{
    public string Type { get; set; } // Role, Claim, CustomRequirement, Assertion
    public string ClaimType { get; set; }
    public List<string> Values { get; set; } = new();
    public string CustomType { get; set; }
    public string Assertion { get; set; }
}
```

## Security Best Practices

### 1. Fail-Safe Authorization
```csharp
public class FailSafeAuthorizationHandler<T> : AuthorizationHandler<T> where T : IAuthorizationRequirement
{
    private readonly IAuthorizationHandler<T> _innerHandler;
    private readonly ILogger<FailSafeAuthorizationHandler<T>> _logger;
    
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, T requirement)
    {
        try
        {
            await _innerHandler.HandleAsync(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authorization handler failed, denying access");
            // Fail safe - don't succeed if there's an exception
        }
    }
}
```

### 2. Authorization Auditing
```csharp
public class AuditingAuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuditingAuthorizationMiddleware> _logger;
    
    public async Task InvokeAsync(HttpContext context)
    {
        await _next(context);
        
        // Log authorization results
        if (context.Response.StatusCode == 403)
        {
            _logger.LogWarning("Authorization failed for user {User} accessing {Path}",
                context.User?.Identity?.Name ?? "Anonymous",
                context.Request.Path);
        }
    }
}
```

## Testing Strategies

### 1. Policy Testing
```csharp
[TestFixture]
public class PolicyAuthorizationTests
{
    private IAuthorizationService _authorizationService;
    private IServiceProvider _serviceProvider;
    
    [SetUp]
    public void Setup()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(ConfigurePolicies);
        services.AddScoped<IAuthorizationHandler, MinimumAgeHandler>();
        
        _serviceProvider = services.BuildServiceProvider();
        _authorizationService = _serviceProvider.GetService<IAuthorizationService>();
    }
    
    [Test]
    public async Task MinimumAgePolicy_WithValidAge_ShouldSucceed()
    {
        // Arrange
        var user = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("date_of_birth", "1990-01-01")
        }));
        
        // Act
        var result = await _authorizationService.AuthorizeAsync(user, "MinimumAge18");
        
        // Assert
        Assert.IsTrue(result.Succeeded);
    }
}
```

---
**Next**: Continue with the remaining authorization notes