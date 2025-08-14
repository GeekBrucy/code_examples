# Claims-Based Authorization

## Overview
Claims-based authorization uses claims (key-value pairs) that describe what a user is rather than what a user can do. Claims are issued by trusted parties and provide a flexible, fine-grained approach to authorization that works well across distributed systems.

## Core Concepts

### 1. What are Claims?
- **Key-value pairs** that describe attributes of a user
- **Issued by trusted sources** (identity providers, applications)
- **Portable** across different systems and applications
- **Flexible** - can represent any attribute

#### Examples of Claims
```
Name: "John Doe"
Email: "john@example.com"
Role: "Administrator"
Department: "Engineering"
ClearanceLevel: "Secret"
Age: "25"
Country: "USA"
```

### 2. Claims vs Traditional Authorization

#### Traditional Role-Based
- User has roles: Admin, User, Manager
- Authorization: "Is user in Admin role?"

#### Claims-Based
- User has claims: Department=Engineering, Level=Senior, Project=Alpha
- Authorization: "Does user have Department=Engineering AND Level=Senior?"

### 3. Claims Identity Model

#### ClaimsIdentity
- Represents a user's identity
- Contains a collection of claims
- Can have multiple identities (authentication schemes)

#### ClaimsPrincipal
- Represents the user
- Contains one or more ClaimsIdentity objects
- Primary interface for authorization

## .NET Claims-Based Implementation

### 1. Basic Claims Setup

#### Adding Claims to Identity
```csharp
public class UserClaimsService
{
    public async Task<ClaimsIdentity> CreateUserClaimsIdentityAsync(ApplicationUser user)
    {
        var identity = new ClaimsIdentity("custom");
        
        // Standard claims
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
        identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
        
        // Custom business claims
        identity.AddClaim(new Claim("employee_id", user.EmployeeId));
        identity.AddClaim(new Claim("department", user.Department));
        identity.AddClaim(new Claim("hire_date", user.HireDate.ToString("yyyy-MM-dd")));
        identity.AddClaim(new Claim("security_clearance", user.SecurityClearance));
        
        // Dynamic claims based on business logic
        var permissions = await GetUserPermissionsAsync(user.Id);
        foreach (var permission in permissions)
        {
            identity.AddClaim(new Claim("permission", permission));
        }
        
        // Project-specific claims
        var projects = await GetUserProjectsAsync(user.Id);
        foreach (var project in projects)
        {
            identity.AddClaim(new Claim("project", project.Name));
            identity.AddClaim(new Claim($"project_{project.Name}_role", project.Role));
        }
        
        return identity;
    }
    
    private async Task<List<string>> GetUserPermissionsAsync(string userId)
    {
        // Fetch permissions from database, cache, etc.
        return await Task.FromResult(new List<string> 
        { 
            "read_documents", 
            "write_documents", 
            "approve_requests" 
        });
    }
    
    private async Task<List<UserProject>> GetUserProjectsAsync(string userId)
    {
        // Fetch user projects from database
        return await Task.FromResult(new List<UserProject>
        {
            new UserProject { Name = "ProjectAlpha", Role = "Lead" },
            new UserProject { Name = "ProjectBeta", Role = "Developer" }
        });
    }
}

public class UserProject
{
    public string Name { get; set; }
    public string Role { get; set; }
}
```

#### Claims Transformation
```csharp
public class CustomClaimsTransformer : IClaimsTransformation
{
    private readonly IUserService _userService;
    private readonly IMemoryCache _cache;
    
    public CustomClaimsTransformer(IUserService userService, IMemoryCache cache)
    {
        _userService = userService;
        _cache = cache;
    }
    
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true)
            return principal;
        
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            return principal;
        
        // Check if claims are already transformed
        if (principal.HasClaim("claims_transformed", "true"))
            return principal;
        
        // Get cached claims or fetch from database
        var cacheKey = $"user_claims_{userId}";
        if (!_cache.TryGetValue(cacheKey, out List<Claim> additionalClaims))
        {
            additionalClaims = await GetAdditionalClaimsAsync(userId);
            _cache.Set(cacheKey, additionalClaims, TimeSpan.FromMinutes(30));
        }
        
        // Add additional claims
        var identity = (ClaimsIdentity)principal.Identity;
        identity.AddClaims(additionalClaims);
        identity.AddClaim(new Claim("claims_transformed", "true"));
        
        return principal;
    }
    
    private async Task<List<Claim>> GetAdditionalClaimsAsync(string userId)
    {
        var user = await _userService.GetUserByIdAsync(userId);
        var claims = new List<Claim>();
        
        // Add organizational claims
        if (!string.IsNullOrEmpty(user.Department))
        {
            claims.Add(new Claim("department", user.Department));
            
            // Add department-specific permissions
            var deptPermissions = await GetDepartmentPermissionsAsync(user.Department);
            foreach (var permission in deptPermissions)
            {
                claims.Add(new Claim("dept_permission", permission));
            }
        }
        
        // Add subscription-based claims
        var subscription = await _userService.GetUserSubscriptionAsync(userId);
        if (subscription != null)
        {
            claims.Add(new Claim("subscription_level", subscription.Level));
            claims.Add(new Claim("subscription_expires", subscription.ExpiresAt.ToString("O")));
        }
        
        // Add geographic claims
        if (!string.IsNullOrEmpty(user.Country))
        {
            claims.Add(new Claim(ClaimTypes.Country, user.Country));
            
            // Add country-specific regulations
            var regulations = await GetCountryRegulationsAsync(user.Country);
            foreach (var regulation in regulations)
            {
                claims.Add(new Claim("regulation", regulation));
            }
        }
        
        return claims;
    }
    
    private async Task<List<string>> GetDepartmentPermissionsAsync(string department)
    {
        // Department-specific business logic
        return department.ToLower() switch
        {
            "hr" => new List<string> { "view_employee_data", "modify_benefits" },
            "finance" => new List<string> { "view_financial_data", "approve_expenses" },
            "engineering" => new List<string> { "deploy_code", "access_production" },
            _ => new List<string>()
        };
    }
    
    private async Task<List<string>> GetCountryRegulationsAsync(string country)
    {
        return country.ToUpper() switch
        {
            "US" => new List<string> { "HIPAA", "SOX" },
            "DE" => new List<string> { "GDPR" },
            "UK" => new List<string> { "GDPR", "DPA" },
            _ => new List<string>()
        };
    }
}

// Register the transformer
public void ConfigureServices(IServiceCollection services)
{
    services.AddTransient<IClaimsTransformation, CustomClaimsTransformer>();
}
```

### 2. Policy-Based Authorization with Claims

#### Simple Claims Requirements
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthorization(options =>
    {
        // Simple claim requirements
        options.AddPolicy("RequireAdminRole", policy =>
            policy.RequireClaim(ClaimTypes.Role, "Administrator"));
        
        options.AddPolicy("RequireEngineering", policy =>
            policy.RequireClaim("department", "Engineering"));
        
        options.AddPolicy("RequireHighClearance", policy =>
            policy.RequireClaim("security_clearance", "Top Secret", "Secret"));
        
        // Multiple claims (AND logic)
        options.AddPolicy("RequireEngineeringManager", policy =>
            policy.RequireClaim("department", "Engineering")
                  .RequireClaim(ClaimTypes.Role, "Manager"));
        
        // Custom claim validation
        options.AddPolicy("RequireValidSubscription", policy =>
            policy.RequireAssertion(context =>
                ValidateSubscription(context.User)));
    });
}

private static bool ValidateSubscription(ClaimsPrincipal user)
{
    var subscriptionExpiry = user.FindFirst("subscription_expires")?.Value;
    if (DateTime.TryParse(subscriptionExpiry, out var expiryDate))
    {
        return expiryDate > DateTime.UtcNow;
    }
    return false;
}
```

#### Advanced Claims Requirements
```csharp
public class CustomClaimsRequirement : IAuthorizationRequirement
{
    public string ClaimType { get; }
    public Func<string, bool> ClaimValueValidator { get; }
    
    public CustomClaimsRequirement(string claimType, Func<string, bool> validator)
    {
        ClaimType = claimType;
        ClaimValueValidator = validator;
    }
}

public class CustomClaimsHandler : AuthorizationHandler<CustomClaimsRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CustomClaimsRequirement requirement)
    {
        var claims = context.User.FindAll(requirement.ClaimType);
        
        if (claims.Any(claim => requirement.ClaimValueValidator(claim.Value)))
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}

// Complex requirements
public class DepartmentPermissionRequirement : IAuthorizationRequirement
{
    public string Department { get; }
    public string Permission { get; }
    
    public DepartmentPermissionRequirement(string department, string permission)
    {
        Department = department;
        Permission = permission;
    }
}

public class DepartmentPermissionHandler : AuthorizationHandler<DepartmentPermissionRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DepartmentPermissionRequirement requirement)
    {
        var userDepartment = context.User.FindFirst("department")?.Value;
        var userPermissions = context.User.FindAll("dept_permission").Select(c => c.Value);
        
        if (userDepartment == requirement.Department && 
            userPermissions.Contains(requirement.Permission))
        {
            context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}

// Registration
public void ConfigureServices(IServiceCollection services)
{
    services.AddScoped<IAuthorizationHandler, CustomClaimsHandler>();
    services.AddScoped<IAuthorizationHandler, DepartmentPermissionHandler>();
    
    services.AddAuthorization(options =>
    {
        options.AddPolicy("RequireHighValue", policy =>
            policy.Requirements.Add(new CustomClaimsRequirement("transaction_limit", 
                value => decimal.TryParse(value, out var limit) && limit >= 10000)));
        
        options.AddPolicy("RequireHRAccess", policy =>
            policy.Requirements.Add(new DepartmentPermissionRequirement("HR", "view_employee_data")));
    });
}
```

### 3. Resource-Based Authorization with Claims

#### Resource-Based Handler
```csharp
public class DocumentResource
{
    public string Id { get; set; }
    public string OwnerId { get; set; }
    public string Department { get; set; }
    public string Classification { get; set; }
    public List<string> AuthorizedUsers { get; set; } = new();
}

public static class DocumentOperations
{
    public static OperationAuthorizationRequirement Read = new() { Name = "Read" };
    public static OperationAuthorizationRequirement Edit = new() { Name = "Edit" };
    public static OperationAuthorizationRequirement Delete = new() { Name = "Delete" };
}

public class DocumentAuthorizationHandler : 
    AuthorizationHandler<OperationAuthorizationRequirement, DocumentResource>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        DocumentResource resource)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userDepartment = context.User.FindFirst("department")?.Value;
        var userClearance = context.User.FindFirst("security_clearance")?.Value;
        
        switch (requirement.Name)
        {
            case "Read":
                if (CanReadDocument(context.User, resource))
                    context.Succeed(requirement);
                break;
                
            case "Edit":
                if (CanEditDocument(context.User, resource))
                    context.Succeed(requirement);
                break;
                
            case "Delete":
                if (CanDeleteDocument(context.User, resource))
                    context.Succeed(requirement);
                break;
        }
        
        return Task.CompletedTask;
    }
    
    private bool CanReadDocument(ClaimsPrincipal user, DocumentResource document)
    {
        var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userDepartment = user.FindFirst("department")?.Value;
        var userClearance = user.FindFirst("security_clearance")?.Value;
        
        // Owner can always read
        if (document.OwnerId == userId)
            return true;
        
        // Same department can read
        if (document.Department == userDepartment)
            return true;
        
        // Check clearance level for classified documents
        if (document.Classification == "Secret" && userClearance != "Secret" && userClearance != "Top Secret")
            return false;
        
        if (document.Classification == "Top Secret" && userClearance != "Top Secret")
            return false;
        
        // Check if user is in authorized list
        return document.AuthorizedUsers.Contains(userId);
    }
    
    private bool CanEditDocument(ClaimsPrincipal user, DocumentResource document)
    {
        var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userPermissions = user.FindAll("permission").Select(c => c.Value);
        
        // Owner can edit
        if (document.OwnerId == userId)
            return true;
        
        // Must have edit permission
        if (!userPermissions.Contains("edit_documents"))
            return false;
        
        // Must be able to read first
        return CanReadDocument(user, document);
    }
    
    private bool CanDeleteDocument(ClaimsPrincipal user, DocumentResource document)
    {
        var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userRoles = user.FindAll(ClaimTypes.Role).Select(c => c.Value);
        var userPermissions = user.FindAll("permission").Select(c => c.Value);
        
        // Owner can delete
        if (document.OwnerId == userId)
            return true;
        
        // Admin can delete anything
        if (userRoles.Contains("Administrator"))
            return true;
        
        // Must have delete permission
        return userPermissions.Contains("delete_documents");
    }
}
```

#### Using Resource-Based Authorization
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
    
    [HttpGet("{id}")]
    public async Task<IActionResult> GetDocument(string id)
    {
        var document = await _documentService.GetDocumentAsync(id);
        if (document == null)
            return NotFound();
        
        var authorizationResult = await _authorizationService
            .AuthorizeAsync(User, document, DocumentOperations.Read);
        
        if (!authorizationResult.Succeeded)
            return Forbid();
        
        return Ok(document);
    }
    
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateDocument(string id, [FromBody] UpdateDocumentRequest request)
    {
        var document = await _documentService.GetDocumentAsync(id);
        if (document == null)
            return NotFound();
        
        var authorizationResult = await _authorizationService
            .AuthorizeAsync(User, document, DocumentOperations.Edit);
        
        if (!authorizationResult.Succeeded)
            return Forbid();
        
        await _documentService.UpdateDocumentAsync(id, request);
        return Ok();
    }
    
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteDocument(string id)
    {
        var document = await _documentService.GetDocumentAsync(id);
        if (document == null)
            return NotFound();
        
        var authorizationResult = await _authorizationService
            .AuthorizeAsync(User, document, DocumentOperations.Delete);
        
        if (!authorizationResult.Succeeded)
            return Forbid();
        
        await _documentService.DeleteDocumentAsync(id);
        return Ok();
    }
}
```

### 4. Dynamic Claims Management

#### Claims Management Service
```csharp
public interface IUserClaimsManager
{
    Task AddClaimAsync(string userId, Claim claim);
    Task RemoveClaimAsync(string userId, string claimType, string claimValue);
    Task UpdateClaimAsync(string userId, string claimType, string oldValue, string newValue);
    Task<List<Claim>> GetUserClaimsAsync(string userId);
    Task RefreshUserClaimsAsync(string userId);
}

public class UserClaimsManager : IUserClaimsManager
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IMemoryCache _cache;
    private readonly IServiceBus _serviceBus;
    private readonly ILogger<UserClaimsManager> _logger;
    
    public UserClaimsManager(
        UserManager<ApplicationUser> userManager,
        IMemoryCache cache,
        IServiceBus serviceBus,
        ILogger<UserClaimsManager> logger)
    {
        _userManager = userManager;
        _cache = cache;
        _serviceBus = serviceBus;
        _logger = logger;
    }
    
    public async Task AddClaimAsync(string userId, Claim claim)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            throw new ArgumentException("User not found");
        
        await _userManager.AddClaimAsync(user, claim);
        
        // Invalidate cache
        _cache.Remove($"user_claims_{userId}");
        
        // Publish event for real-time updates
        await _serviceBus.PublishAsync(new UserClaimsChangedEvent
        {
            UserId = userId,
            Action = "Added",
            ClaimType = claim.Type,
            ClaimValue = claim.Value
        });
        
        _logger.LogInformation("Added claim {ClaimType}:{ClaimValue} to user {UserId}",
            claim.Type, claim.Value, userId);
    }
    
    public async Task RemoveClaimAsync(string userId, string claimType, string claimValue)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            throw new ArgumentException("User not found");
        
        var claim = new Claim(claimType, claimValue);
        await _userManager.RemoveClaimAsync(user, claim);
        
        _cache.Remove($"user_claims_{userId}");
        
        await _serviceBus.PublishAsync(new UserClaimsChangedEvent
        {
            UserId = userId,
            Action = "Removed",
            ClaimType = claimType,
            ClaimValue = claimValue
        });
        
        _logger.LogInformation("Removed claim {ClaimType}:{ClaimValue} from user {UserId}",
            claimType, claimValue, userId);
    }
    
    public async Task UpdateClaimAsync(string userId, string claimType, string oldValue, string newValue)
    {
        await RemoveClaimAsync(userId, claimType, oldValue);
        await AddClaimAsync(userId, new Claim(claimType, newValue));
    }
    
    public async Task<List<Claim>> GetUserClaimsAsync(string userId)
    {
        var cacheKey = $"user_claims_{userId}";
        
        if (_cache.TryGetValue(cacheKey, out List<Claim> cachedClaims))
            return cachedClaims;
        
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return new List<Claim>();
        
        var claims = (await _userManager.GetClaimsAsync(user)).ToList();
        
        _cache.Set(cacheKey, claims, TimeSpan.FromMinutes(30));
        
        return claims;
    }
    
    public async Task RefreshUserClaimsAsync(string userId)
    {
        _cache.Remove($"user_claims_{userId}");
        await GetUserClaimsAsync(userId); // This will repopulate the cache
    }
}

public class UserClaimsChangedEvent
{
    public string UserId { get; set; }
    public string Action { get; set; }
    public string ClaimType { get; set; }
    public string ClaimValue { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
```

### 5. Claims-Based API Controller

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ClaimsController : ControllerBase
{
    private readonly IUserClaimsManager _claimsManager;
    
    public ClaimsController(IUserClaimsManager claimsManager)
    {
        _claimsManager = claimsManager;
    }
    
    [HttpGet("my-claims")]
    public IActionResult GetMyClaims()
    {
        var claims = User.Claims.Select(c => new
        {
            Type = c.Type,
            Value = c.Value,
            Issuer = c.Issuer
        });
        
        return Ok(claims);
    }
    
    [HttpGet("check-claim")]
    public IActionResult CheckClaim([FromQuery] string type, [FromQuery] string value)
    {
        var hasClaim = User.HasClaim(type, value);
        return Ok(new { HasClaim = hasClaim });
    }
    
    [HttpPost("user/{userId}/claims")]
    [Authorize(Policy = "RequireAdminRole")]
    public async Task<IActionResult> AddUserClaim(string userId, [FromBody] AddClaimRequest request)
    {
        try
        {
            var claim = new Claim(request.Type, request.Value);
            await _claimsManager.AddClaimAsync(userId, claim);
            
            return Ok(new { Message = "Claim added successfully" });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }
    
    [HttpDelete("user/{userId}/claims")]
    [Authorize(Policy = "RequireAdminRole")]
    public async Task<IActionResult> RemoveUserClaim(
        string userId, 
        [FromQuery] string type, 
        [FromQuery] string value)
    {
        try
        {
            await _claimsManager.RemoveClaimAsync(userId, type, value);
            return Ok(new { Message = "Claim removed successfully" });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }
}

public class AddClaimRequest
{
    [Required]
    public string Type { get; set; }
    
    [Required]
    public string Value { get; set; }
}
```

## Security Best Practices

### 1. Claims Security
- **Minimal claims**: Only include necessary claims
- **Sensitive data**: Avoid putting sensitive data in claims
- **Validation**: Always validate claim values
- **Expiration**: Use time-sensitive claims when appropriate
- **Signing**: Ensure claims are from trusted sources

### 2. Performance Considerations
```csharp
public class OptimizedClaimsTransformer : IClaimsTransformation
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<OptimizedClaimsTransformer> _logger;
    
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        // Batch claim transformations
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var cacheKey = $"transformed_claims_{userId}";
        
        if (_cache.TryGetValue(cacheKey, out ClaimsPrincipal cachedPrincipal))
        {
            return cachedPrincipal;
        }
        
        // Transform claims
        var transformedPrincipal = await PerformTransformationAsync(principal);
        
        // Cache for performance
        _cache.Set(cacheKey, transformedPrincipal, TimeSpan.FromMinutes(15));
        
        return transformedPrincipal;
    }
}
```

## Testing Strategies

### 1. Claims Testing
```csharp
[TestFixture]
public class ClaimsAuthorizationTests
{
    [Test]
    public async Task AuthorizeAsync_WithValidClaims_ShouldSucceed()
    {
        // Arrange
        var user = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "123"),
            new Claim("department", "Engineering"),
            new Claim("security_clearance", "Secret")
        }));
        
        var resource = new DocumentResource
        {
            Department = "Engineering",
            Classification = "Secret"
        };
        
        var handler = new DocumentAuthorizationHandler();
        var context = new AuthorizationHandlerContext(
            new[] { DocumentOperations.Read }, user, resource);
        
        // Act
        await handler.HandleAsync(context);
        
        // Assert
        Assert.IsTrue(context.HasSucceeded);
    }
}
```

---
**Next**: Continue to `12-rbac.md` to learn about Role-Based Access Control implementation