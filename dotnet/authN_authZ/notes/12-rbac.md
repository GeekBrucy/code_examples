# Role-Based Access Control (RBAC)

## Overview
Role-Based Access Control (RBAC) is an authorization model where permissions are assigned to roles, and roles are assigned to users. It's one of the most widely adopted access control models due to its simplicity and effectiveness in managing permissions at scale.

## Core Concepts

### 1. RBAC Components

#### Users
- Individual entities that need access to resources
- Can be assigned multiple roles
- Inherit permissions from all assigned roles

#### Roles
- Named collection of permissions
- Represent job functions or responsibilities
- Examples: Administrator, Manager, Employee, Guest

#### Permissions
- Specific actions that can be performed on resources
- Examples: Create, Read, Update, Delete, Execute, Approve

#### Resources
- Protected entities or services
- Examples: Documents, APIs, Database tables, Features

### 2. RBAC Models

#### Flat RBAC (RBAC0)
- Basic model with users, roles, and permissions
- No role hierarchies
- Simple many-to-many relationships

#### Hierarchical RBAC (RBAC1)
- Roles can inherit permissions from other roles
- Senior roles inherit permissions from junior roles
- Examples: Manager inherits all Employee permissions

#### Constrained RBAC (RBAC2)
- Adds constraints and business rules
- Separation of Duty (SoD): Users cannot have conflicting roles
- Cardinality constraints: Limit number of users per role

#### Consolidated RBAC (RBAC3)
- Combines hierarchical and constrained models
- Most comprehensive RBAC implementation

### 3. RBAC Benefits
- **Simplified management**: Assign roles instead of individual permissions
- **Scalability**: Easy to manage permissions for large organizations
- **Compliance**: Supports regulatory requirements
- **Principle of least privilege**: Users get minimum necessary permissions
- **Audit trail**: Clear role assignments for security audits

## .NET RBAC Implementation

### 1. Basic RBAC Data Model

```csharp
// User entity
public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Department { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLogin { get; set; }
    public bool IsActive { get; set; } = true;
    
    // Navigation properties
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
}

// Role entity
public class ApplicationRole : IdentityRole
{
    public string Description { get; set; }
    public string Category { get; set; }
    public int Priority { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    
    // Navigation properties
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
    public virtual ICollection<RoleHierarchy> ParentRoles { get; set; } = new List<RoleHierarchy>();
    public virtual ICollection<RoleHierarchy> ChildRoles { get; set; } = new List<RoleHierarchy>();
}

// Permission entity
public class Permission
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
    public string Resource { get; set; }
    public string Action { get; set; }
    public string Category { get; set; }
    public bool IsActive { get; set; } = true;
    
    // Navigation properties
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}

// Many-to-many relationships
public class UserRole : IdentityUserRole<string>
{
    public DateTime AssignedAt { get; set; }
    public string AssignedBy { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool IsActive { get; set; } = true;
    
    // Navigation properties
    public virtual ApplicationUser User { get; set; }
    public virtual ApplicationRole Role { get; set; }
}

public class RolePermission
{
    public string RoleId { get; set; }
    public int PermissionId { get; set; }
    public DateTime GrantedAt { get; set; }
    public string GrantedBy { get; set; }
    
    // Navigation properties
    public virtual ApplicationRole Role { get; set; }
    public virtual Permission Permission { get; set; }
}

// Role hierarchy for RBAC1
public class RoleHierarchy
{
    public int Id { get; set; }
    public string ParentRoleId { get; set; }
    public string ChildRoleId { get; set; }
    public DateTime CreatedAt { get; set; }
    
    // Navigation properties
    public virtual ApplicationRole ParentRole { get; set; }
    public virtual ApplicationRole ChildRole { get; set; }
}
```

### 2. DbContext Configuration

```csharp
public class RbacDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string, IdentityUserClaim<string>, UserRole, IdentityUserLogin<string>, IdentityRoleClaim<string>, IdentityUserToken<string>>
{
    public DbSet<Permission> Permissions { get; set; }
    public DbSet<RolePermission> RolePermissions { get; set; }
    public DbSet<RoleHierarchy> RoleHierarchies { get; set; }
    
    public RbacDbContext(DbContextOptions<RbacDbContext> options) : base(options) { }
    
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        
        // Configure UserRole
        builder.Entity<UserRole>(entity =>
        {
            entity.HasKey(ur => new { ur.UserId, ur.RoleId });
            
            entity.HasOne(ur => ur.User)
                  .WithMany(u => u.UserRoles)
                  .HasForeignKey(ur => ur.UserId);
                  
            entity.HasOne(ur => ur.Role)
                  .WithMany(r => r.UserRoles)
                  .HasForeignKey(ur => ur.RoleId);
        });
        
        // Configure RolePermission
        builder.Entity<RolePermission>(entity =>
        {
            entity.HasKey(rp => new { rp.RoleId, rp.PermissionId });
            
            entity.HasOne(rp => rp.Role)
                  .WithMany(r => r.RolePermissions)
                  .HasForeignKey(rp => rp.RoleId);
                  
            entity.HasOne(rp => rp.Permission)
                  .WithMany(p => p.RolePermissions)
                  .HasForeignKey(rp => rp.PermissionId);
        });
        
        // Configure RoleHierarchy
        builder.Entity<RoleHierarchy>(entity =>
        {
            entity.HasKey(rh => rh.Id);
            
            entity.HasOne(rh => rh.ParentRole)
                  .WithMany(r => r.ChildRoles)
                  .HasForeignKey(rh => rh.ParentRoleId)
                  .OnDelete(DeleteBehavior.Restrict);
                  
            entity.HasOne(rh => rh.ChildRole)
                  .WithMany(r => r.ParentRoles)
                  .HasForeignKey(rh => rh.ChildRoleId)
                  .OnDelete(DeleteBehavior.Restrict);
                  
            // Prevent self-referencing and duplicate hierarchies
            entity.HasIndex(rh => new { rh.ParentRoleId, rh.ChildRoleId }).IsUnique();
        });
        
        // Configure Permission
        builder.Entity<Permission>(entity =>
        {
            entity.HasKey(p => p.Id);
            entity.Property(p => p.Name).IsRequired().HasMaxLength(100);
            entity.Property(p => p.Resource).HasMaxLength(100);
            entity.Property(p => p.Action).HasMaxLength(50);
            entity.HasIndex(p => new { p.Resource, p.Action }).IsUnique();
        });
    }
}
```

### 3. RBAC Service Implementation

```csharp
public interface IRbacService
{
    // Role management
    Task<bool> CreateRoleAsync(string roleName, string description, string category = null);
    Task<bool> DeleteRoleAsync(string roleName);
    Task<List<ApplicationRole>> GetAllRolesAsync();
    Task<ApplicationRole> GetRoleByNameAsync(string roleName);
    
    // Permission management
    Task<bool> CreatePermissionAsync(string name, string description, string resource, string action);
    Task<List<Permission>> GetAllPermissionsAsync();
    Task<List<Permission>> GetPermissionsByResourceAsync(string resource);
    
    // Role-Permission management
    Task<bool> GrantPermissionToRoleAsync(string roleName, int permissionId);
    Task<bool> RevokePermissionFromRoleAsync(string roleName, int permissionId);
    Task<List<Permission>> GetRolePermissionsAsync(string roleName);
    
    // User-Role management
    Task<bool> AssignUserToRoleAsync(string userId, string roleName, DateTime? expiresAt = null);
    Task<bool> RemoveUserFromRoleAsync(string userId, string roleName);
    Task<List<ApplicationRole>> GetUserRolesAsync(string userId);
    Task<List<ApplicationUser>> GetUsersInRoleAsync(string roleName);
    
    // Role hierarchy
    Task<bool> CreateRoleHierarchyAsync(string parentRoleName, string childRoleName);
    Task<bool> RemoveRoleHierarchyAsync(string parentRoleName, string childRoleName);
    Task<List<ApplicationRole>> GetChildRolesAsync(string roleName);
    Task<List<ApplicationRole>> GetParentRolesAsync(string roleName);
    
    // Authorization checks
    Task<bool> UserHasPermissionAsync(string userId, string resource, string action);
    Task<bool> UserHasRoleAsync(string userId, string roleName);
    Task<List<Permission>> GetEffectiveUserPermissionsAsync(string userId);
}

public class RbacService : IRbacService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly RbacDbContext _context;
    private readonly IMemoryCache _cache;
    private readonly ILogger<RbacService> _logger;
    
    public RbacService(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        RbacDbContext context,
        IMemoryCache cache,
        ILogger<RbacService> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _context = context;
        _cache = cache;
        _logger = logger;
    }
    
    public async Task<bool> CreateRoleAsync(string roleName, string description, string category = null)
    {
        try
        {
            var role = new ApplicationRole
            {
                Name = roleName,
                NormalizedName = roleName.ToUpper(),
                Description = description,
                Category = category,
                CreatedAt = DateTime.UtcNow
            };
            
            var result = await _roleManager.CreateAsync(role);
            
            if (result.Succeeded)
            {
                _logger.LogInformation("Role {RoleName} created successfully", roleName);
                InvalidateCache();
                return true;
            }
            
            _logger.LogWarning("Failed to create role {RoleName}: {Errors}", 
                roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating role {RoleName}", roleName);
            return false;
        }
    }
    
    public async Task<bool> CreatePermissionAsync(string name, string description, string resource, string action)
    {
        try
        {
            var permission = new Permission
            {
                Name = name,
                Description = description,
                Resource = resource,
                Action = action,
                Category = resource
            };
            
            _context.Permissions.Add(permission);
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Permission {PermissionName} created for {Resource}:{Action}", 
                name, resource, action);
            InvalidateCache();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating permission {PermissionName}", name);
            return false;
        }
    }
    
    public async Task<bool> GrantPermissionToRoleAsync(string roleName, int permissionId)
    {
        try
        {
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role == null)
            {
                _logger.LogWarning("Role {RoleName} not found", roleName);
                return false;
            }
            
            var permission = await _context.Permissions.FindAsync(permissionId);
            if (permission == null)
            {
                _logger.LogWarning("Permission {PermissionId} not found", permissionId);
                return false;
            }
            
            // Check if permission is already granted
            var existingGrant = await _context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == role.Id && rp.PermissionId == permissionId);
                
            if (existingGrant != null)
            {
                _logger.LogInformation("Permission {PermissionId} already granted to role {RoleName}", 
                    permissionId, roleName);
                return true;
            }
            
            var rolePermission = new RolePermission
            {
                RoleId = role.Id,
                PermissionId = permissionId,
                GrantedAt = DateTime.UtcNow,
                GrantedBy = "System" // In real app, use current user
            };
            
            _context.RolePermissions.Add(rolePermission);
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Permission {PermissionId} granted to role {RoleName}", 
                permissionId, roleName);
            InvalidateCache();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error granting permission {PermissionId} to role {RoleName}", 
                permissionId, roleName);
            return false;
        }
    }
    
    public async Task<bool> AssignUserToRoleAsync(string userId, string roleName, DateTime? expiresAt = null)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User {UserId} not found", userId);
                return false;
            }
            
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role == null)
            {
                _logger.LogWarning("Role {RoleName} not found", roleName);
                return false;
            }
            
            // Check if user already has role
            if (await _userManager.IsInRoleAsync(user, roleName))
            {
                _logger.LogInformation("User {UserId} already has role {RoleName}", userId, roleName);
                return true;
            }
            
            // Add user to role using Identity
            var result = await _userManager.AddToRoleAsync(user, roleName);
            
            if (result.Succeeded)
            {
                // Update our extended UserRole entity
                var userRole = await _context.UserRoles
                    .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == role.Id);
                    
                if (userRole != null)
                {
                    userRole.AssignedAt = DateTime.UtcNow;
                    userRole.ExpiresAt = expiresAt;
                    userRole.IsActive = true;
                    await _context.SaveChangesAsync();
                }
                
                _logger.LogInformation("User {UserId} assigned to role {RoleName}", userId, roleName);
                InvalidateCache();
                return true;
            }
            
            _logger.LogWarning("Failed to assign user {UserId} to role {RoleName}: {Errors}", 
                userId, roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error assigning user {UserId} to role {RoleName}", userId, roleName);
            return false;
        }
    }
    
    public async Task<bool> UserHasPermissionAsync(string userId, string resource, string action)
    {
        try
        {
            var cacheKey = $"user_permissions_{userId}";
            
            if (!_cache.TryGetValue(cacheKey, out List<Permission> userPermissions))
            {
                userPermissions = await GetEffectiveUserPermissionsAsync(userId);
                _cache.Set(cacheKey, userPermissions, TimeSpan.FromMinutes(30));
            }
            
            return userPermissions.Any(p => p.Resource == resource && p.Action == action);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking permission for user {UserId}", userId);
            return false;
        }
    }
    
    public async Task<List<Permission>> GetEffectiveUserPermissionsAsync(string userId)
    {
        try
        {
            var userRoles = await GetUserRolesAsync(userId);
            var allPermissions = new HashSet<Permission>();
            
            foreach (var role in userRoles)
            {
                // Get direct role permissions
                var rolePermissions = await GetRolePermissionsAsync(role.Name);
                foreach (var permission in rolePermissions)
                {
                    allPermissions.Add(permission);
                }
                
                // Get permissions from child roles (role hierarchy)
                var childRoles = await GetAllChildRolesRecursiveAsync(role.Name);
                foreach (var childRole in childRoles)
                {
                    var childPermissions = await GetRolePermissionsAsync(childRole.Name);
                    foreach (var permission in childPermissions)
                    {
                        allPermissions.Add(permission);
                    }
                }
            }
            
            return allPermissions.Where(p => p.IsActive).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting effective permissions for user {UserId}", userId);
            return new List<Permission>();
        }
    }
    
    private async Task<List<ApplicationRole>> GetAllChildRolesRecursiveAsync(string roleName)
    {
        var allChildRoles = new List<ApplicationRole>();
        var visited = new HashSet<string>();
        
        await GetChildRolesRecursive(roleName, allChildRoles, visited);
        
        return allChildRoles;
    }
    
    private async Task GetChildRolesRecursive(string roleName, List<ApplicationRole> result, HashSet<string> visited)
    {
        if (visited.Contains(roleName))
            return; // Prevent infinite loops
            
        visited.Add(roleName);
        
        var childRoles = await GetChildRolesAsync(roleName);
        
        foreach (var childRole in childRoles)
        {
            result.Add(childRole);
            await GetChildRolesRecursive(childRole.Name, result, visited);
        }
    }
    
    public async Task<List<ApplicationRole>> GetChildRolesAsync(string roleName)
    {
        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null) return new List<ApplicationRole>();
        
        return await _context.RoleHierarchies
            .Where(rh => rh.ParentRoleId == role.Id)
            .Include(rh => rh.ChildRole)
            .Select(rh => rh.ChildRole)
            .ToListAsync();
    }
    
    public async Task<List<Permission>> GetRolePermissionsAsync(string roleName)
    {
        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null) return new List<Permission>();
        
        return await _context.RolePermissions
            .Where(rp => rp.RoleId == role.Id)
            .Include(rp => rp.Permission)
            .Select(rp => rp.Permission)
            .Where(p => p.IsActive)
            .ToListAsync();
    }
    
    public async Task<List<ApplicationRole>> GetUserRolesAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return new List<ApplicationRole>();
        
        var roleNames = await _userManager.GetRolesAsync(user);
        var roles = new List<ApplicationRole>();
        
        foreach (var roleName in roleNames)
        {
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role != null && role.IsActive)
            {
                roles.Add(role);
            }
        }
        
        return roles;
    }
    
    private void InvalidateCache()
    {
        // In a real application, you might want to use a more sophisticated cache invalidation strategy
        // This is a simple approach for demonstration
        var field = typeof(MemoryCache).GetField("_memoryCache", 
            BindingFlags.NonPublic | BindingFlags.Instance);
        if (field?.GetValue(_cache) is IDictionary cache)
        {
            var keysToRemove = cache.Keys.Cast<object>()
                .Where(k => k.ToString().StartsWith("user_permissions_") || 
                           k.ToString().StartsWith("role_permissions_"))
                .ToList();
                
            foreach (var key in keysToRemove)
            {
                _cache.Remove(key);
            }
        }
    }
    
    // Additional methods implementation...
    public async Task<bool> DeleteRoleAsync(string roleName) { /* Implementation */ return true; }
    public async Task<List<ApplicationRole>> GetAllRolesAsync() { /* Implementation */ return new List<ApplicationRole>(); }
    public async Task<ApplicationRole> GetRoleByNameAsync(string roleName) { /* Implementation */ return null; }
    public async Task<List<Permission>> GetAllPermissionsAsync() { /* Implementation */ return new List<Permission>(); }
    public async Task<List<Permission>> GetPermissionsByResourceAsync(string resource) { /* Implementation */ return new List<Permission>(); }
    public async Task<bool> RevokePermissionFromRoleAsync(string roleName, int permissionId) { /* Implementation */ return true; }
    public async Task<bool> RemoveUserFromRoleAsync(string userId, string roleName) { /* Implementation */ return true; }
    public async Task<List<ApplicationUser>> GetUsersInRoleAsync(string roleName) { /* Implementation */ return new List<ApplicationUser>(); }
    public async Task<bool> CreateRoleHierarchyAsync(string parentRoleName, string childRoleName) { /* Implementation */ return true; }
    public async Task<bool> RemoveRoleHierarchyAsync(string parentRoleName, string childRoleName) { /* Implementation */ return true; }
    public async Task<List<ApplicationRole>> GetParentRolesAsync(string roleName) { /* Implementation */ return new List<ApplicationRole>(); }
    public async Task<bool> UserHasRoleAsync(string userId, string roleName) { /* Implementation */ return true; }
}
```

### 4. RBAC Authorization Handlers

```csharp
public class RbacPermissionRequirement : IAuthorizationRequirement
{
    public string Resource { get; }
    public string Action { get; }
    
    public RbacPermissionRequirement(string resource, string action)
    {
        Resource = resource;
        Action = action;
    }
}

public class RbacPermissionHandler : AuthorizationHandler<RbacPermissionRequirement>
{
    private readonly IRbacService _rbacService;
    
    public RbacPermissionHandler(IRbacService rbacService)
    {
        _rbacService = rbacService;
    }
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        RbacPermissionRequirement requirement)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
        {
            context.Fail();
            return;
        }
        
        var hasPermission = await _rbacService.UserHasPermissionAsync(
            userId, 
            requirement.Resource, 
            requirement.Action);
        
        if (hasPermission)
        {
            context.Succeed(requirement);
        }
    }
}

// Resource-specific authorization
public class DocumentOperations
{
    public static RbacPermissionRequirement Read = new("Document", "Read");
    public static RbacPermissionRequirement Create = new("Document", "Create");
    public static RbacPermissionRequirement Update = new("Document", "Update");
    public static RbacPermissionRequirement Delete = new("Document", "Delete");
}
```

### 5. RBAC Controller Implementation

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class RbacController : ControllerBase
{
    private readonly IRbacService _rbacService;
    private readonly IAuthorizationService _authorizationService;
    
    public RbacController(IRbacService rbacService, IAuthorizationService authorizationService)
    {
        _rbacService = rbacService;
        _authorizationService = authorizationService;
    }
    
    [HttpPost("roles")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
    {
        var result = await _rbacService.CreateRoleAsync(request.Name, request.Description, request.Category);
        
        if (result)
            return Ok(new { Message = "Role created successfully" });
            
        return BadRequest("Failed to create role");
    }
    
    [HttpPost("permissions")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> CreatePermission([FromBody] CreatePermissionRequest request)
    {
        var result = await _rbacService.CreatePermissionAsync(
            request.Name, 
            request.Description, 
            request.Resource, 
            request.Action);
        
        if (result)
            return Ok(new { Message = "Permission created successfully" });
            
        return BadRequest("Failed to create permission");
    }
    
    [HttpPost("roles/{roleName}/permissions/{permissionId}")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> GrantPermissionToRole(string roleName, int permissionId)
    {
        var result = await _rbacService.GrantPermissionToRoleAsync(roleName, permissionId);
        
        if (result)
            return Ok(new { Message = "Permission granted successfully" });
            
        return BadRequest("Failed to grant permission");
    }
    
    [HttpPost("users/{userId}/roles/{roleName}")]
    [Authorize(Roles = "Administrator")]
    public async Task<IActionResult> AssignUserToRole(string userId, string roleName)
    {
        var result = await _rbacService.AssignUserToRoleAsync(userId, roleName);
        
        if (result)
            return Ok(new { Message = "User assigned to role successfully" });
            
        return BadRequest("Failed to assign user to role");
    }
    
    [HttpGet("users/{userId}/permissions")]
    public async Task<IActionResult> GetUserPermissions(string userId)
    {
        // Check if current user can view this information
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (currentUserId != userId && !User.IsInRole("Administrator"))
        {
            return Forbid();
        }
        
        var permissions = await _rbacService.GetEffectiveUserPermissionsAsync(userId);
        return Ok(permissions.Select(p => new
        {
            p.Id,
            p.Name,
            p.Resource,
            p.Action,
            p.Description
        }));
    }
    
    [HttpGet("users/{userId}/roles")]
    public async Task<IActionResult> GetUserRoles(string userId)
    {
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (currentUserId != userId && !User.IsInRole("Administrator"))
        {
            return Forbid();
        }
        
        var roles = await _rbacService.GetUserRolesAsync(userId);
        return Ok(roles.Select(r => new
        {
            r.Id,
            r.Name,
            r.Description,
            r.Category
        }));
    }
    
    [HttpGet("check-permission")]
    public async Task<IActionResult> CheckPermission([FromQuery] string resource, [FromQuery] string action)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var hasPermission = await _rbacService.UserHasPermissionAsync(userId, resource, action);
        
        return Ok(new { HasPermission = hasPermission });
    }
}

public class CreateRoleRequest
{
    [Required]
    public string Name { get; set; }
    
    public string Description { get; set; }
    public string Category { get; set; }
}

public class CreatePermissionRequest
{
    [Required]
    public string Name { get; set; }
    
    public string Description { get; set; }
    
    [Required]
    public string Resource { get; set; }
    
    [Required]
    public string Action { get; set; }
}
```

### 6. RBAC Startup Configuration

```csharp
public void ConfigureServices(IServiceCollection services)
{
    // Identity configuration
    services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 8;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddEntityFrameworkStores<RbacDbContext>()
    .AddDefaultTokenProviders();
    
    // RBAC services
    services.AddScoped<IRbacService, RbacService>();
    services.AddScoped<IAuthorizationHandler, RbacPermissionHandler>();
    
    // Authorization policies
    services.AddAuthorization(options =>
    {
        // Document permissions
        options.AddPolicy("CanReadDocuments", policy =>
            policy.Requirements.Add(new RbacPermissionRequirement("Document", "Read")));
            
        options.AddPolicy("CanCreateDocuments", policy =>
            policy.Requirements.Add(new RbacPermissionRequirement("Document", "Create")));
            
        options.AddPolicy("CanUpdateDocuments", policy =>
            policy.Requirements.Add(new RbacPermissionRequirement("Document", "Update")));
            
        options.AddPolicy("CanDeleteDocuments", policy =>
            policy.Requirements.Add(new RbacPermissionRequirement("Document", "Delete")));
            
        // User management permissions
        options.AddPolicy("CanManageUsers", policy =>
            policy.Requirements.Add(new RbacPermissionRequirement("User", "Manage")));
            
        // System administration
        options.AddPolicy("CanAccessAdminPanel", policy =>
            policy.Requirements.Add(new RbacPermissionRequirement("System", "Administrate")));
    });
    
    services.AddMemoryCache();
}
```

### 7. Data Seeding

```csharp
public class RbacDataSeeder
{
    public static async Task SeedAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        
        // Create permissions
        await CreatePermissionsAsync(rbacService);
        
        // Create roles
        await CreateRolesAsync(rbacService);
        
        // Assign permissions to roles
        await AssignPermissionsToRolesAsync(rbacService);
        
        // Create role hierarchy
        await CreateRoleHierarchyAsync(rbacService);
        
        // Create users and assign roles
        await CreateUsersAndAssignRolesAsync(userManager, rbacService);
    }
    
    private static async Task CreatePermissionsAsync(IRbacService rbacService)
    {
        var permissions = new[]
        {
            ("Read Documents", "Read documents", "Document", "Read"),
            ("Create Documents", "Create new documents", "Document", "Create"),
            ("Update Documents", "Update existing documents", "Document", "Update"),
            ("Delete Documents", "Delete documents", "Document", "Delete"),
            ("Manage Users", "Manage user accounts", "User", "Manage"),
            ("View Reports", "View system reports", "Report", "View"),
            ("Generate Reports", "Generate new reports", "Report", "Generate"),
            ("System Admin", "Full system administration", "System", "Administrate")
        };
        
        foreach (var (name, description, resource, action) in permissions)
        {
            await rbacService.CreatePermissionAsync(name, description, resource, action);
        }
    }
    
    private static async Task CreateRolesAsync(IRbacService rbacService)
    {
        var roles = new[]
        {
            ("Guest", "Basic read-only access", "General"),
            ("Employee", "Standard employee access", "General"),
            ("Manager", "Management access", "Management"),
            ("Administrator", "Full system access", "Administration"),
            ("HR Manager", "Human resources management", "HR"),
            ("Finance Manager", "Financial management", "Finance")
        };
        
        foreach (var (name, description, category) in roles)
        {
            await rbacService.CreateRoleAsync(name, description, category);
        }
    }
    
    private static async Task AssignPermissionsToRolesAsync(IRbacService rbacService)
    {
        // Guest permissions
        await rbacService.GrantPermissionToRoleAsync("Guest", 1); // Read Documents
        
        // Employee permissions (inherits Guest + additional)
        await rbacService.GrantPermissionToRoleAsync("Employee", 1); // Read Documents
        await rbacService.GrantPermissionToRoleAsync("Employee", 2); // Create Documents
        await rbacService.GrantPermissionToRoleAsync("Employee", 6); // View Reports
        
        // Manager permissions
        await rbacService.GrantPermissionToRoleAsync("Manager", 3); // Update Documents
        await rbacService.GrantPermissionToRoleAsync("Manager", 7); // Generate Reports
        
        // Administrator permissions
        await rbacService.GrantPermissionToRoleAsync("Administrator", 4); // Delete Documents
        await rbacService.GrantPermissionToRoleAsync("Administrator", 5); // Manage Users
        await rbacService.GrantPermissionToRoleAsync("Administrator", 8); // System Admin
    }
    
    private static async Task CreateRoleHierarchyAsync(IRbacService rbacService)
    {
        // Employee inherits from Guest
        await rbacService.CreateRoleHierarchyAsync("Employee", "Guest");
        
        // Manager inherits from Employee
        await rbacService.CreateRoleHierarchyAsync("Manager", "Employee");
        
        // Administrator inherits from Manager
        await rbacService.CreateRoleHierarchyAsync("Administrator", "Manager");
        
        // HR Manager inherits from Manager
        await rbacService.CreateRoleHierarchyAsync("HR Manager", "Manager");
        
        // Finance Manager inherits from Manager
        await rbacService.CreateRoleHierarchyAsync("Finance Manager", "Manager");
    }
}
```

## Security Best Practices

### 1. Role Design Principles
- **Principle of least privilege**: Assign minimum necessary permissions
- **Separation of duties**: Prevent conflicting roles for same user
- **Regular review**: Audit role assignments periodically
- **Role naming**: Use clear, descriptive role names
- **Documentation**: Document role purposes and permissions

### 2. Implementation Security
```csharp
public class RbacSecurityService
{
    public async Task<bool> ValidateRoleAssignmentAsync(string userId, string roleName)
    {
        // Check for separation of duty violations
        var conflictingRoles = GetConflictingRoles(roleName);
        var userRoles = await GetUserRolesAsync(userId);
        
        foreach (var conflictingRole in conflictingRoles)
        {
            if (userRoles.Any(r => r.Name == conflictingRole))
            {
                throw new InvalidOperationException($"Cannot assign {roleName} - conflicts with {conflictingRole}");
            }
        }
        
        return true;
    }
    
    private List<string> GetConflictingRoles(string roleName)
    {
        // Define role conflicts based on business rules
        return roleName switch
        {
            "Auditor" => new List<string> { "Administrator", "Finance Manager" },
            "Approver" => new List<string> { "Requester" },
            _ => new List<string>()
        };
    }
}
```

### 3. Performance Optimizations
```csharp
public class CachedRbacService : IRbacService
{
    private readonly IRbacService _baseService;
    private readonly IDistributedCache _cache;
    
    public async Task<bool> UserHasPermissionAsync(string userId, string resource, string action)
    {
        var cacheKey = $"rbac:user:{userId}:perm:{resource}:{action}";
        var cachedResult = await _cache.GetStringAsync(cacheKey);
        
        if (cachedResult != null)
        {
            return bool.Parse(cachedResult);
        }
        
        var result = await _baseService.UserHasPermissionAsync(userId, resource, action);
        
        await _cache.SetStringAsync(cacheKey, result.ToString(), new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30)
        });
        
        return result;
    }
}
```

## Testing Strategies

### 1. Unit Tests
```csharp
[TestFixture]
public class RbacServiceTests
{
    private IRbacService _rbacService;
    private Mock<UserManager<ApplicationUser>> _mockUserManager;
    private Mock<RoleManager<ApplicationRole>> _mockRoleManager;
    
    [SetUp]
    public void Setup()
    {
        // Setup mocks and dependencies
    }
    
    [Test]
    public async Task UserHasPermissionAsync_WithValidPermission_ShouldReturnTrue()
    {
        // Arrange
        var userId = "user123";
        var resource = "Document";
        var action = "Read";
        
        // Setup mock data
        SetupUserWithPermission(userId, resource, action);
        
        // Act
        var result = await _rbacService.UserHasPermissionAsync(userId, resource, action);
        
        // Assert
        Assert.IsTrue(result);
    }
    
    [Test]
    public async Task CreateRoleHierarchy_WithCircularReference_ShouldFail()
    {
        // Test circular reference prevention
        await _rbacService.CreateRoleHierarchyAsync("Manager", "Employee");
        
        var result = await _rbacService.CreateRoleHierarchyAsync("Employee", "Manager");
        
        Assert.IsFalse(result);
    }
}
```

### 2. Integration Tests
```csharp
[Test]
public async Task EndToEndRbacFlow_ShouldWorkCorrectly()
{
    // Create role
    await _rbacService.CreateRoleAsync("TestRole", "Test Description");
    
    // Create permission
    await _rbacService.CreatePermissionAsync("TestPerm", "Test Permission", "TestResource", "TestAction");
    
    // Grant permission to role
    await _rbacService.GrantPermissionToRoleAsync("TestRole", 1);
    
    // Create user and assign role
    var user = new ApplicationUser { UserName = "testuser", Email = "test@example.com" };
    await _userManager.CreateAsync(user, "Password123!");
    await _rbacService.AssignUserToRoleAsync(user.Id, "TestRole");
    
    // Check permission
    var hasPermission = await _rbacService.UserHasPermissionAsync(user.Id, "TestResource", "TestAction");
    
    Assert.IsTrue(hasPermission);
}
```

---
**Next**: Continue to `08-social-auth.md` to learn about social authentication implementation