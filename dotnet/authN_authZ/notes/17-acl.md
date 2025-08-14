# Access Control Lists (ACL)

## Overview
Access Control Lists (ACL) are a simple authorization model that specifies which users or systems are granted access to objects and what operations they can perform. ACLs provide fine-grained control over individual resources by maintaining a list of permissions for each object.

## Core Concepts

### 1. ACL Components

#### Access Control Entry (ACE)
- Individual permission entry in an ACL
- Specifies a principal (user/group) and their permissions
- Can be Allow or Deny entries
- Has inheritance and propagation flags

#### Principal
- User, group, or system that can be granted permissions
- Identified by unique identifier (SID, username, etc.)
- Can be individual users or groups of users

#### Permissions
- Specific actions that can be performed
- Examples: Read, Write, Delete, Execute, FullControl
- Can be combined (Read + Write = Modify)
- Can be object-specific

#### Access Control List
- Ordered collection of ACEs
- Evaluated top-to-bottom
- First matching rule typically wins
- Can have inheritance from parent objects

### 2. ACL Types

#### Discretionary Access Control List (DACL)
- Controls access to the object
- Owner can modify permissions
- Most common type of ACL

#### System Access Control List (SACL)
- Controls auditing of object access
- Requires special privileges to modify
- Used for security logging

### 3. ACL vs Other Models

#### Advantages
- **Fine-grained control**: Per-object permissions
- **Flexible**: Can grant different permissions to different users
- **Intuitive**: Easy to understand "who can do what"
- **Direct**: No intermediate roles or policies

#### Disadvantages
- **Scalability**: Can become unwieldy with many objects
- **Management**: Difficult to maintain consistency
- **Complexity**: Hard to audit across many objects
- **Performance**: Can be slow with large ACLs

## .NET ACL Implementation

### 1. Basic ACL Data Model

```csharp
// ACL Entity
public class AccessControlList
{
    public int Id { get; set; }
    public string ResourceId { get; set; }
    public string ResourceType { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string CreatedBy { get; set; }
    
    // Navigation properties
    public virtual ICollection<AccessControlEntry> Entries { get; set; } = new List<AccessControlEntry>();
}

// ACE Entity
public class AccessControlEntry
{
    public int Id { get; set; }
    public int AccessControlListId { get; set; }
    public string PrincipalId { get; set; }
    public string PrincipalType { get; set; } // User, Group, Role
    public string Permission { get; set; }
    public AccessType AccessType { get; set; } // Allow, Deny
    public int Order { get; set; }
    public bool IsInherited { get; set; }
    public DateTime CreatedAt { get; set; }
    public string CreatedBy { get; set; }
    
    // Navigation properties
    public virtual AccessControlList AccessControlList { get; set; }
}

public enum AccessType
{
    Allow = 0,
    Deny = 1
}

// Permission definitions
public static class Permissions
{
    public const string Read = "Read";
    public const string Write = "Write";
    public const string Delete = "Delete";
    public const string Execute = "Execute";
    public const string FullControl = "FullControl";
    public const string Modify = "Modify";
    public const string ReadWrite = "ReadWrite";
    
    // Document-specific permissions
    public const string ViewDocument = "ViewDocument";
    public const string EditDocument = "EditDocument";
    public const string DeleteDocument = "DeleteDocument";
    public const string ShareDocument = "ShareDocument";
    public const string PrintDocument = "PrintDocument";
    
    // Folder-specific permissions
    public const string ListContents = "ListContents";
    public const string CreateFiles = "CreateFiles";
    public const string CreateFolders = "CreateFolders";
    public const string DeleteSubfolders = "DeleteSubfolders";
    
    public static readonly Dictionary<string, string[]> PermissionHierarchy = new()
    {
        [FullControl] = new[] { Read, Write, Delete, Execute, Modify },
        [Modify] = new[] { Read, Write, Delete },
        [ReadWrite] = new[] { Read, Write },
        [Write] = new[] { Read }
    };
}
```

### 2. ACL Service Implementation

```csharp
public interface IAclService
{
    Task<bool> HasPermissionAsync(string principalId, string resourceId, string permission);
    Task<AccessControlList> GetAclAsync(string resourceId, string resourceType);
    Task<bool> GrantPermissionAsync(string resourceId, string principalId, string permission, string principalType = "User");
    Task<bool> DenyPermissionAsync(string resourceId, string principalId, string permission, string principalType = "User");
    Task<bool> RevokePermissionAsync(string resourceId, string principalId, string permission);
    Task<List<string>> GetUserPermissionsAsync(string principalId, string resourceId);
    Task<List<AccessControlEntry>> GetEffectivePermissionsAsync(string principalId, string resourceId);
    Task<bool> CopyAclAsync(string sourceResourceId, string targetResourceId);
    Task<bool> InheritFromParentAsync(string resourceId, string parentResourceId);
}

public class AclService : IAclService
{
    private readonly AclDbContext _context;
    private readonly IUserService _userService;
    private readonly IMemoryCache _cache;
    private readonly ILogger<AclService> _logger;
    
    public AclService(
        AclDbContext context,
        IUserService userService,
        IMemoryCache cache,
        ILogger<AclService> logger)
    {
        _context = context;
        _userService = userService;
        _cache = cache;
        _logger = logger;
    }
    
    public async Task<bool> HasPermissionAsync(string principalId, string resourceId, string permission)
    {
        try
        {
            var cacheKey = $"acl_permission_{principalId}_{resourceId}_{permission}";
            
            if (_cache.TryGetValue(cacheKey, out bool cachedResult))
                return cachedResult;
            
            var effectivePermissions = await GetEffectivePermissionsAsync(principalId, resourceId);
            
            // Check for explicit deny first
            var denyEntry = effectivePermissions
                .Where(ace => ace.AccessType == AccessType.Deny)
                .FirstOrDefault(ace => HasSpecificPermission(ace.Permission, permission));
            
            if (denyEntry != null)
            {
                _cache.Set(cacheKey, false, TimeSpan.FromMinutes(5));
                return false;
            }
            
            // Check for allow
            var allowEntry = effectivePermissions
                .Where(ace => ace.AccessType == AccessType.Allow)
                .FirstOrDefault(ace => HasSpecificPermission(ace.Permission, permission));
            
            var hasPermission = allowEntry != null;
            _cache.Set(cacheKey, hasPermission, TimeSpan.FromMinutes(5));
            
            return hasPermission;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking permission {Permission} for principal {PrincipalId} on resource {ResourceId}",
                permission, principalId, resourceId);
            return false; // Fail secure
        }
    }
    
    public async Task<List<AccessControlEntry>> GetEffectivePermissionsAsync(string principalId, string resourceId)
    {
        var acl = await GetAclAsync(resourceId, "Document"); // Default to Document type
        if (acl == null)
            return new List<AccessControlEntry>();
        
        var userGroups = await _userService.GetUserGroupsAsync(principalId);
        var userRoles = await _userService.GetUserRolesAsync(principalId);
        
        var effectiveEntries = acl.Entries
            .Where(ace => 
                ace.PrincipalId == principalId || // Direct user permission
                (ace.PrincipalType == "Group" && userGroups.Contains(ace.PrincipalId)) || // Group membership
                (ace.PrincipalType == "Role" && userRoles.Contains(ace.PrincipalId))) // Role membership
            .OrderBy(ace => ace.Order)
            .ThenBy(ace => ace.AccessType) // Deny entries first
            .ToList();
        
        return effectiveEntries;
    }
    
    public async Task<bool> GrantPermissionAsync(string resourceId, string principalId, string permission, string principalType = "User")
    {
        try
        {
            var acl = await GetOrCreateAclAsync(resourceId, "Document");
            
            // Remove any existing deny entries for this principal/permission
            var existingDeny = acl.Entries
                .Where(ace => ace.PrincipalId == principalId && 
                             ace.Permission == permission && 
                             ace.AccessType == AccessType.Deny)
                .ToList();
            
            foreach (var denyEntry in existingDeny)
            {
                acl.Entries.Remove(denyEntry);
            }
            
            // Check if allow entry already exists
            var existingAllow = acl.Entries
                .FirstOrDefault(ace => ace.PrincipalId == principalId && 
                                      ace.Permission == permission && 
                                      ace.AccessType == AccessType.Allow);
            
            if (existingAllow == null)
            {
                var newEntry = new AccessControlEntry
                {
                    AccessControlListId = acl.Id,
                    PrincipalId = principalId,
                    PrincipalType = principalType,
                    Permission = permission,
                    AccessType = AccessType.Allow,
                    Order = acl.Entries.Count,
                    CreatedAt = DateTime.UtcNow,
                    CreatedBy = "System" // In real app, use current user
                };
                
                acl.Entries.Add(newEntry);
            }
            
            acl.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            
            InvalidateCache(principalId, resourceId);
            
            _logger.LogInformation("Granted {Permission} permission to {PrincipalId} for resource {ResourceId}",
                permission, principalId, resourceId);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error granting permission {Permission} to {PrincipalId} for resource {ResourceId}",
                permission, principalId, resourceId);
            return false;
        }
    }
    
    public async Task<bool> DenyPermissionAsync(string resourceId, string principalId, string permission, string principalType = "User")
    {
        try
        {
            var acl = await GetOrCreateAclAsync(resourceId, "Document");
            
            // Remove any existing allow entries for this principal/permission
            var existingAllow = acl.Entries
                .Where(ace => ace.PrincipalId == principalId && 
                             ace.Permission == permission && 
                             ace.AccessType == AccessType.Allow)
                .ToList();
            
            foreach (var allowEntry in existingAllow)
            {
                acl.Entries.Remove(allowEntry);
            }
            
            // Check if deny entry already exists
            var existingDeny = acl.Entries
                .FirstOrDefault(ace => ace.PrincipalId == principalId && 
                                      ace.Permission == permission && 
                                      ace.AccessType == AccessType.Deny);
            
            if (existingDeny == null)
            {
                var newEntry = new AccessControlEntry
                {
                    AccessControlListId = acl.Id,
                    PrincipalId = principalId,
                    PrincipalType = principalType,
                    Permission = permission,
                    AccessType = AccessType.Deny,
                    Order = 0, // Deny entries get higher priority
                    CreatedAt = DateTime.UtcNow,
                    CreatedBy = "System"
                };
                
                // Reorder existing entries
                foreach (var entry in acl.Entries)
                {
                    entry.Order++;
                }
                
                acl.Entries.Add(newEntry);
            }
            
            acl.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            
            InvalidateCache(principalId, resourceId);
            
            _logger.LogInformation("Denied {Permission} permission to {PrincipalId} for resource {ResourceId}",
                permission, principalId, resourceId);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error denying permission {Permission} to {PrincipalId} for resource {ResourceId}",
                permission, principalId, resourceId);
            return false;
        }
    }
    
    public async Task<bool> RevokePermissionAsync(string resourceId, string principalId, string permission)
    {
        try
        {
            var acl = await GetAclAsync(resourceId, "Document");
            if (acl == null)
                return true; // No ACL means no permissions
            
            var entriesToRemove = acl.Entries
                .Where(ace => ace.PrincipalId == principalId && ace.Permission == permission)
                .ToList();
            
            foreach (var entry in entriesToRemove)
            {
                acl.Entries.Remove(entry);
            }
            
            if (entriesToRemove.Any())
            {
                acl.UpdatedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();
                
                InvalidateCache(principalId, resourceId);
                
                _logger.LogInformation("Revoked {Permission} permission from {PrincipalId} for resource {ResourceId}",
                    permission, principalId, resourceId);
            }
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking permission {Permission} from {PrincipalId} for resource {ResourceId}",
                permission, principalId, resourceId);
            return false;
        }
    }
    
    public async Task<List<string>> GetUserPermissionsAsync(string principalId, string resourceId)
    {
        var effectivePermissions = await GetEffectivePermissionsAsync(principalId, resourceId);
        var permissions = new HashSet<string>();
        
        // Process entries in order (deny first, then allow)
        var deniedPermissions = new HashSet<string>();
        
        foreach (var ace in effectivePermissions.Where(ace => ace.AccessType == AccessType.Deny))
        {
            deniedPermissions.Add(ace.Permission);
            // Also deny any sub-permissions
            if (Permissions.PermissionHierarchy.ContainsKey(ace.Permission))
            {
                foreach (var subPermission in Permissions.PermissionHierarchy[ace.Permission])
                {
                    deniedPermissions.Add(subPermission);
                }
            }
        }
        
        foreach (var ace in effectivePermissions.Where(ace => ace.AccessType == AccessType.Allow))
        {
            if (!deniedPermissions.Contains(ace.Permission))
            {
                permissions.Add(ace.Permission);
                
                // Add sub-permissions
                if (Permissions.PermissionHierarchy.ContainsKey(ace.Permission))
                {
                    foreach (var subPermission in Permissions.PermissionHierarchy[ace.Permission])
                    {
                        if (!deniedPermissions.Contains(subPermission))
                        {
                            permissions.Add(subPermission);
                        }
                    }
                }
            }
        }
        
        return permissions.ToList();
    }
    
    public async Task<AccessControlList> GetAclAsync(string resourceId, string resourceType)
    {
        return await _context.AccessControlLists
            .Include(acl => acl.Entries)
            .FirstOrDefaultAsync(acl => acl.ResourceId == resourceId && acl.ResourceType == resourceType);
    }
    
    public async Task<bool> CopyAclAsync(string sourceResourceId, string targetResourceId)
    {
        try
        {
            var sourceAcl = await GetAclAsync(sourceResourceId, "Document");
            if (sourceAcl == null)
                return true;
            
            var targetAcl = await GetOrCreateAclAsync(targetResourceId, "Document");
            
            // Clear existing entries
            targetAcl.Entries.Clear();
            
            // Copy entries
            foreach (var sourceEntry in sourceAcl.Entries)
            {
                var newEntry = new AccessControlEntry
                {
                    AccessControlListId = targetAcl.Id,
                    PrincipalId = sourceEntry.PrincipalId,
                    PrincipalType = sourceEntry.PrincipalType,
                    Permission = sourceEntry.Permission,
                    AccessType = sourceEntry.AccessType,
                    Order = sourceEntry.Order,
                    CreatedAt = DateTime.UtcNow,
                    CreatedBy = "System"
                };
                
                targetAcl.Entries.Add(newEntry);
            }
            
            targetAcl.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error copying ACL from {SourceId} to {TargetId}", sourceResourceId, targetResourceId);
            return false;
        }
    }
    
    private async Task<AccessControlList> GetOrCreateAclAsync(string resourceId, string resourceType)
    {
        var acl = await GetAclAsync(resourceId, resourceType);
        
        if (acl == null)
        {
            acl = new AccessControlList
            {
                ResourceId = resourceId,
                ResourceType = resourceType,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                CreatedBy = "System"
            };
            
            _context.AccessControlLists.Add(acl);
            await _context.SaveChangesAsync();
        }
        
        return acl;
    }
    
    private bool HasSpecificPermission(string grantedPermission, string requiredPermission)
    {
        if (grantedPermission == requiredPermission)
            return true;
        
        // Check if granted permission includes the required permission
        if (Permissions.PermissionHierarchy.ContainsKey(grantedPermission))
        {
            return Permissions.PermissionHierarchy[grantedPermission].Contains(requiredPermission);
        }
        
        return false;
    }
    
    private void InvalidateCache(string principalId, string resourceId)
    {
        // Simple cache invalidation - in production, use a more sophisticated approach
        var keysToRemove = new List<string>();
        
        // This is a simplified approach - you'd want a more efficient cache invalidation strategy
        foreach (var permission in new[] { "Read", "Write", "Delete", "Execute", "FullControl" })
        {
            keysToRemove.Add($"acl_permission_{principalId}_{resourceId}_{permission}");
        }
        
        foreach (var key in keysToRemove)
        {
            _cache.Remove(key);
        }
    }
    
    public async Task<bool> InheritFromParentAsync(string resourceId, string parentResourceId)
    {
        // Implementation for ACL inheritance
        var parentAcl = await GetAclAsync(parentResourceId, "Document");
        if (parentAcl == null)
            return true;
        
        var childAcl = await GetOrCreateAclAsync(resourceId, "Document");
        
        // Add inherited entries
        foreach (var parentEntry in parentAcl.Entries)
        {
            var inheritedEntry = new AccessControlEntry
            {
                AccessControlListId = childAcl.Id,
                PrincipalId = parentEntry.PrincipalId,
                PrincipalType = parentEntry.PrincipalType,
                Permission = parentEntry.Permission,
                AccessType = parentEntry.AccessType,
                Order = parentEntry.Order + 1000, // Lower priority than direct entries
                IsInherited = true,
                CreatedAt = DateTime.UtcNow,
                CreatedBy = "System"
            };
            
            childAcl.Entries.Add(inheritedEntry);
        }
        
        await _context.SaveChangesAsync();
        return true;
    }
}
```

### 3. ACL Authorization Handler

```csharp
public class AclAuthorizationRequirement : IAuthorizationRequirement
{
    public string Permission { get; }
    
    public AclAuthorizationRequirement(string permission)
    {
        Permission = permission;
    }
}

public class AclAuthorizationHandler : AuthorizationHandler<AclAuthorizationRequirement, IResource>
{
    private readonly IAclService _aclService;
    
    public AclAuthorizationHandler(IAclService aclService)
    {
        _aclService = aclService;
    }
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AclAuthorizationRequirement requirement,
        IResource resource)
    {
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
        {
            context.Fail();
            return;
        }
        
        var hasPermission = await _aclService.HasPermissionAsync(
            userId, 
            resource.Id.ToString(), 
            requirement.Permission);
        
        if (hasPermission)
        {
            context.Succeed(requirement);
        }
    }
}

public interface IResource
{
    int Id { get; }
    string ResourceType { get; }
}

public class Document : IResource
{
    public int Id { get; set; }
    public string ResourceType => "Document";
    public string Title { get; set; }
    public string Content { get; set; }
    public string OwnerId { get; set; }
    public DateTime CreatedAt { get; set; }
}
```

### 4. ACL Controller

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AclController : ControllerBase
{
    private readonly IAclService _aclService;
    private readonly IAuthorizationService _authorizationService;
    
    public AclController(IAclService aclService, IAuthorizationService authorizationService)
    {
        _aclService = aclService;
        _authorizationService = authorizationService;
    }
    
    [HttpGet("resource/{resourceId}/permissions")]
    public async Task<IActionResult> GetResourcePermissions(string resourceId, [FromQuery] string userId = null)
    {
        userId ??= User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (string.IsNullOrEmpty(userId))
            return BadRequest("User ID is required");
        
        var permissions = await _aclService.GetUserPermissionsAsync(userId, resourceId);
        
        return Ok(new
        {
            ResourceId = resourceId,
            UserId = userId,
            Permissions = permissions
        });
    }
    
    [HttpPost("resource/{resourceId}/grant")]
    public async Task<IActionResult> GrantPermission(
        string resourceId, 
        [FromBody] GrantPermissionRequest request)
    {
        // Check if current user can manage permissions for this resource
        var canManage = await _aclService.HasPermissionAsync(
            User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            resourceId,
            Permissions.FullControl);
        
        if (!canManage)
            return Forbid("You don't have permission to manage this resource");
        
        var result = await _aclService.GrantPermissionAsync(
            resourceId, 
            request.PrincipalId, 
            request.Permission, 
            request.PrincipalType);
        
        if (result)
            return Ok(new { Message = "Permission granted successfully" });
            
        return BadRequest("Failed to grant permission");
    }
    
    [HttpPost("resource/{resourceId}/deny")]
    public async Task<IActionResult> DenyPermission(
        string resourceId, 
        [FromBody] DenyPermissionRequest request)
    {
        var canManage = await _aclService.HasPermissionAsync(
            User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            resourceId,
            Permissions.FullControl);
        
        if (!canManage)
            return Forbid("You don't have permission to manage this resource");
        
        var result = await _aclService.DenyPermissionAsync(
            resourceId, 
            request.PrincipalId, 
            request.Permission, 
            request.PrincipalType);
        
        if (result)
            return Ok(new { Message = "Permission denied successfully" });
            
        return BadRequest("Failed to deny permission");
    }
    
    [HttpDelete("resource/{resourceId}/revoke")]
    public async Task<IActionResult> RevokePermission(
        string resourceId,
        [FromQuery] string principalId,
        [FromQuery] string permission)
    {
        var canManage = await _aclService.HasPermissionAsync(
            User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            resourceId,
            Permissions.FullControl);
        
        if (!canManage)
            return Forbid("You don't have permission to manage this resource");
        
        var result = await _aclService.RevokePermissionAsync(resourceId, principalId, permission);
        
        if (result)
            return Ok(new { Message = "Permission revoked successfully" });
            
        return BadRequest("Failed to revoke permission");
    }
    
    [HttpGet("resource/{resourceId}/acl")]
    public async Task<IActionResult> GetAcl(string resourceId)
    {
        var canView = await _aclService.HasPermissionAsync(
            User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            resourceId,
            Permissions.Read);
        
        if (!canView)
            return Forbid("You don't have permission to view this resource");
        
        var acl = await _aclService.GetAclAsync(resourceId, "Document");
        
        if (acl == null)
            return NotFound("ACL not found for this resource");
        
        return Ok(new
        {
            ResourceId = resourceId,
            Entries = acl.Entries.Select(ace => new
            {
                ace.PrincipalId,
                ace.PrincipalType,
                ace.Permission,
                AccessType = ace.AccessType.ToString(),
                ace.IsInherited,
                ace.CreatedAt
            }).OrderBy(ace => ace.AccessType).ThenBy(ace => ace.PrincipalId)
        });
    }
    
    [HttpPost("resource/{resourceId}/copy-from/{sourceResourceId}")]
    public async Task<IActionResult> CopyAcl(string resourceId, string sourceResourceId)
    {
        var canManageSource = await _aclService.HasPermissionAsync(
            User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            sourceResourceId,
            Permissions.Read);
        
        var canManageTarget = await _aclService.HasPermissionAsync(
            User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            resourceId,
            Permissions.FullControl);
        
        if (!canManageSource || !canManageTarget)
            return Forbid("Insufficient permissions to copy ACL");
        
        var result = await _aclService.CopyAclAsync(sourceResourceId, resourceId);
        
        if (result)
            return Ok(new { Message = "ACL copied successfully" });
            
        return BadRequest("Failed to copy ACL");
    }
}

public class GrantPermissionRequest
{
    [Required]
    public string PrincipalId { get; set; }
    
    [Required]
    public string Permission { get; set; }
    
    public string PrincipalType { get; set; } = "User";
}

public class DenyPermissionRequest
{
    [Required]
    public string PrincipalId { get; set; }
    
    [Required]
    public string Permission { get; set; }
    
    public string PrincipalType { get; set; } = "User";
}
```

## Security Best Practices

### 1. ACL Security Considerations
```csharp
public class AclSecurityService
{
    public bool ValidatePermissionRequest(string requestingUserId, string resourceId, string permission)
    {
        // Prevent privilege escalation
        if (permission == Permissions.FullControl)
        {
            // Only resource owners or administrators can grant FullControl
            return IsResourceOwner(requestingUserId, resourceId) || IsAdministrator(requestingUserId);
        }
        
        // Validate permission exists
        var validPermissions = new[] 
        { 
            Permissions.Read, Permissions.Write, Permissions.Delete, 
            Permissions.Execute, Permissions.FullControl, Permissions.Modify 
        };
        
        return validPermissions.Contains(permission);
    }
    
    public bool PreventCircularInheritance(string resourceId, string parentResourceId)
    {
        // Implement logic to prevent circular inheritance
        // This would involve checking the inheritance chain
        return true; // Simplified
    }
    
    private bool IsResourceOwner(string userId, string resourceId)
    {
        // Implementation to check resource ownership
        return false; // Simplified
    }
    
    private bool IsAdministrator(string userId)
    {
        // Implementation to check if user is administrator
        return false; // Simplified
    }
}
```

### 2. Performance Optimization
```csharp
public class OptimizedAclService : IAclService
{
    private readonly IDistributedCache _cache;
    private readonly IAclService _baseService;
    
    public async Task<bool> HasPermissionAsync(string principalId, string resourceId, string permission)
    {
        // Use distributed cache for better performance
        var cacheKey = $"acl:{principalId}:{resourceId}:{permission}";
        var cachedResult = await _cache.GetStringAsync(cacheKey);
        
        if (cachedResult != null)
        {
            return bool.Parse(cachedResult);
        }
        
        var result = await _baseService.HasPermissionAsync(principalId, resourceId, permission);
        
        await _cache.SetStringAsync(cacheKey, result.ToString(), new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15)
        });
        
        return result;
    }
    
    // Implement other methods with caching...
    public Task<AccessControlList> GetAclAsync(string resourceId, string resourceType) => _baseService.GetAclAsync(resourceId, resourceType);
    public Task<bool> GrantPermissionAsync(string resourceId, string principalId, string permission, string principalType = "User") => _baseService.GrantPermissionAsync(resourceId, principalId, permission, principalType);
    public Task<bool> DenyPermissionAsync(string resourceId, string principalId, string permission, string principalType = "User") => _baseService.DenyPermissionAsync(resourceId, principalId, permission, principalType);
    public Task<bool> RevokePermissionAsync(string resourceId, string principalId, string permission) => _baseService.RevokePermissionAsync(resourceId, principalId, permission);
    public Task<List<string>> GetUserPermissionsAsync(string principalId, string resourceId) => _baseService.GetUserPermissionsAsync(principalId, resourceId);
    public Task<List<AccessControlEntry>> GetEffectivePermissionsAsync(string principalId, string resourceId) => _baseService.GetEffectivePermissionsAsync(principalId, resourceId);
    public Task<bool> CopyAclAsync(string sourceResourceId, string targetResourceId) => _baseService.CopyAclAsync(sourceResourceId, targetResourceId);
    public Task<bool> InheritFromParentAsync(string resourceId, string parentResourceId) => _baseService.InheritFromParentAsync(resourceId, parentResourceId);
}
```

## Testing Strategies

### 1. Unit Tests
```csharp
[TestFixture]
public class AclServiceTests
{
    private AclService _aclService;
    private Mock<AclDbContext> _mockContext;
    private Mock<IUserService> _mockUserService;
    
    [SetUp]
    public void Setup()
    {
        _mockContext = new Mock<AclDbContext>();
        _mockUserService = new Mock<IUserService>();
        _aclService = new AclService(_mockContext.Object, _mockUserService.Object, null, null);
    }
    
    [Test]
    public async Task HasPermissionAsync_WithAllowEntry_ShouldReturnTrue()
    {
        // Arrange
        var principalId = "user123";
        var resourceId = "resource456";
        var permission = Permissions.Read;
        
        SetupMockAcl(resourceId, new[]
        {
            new AccessControlEntry
            {
                PrincipalId = principalId,
                Permission = permission,
                AccessType = AccessType.Allow
            }
        });
        
        // Act
        var result = await _aclService.HasPermissionAsync(principalId, resourceId, permission);
        
        // Assert
        Assert.IsTrue(result);
    }
    
    [Test]
    public async Task HasPermissionAsync_WithDenyEntry_ShouldReturnFalse()
    {
        // Arrange
        var principalId = "user123";
        var resourceId = "resource456";
        var permission = Permissions.Read;
        
        SetupMockAcl(resourceId, new[]
        {
            new AccessControlEntry
            {
                PrincipalId = principalId,
                Permission = permission,
                AccessType = AccessType.Deny
            }
        });
        
        // Act
        var result = await _aclService.HasPermissionAsync(principalId, resourceId, permission);
        
        // Assert
        Assert.IsFalse(result);
    }
}
```

### 2. Integration Tests
```csharp
[Test]
public async Task AclWorkflow_GrantAndCheckPermission_ShouldWork()
{
    // Grant permission
    var grantResult = await _aclService.GrantPermissionAsync("resource1", "user1", Permissions.Read);
    Assert.IsTrue(grantResult);
    
    // Check permission
    var hasPermission = await _aclService.HasPermissionAsync("user1", "resource1", Permissions.Read);
    Assert.IsTrue(hasPermission);
    
    // Revoke permission
    var revokeResult = await _aclService.RevokePermissionAsync("resource1", "user1", Permissions.Read);
    Assert.IsTrue(revokeResult);
    
    // Check permission again
    var hasPermissionAfterRevoke = await _aclService.HasPermissionAsync("user1", "resource1", Permissions.Read);
    Assert.IsFalse(hasPermissionAfterRevoke);
}
```

---
**Next**: Continue to `14-abac.md` to learn about Attribute-Based Access Control