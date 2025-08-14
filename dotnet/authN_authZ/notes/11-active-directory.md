# Active Directory Integration

## Overview
Active Directory (AD) is Microsoft's directory service that stores information about objects on a network and makes this information available to users and network administrators. In .NET applications, AD integration provides enterprise-level authentication, authorization, and user management capabilities.

## Core Concepts

### 1. Active Directory Components

#### Domain Controller (DC)
- Server running Active Directory Domain Services
- Stores directory database
- Handles authentication requests
- Replicates data with other domain controllers

#### Domain
- Security boundary containing users, computers, and resources
- Has unique DNS name (e.g., company.com)
- Contains organizational units (OUs)

#### Forest
- Collection of one or more domains
- Shares common schema and configuration
- Represents complete AD deployment

#### Organizational Units (OUs)
- Containers for organizing AD objects
- Used for delegation and Group Policy application
- Can contain users, groups, computers, other OUs

#### Groups
- Security groups for permissions
- Distribution groups for email lists
- Nested group membership supported

### 2. Authentication Protocols

#### LDAP (Lightweight Directory Access Protocol)
- Protocol for accessing directory services
- Runs on port 389 (636 for LDAPS)
- Used for queries and authentication

#### Kerberos
- Ticket-based authentication protocol
- Default for Windows domain authentication
- More secure than NTLM

#### NTLM (NT LAN Manager)
- Challenge-response authentication
- Legacy protocol, still widely used
- Less secure than Kerberos

## .NET Active Directory Implementation

### 1. LDAP Authentication

#### Installation
```bash
dotnet add package System.DirectoryServices
dotnet add package System.DirectoryServices.AccountManagement
dotnet add package Microsoft.Extensions.Configuration
```

#### Basic LDAP Service
```csharp
public interface IActiveDirectoryService
{
    Task<bool> AuthenticateUserAsync(string username, string password);
    Task<ADUser> GetUserAsync(string username);
    Task<List<string>> GetUserGroupsAsync(string username);
    Task<List<ADUser>> SearchUsersAsync(string searchTerm);
    Task<bool> IsUserInGroupAsync(string username, string groupName);
    Task<List<ADUser>> GetUsersInGroupAsync(string groupName);
}

public class ActiveDirectoryService : IActiveDirectoryService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<ActiveDirectoryService> _logger;
    
    private string LdapServer => _configuration["ActiveDirectory:Server"];
    private int LdapPort => int.Parse(_configuration["ActiveDirectory:Port"] ?? "389");
    private string BaseDN => _configuration["ActiveDirectory:BaseDN"];
    private string ServiceAccount => _configuration["ActiveDirectory:ServiceAccount"];
    private string ServicePassword => _configuration["ActiveDirectory:ServicePassword"];
    private bool UseSSL => bool.Parse(_configuration["ActiveDirectory:UseSSL"] ?? "false");
    
    public ActiveDirectoryService(IConfiguration configuration, ILogger<ActiveDirectoryService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }
    
    public async Task<bool> AuthenticateUserAsync(string username, string password)
    {
        try
        {
            using var connection = new LdapConnection(new LdapDirectoryIdentifier(LdapServer, LdapPort));
            
            if (UseSSL)
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }
            
            // First, bind with service account to search for user
            connection.Bind(new NetworkCredential(ServiceAccount, ServicePassword));
            
            // Search for user
            var searchRequest = new SearchRequest
            {
                DistinguishedName = BaseDN,
                Filter = $"(&(objectClass=user)(sAMAccountName={username}))",
                Scope = SearchScope.Subtree
            };
            
            searchRequest.Attributes.Add("distinguishedName");
            
            var searchResponse = (SearchResponse)await Task.Run(() => connection.SendRequest(searchRequest));
            
            if (searchResponse.Entries.Count == 0)
            {
                _logger.LogWarning("User {Username} not found in Active Directory", username);
                return false;
            }
            
            var userDN = searchResponse.Entries[0].DistinguishedName;
            
            // Try to bind with user credentials
            try
            {
                connection.Bind(new NetworkCredential(userDN, password));
                _logger.LogInformation("User {Username} authenticated successfully", username);
                return true;
            }
            catch (LdapException ex) when (ex.ErrorCode == 49) // Invalid credentials
            {
                _logger.LogWarning("Invalid credentials for user {Username}", username);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error authenticating user {Username}", username);
            return false;
        }
    }
    
    public async Task<ADUser> GetUserAsync(string username)
    {
        try
        {
            using var connection = new LdapConnection(new LdapDirectoryIdentifier(LdapServer, LdapPort));
            
            if (UseSSL)
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }
            
            connection.Bind(new NetworkCredential(ServiceAccount, ServicePassword));
            
            var searchRequest = new SearchRequest
            {
                DistinguishedName = BaseDN,
                Filter = $"(&(objectClass=user)(sAMAccountName={username}))",
                Scope = SearchScope.Subtree
            };
            
            // Add attributes to retrieve
            var attributes = new[]
            {
                "sAMAccountName", "displayName", "givenName", "sn", "mail",
                "telephoneNumber", "department", "title", "manager",
                "memberOf", "whenCreated", "whenChanged", "userAccountControl"
            };
            
            foreach (var attr in attributes)
            {
                searchRequest.Attributes.Add(attr);
            }
            
            var searchResponse = (SearchResponse)await Task.Run(() => connection.SendRequest(searchRequest));
            
            if (searchResponse.Entries.Count == 0)
                return null;
            
            var entry = searchResponse.Entries[0];
            
            return new ADUser
            {
                Username = GetAttributeValue(entry, "sAMAccountName"),
                DisplayName = GetAttributeValue(entry, "displayName"),
                FirstName = GetAttributeValue(entry, "givenName"),
                LastName = GetAttributeValue(entry, "sn"),
                Email = GetAttributeValue(entry, "mail"),
                Phone = GetAttributeValue(entry, "telephoneNumber"),
                Department = GetAttributeValue(entry, "department"),
                Title = GetAttributeValue(entry, "title"),
                Manager = GetAttributeValue(entry, "manager"),
                DistinguishedName = entry.DistinguishedName,
                IsEnabled = IsAccountEnabled(GetAttributeValue(entry, "userAccountControl")),
                CreatedDate = ParseDate(GetAttributeValue(entry, "whenCreated")),
                ModifiedDate = ParseDate(GetAttributeValue(entry, "whenChanged")),
                Groups = GetAttributeValues(entry, "memberOf")
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving user {Username}", username);
            return null;
        }
    }
    
    public async Task<List<string>> GetUserGroupsAsync(string username)
    {
        try
        {
            var user = await GetUserAsync(username);
            if (user == null) return new List<string>();
            
            var groups = new List<string>();
            
            foreach (var groupDN in user.Groups)
            {
                var groupName = ExtractCNFromDN(groupDN);
                if (!string.IsNullOrEmpty(groupName))
                {
                    groups.Add(groupName);
                }
            }
            
            return groups;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving groups for user {Username}", username);
            return new List<string>();
        }
    }
    
    public async Task<List<ADUser>> SearchUsersAsync(string searchTerm)
    {
        try
        {
            using var connection = new LdapConnection(new LdapDirectoryIdentifier(LdapServer, LdapPort));
            
            if (UseSSL)
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }
            
            connection.Bind(new NetworkCredential(ServiceAccount, ServicePassword));
            
            var filter = $"(&(objectClass=user)(|(sAMAccountName=*{searchTerm}*)(displayName=*{searchTerm}*)(mail=*{searchTerm}*)))";
            
            var searchRequest = new SearchRequest
            {
                DistinguishedName = BaseDN,
                Filter = filter,
                Scope = SearchScope.Subtree,
                SizeLimit = 100 // Limit results
            };
            
            var attributes = new[] { "sAMAccountName", "displayName", "mail", "department" };
            foreach (var attr in attributes)
            {
                searchRequest.Attributes.Add(attr);
            }
            
            var searchResponse = (SearchResponse)await Task.Run(() => connection.SendRequest(searchRequest));
            
            var users = new List<ADUser>();
            
            foreach (SearchResultEntry entry in searchResponse.Entries)
            {
                users.Add(new ADUser
                {
                    Username = GetAttributeValue(entry, "sAMAccountName"),
                    DisplayName = GetAttributeValue(entry, "displayName"),
                    Email = GetAttributeValue(entry, "mail"),
                    Department = GetAttributeValue(entry, "department")
                });
            }
            
            return users;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error searching for users with term {SearchTerm}", searchTerm);
            return new List<ADUser>();
        }
    }
    
    public async Task<bool> IsUserInGroupAsync(string username, string groupName)
    {
        var userGroups = await GetUserGroupsAsync(username);
        return userGroups.Contains(groupName, StringComparer.OrdinalIgnoreCase);
    }
    
    public async Task<List<ADUser>> GetUsersInGroupAsync(string groupName)
    {
        try
        {
            using var connection = new LdapConnection(new LdapDirectoryIdentifier(LdapServer, LdapPort));
            
            if (UseSSL)
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }
            
            connection.Bind(new NetworkCredential(ServiceAccount, ServicePassword));
            
            // First, find the group
            var groupSearchRequest = new SearchRequest
            {
                DistinguishedName = BaseDN,
                Filter = $"(&(objectClass=group)(cn={groupName}))",
                Scope = SearchScope.Subtree
            };
            
            groupSearchRequest.Attributes.Add("member");
            
            var groupSearchResponse = (SearchResponse)await Task.Run(() => connection.SendRequest(groupSearchRequest));
            
            if (groupSearchResponse.Entries.Count == 0)
                return new List<ADUser>();
            
            var memberDNs = GetAttributeValues(groupSearchResponse.Entries[0], "member");
            var users = new List<ADUser>();
            
            // Get details for each member
            foreach (var memberDN in memberDNs)
            {
                var userSearchRequest = new SearchRequest
                {
                    DistinguishedName = memberDN,
                    Filter = "(objectClass=user)",
                    Scope = SearchScope.Base
                };
                
                userSearchRequest.Attributes.Add("sAMAccountName");
                userSearchRequest.Attributes.Add("displayName");
                userSearchRequest.Attributes.Add("mail");
                
                try
                {
                    var userSearchResponse = (SearchResponse)await Task.Run(() => connection.SendRequest(userSearchRequest));
                    
                    if (userSearchResponse.Entries.Count > 0)
                    {
                        var entry = userSearchResponse.Entries[0];
                        users.Add(new ADUser
                        {
                            Username = GetAttributeValue(entry, "sAMAccountName"),
                            DisplayName = GetAttributeValue(entry, "displayName"),
                            Email = GetAttributeValue(entry, "mail"),
                            DistinguishedName = entry.DistinguishedName
                        });
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error retrieving details for member {MemberDN}", memberDN);
                }
            }
            
            return users;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving users in group {GroupName}", groupName);
            return new List<ADUser>();
        }
    }
    
    private string GetAttributeValue(SearchResultEntry entry, string attributeName)
    {
        if (entry.Attributes.Contains(attributeName))
        {
            var attribute = entry.Attributes[attributeName];
            if (attribute.Count > 0)
            {
                return attribute[0]?.ToString();
            }
        }
        return null;
    }
    
    private List<string> GetAttributeValues(SearchResultEntry entry, string attributeName)
    {
        var values = new List<string>();
        
        if (entry.Attributes.Contains(attributeName))
        {
            var attribute = entry.Attributes[attributeName];
            for (int i = 0; i < attribute.Count; i++)
            {
                values.Add(attribute[i]?.ToString());
            }
        }
        
        return values;
    }
    
    private bool IsAccountEnabled(string userAccountControl)
    {
        if (int.TryParse(userAccountControl, out var uac))
        {
            // Check if ACCOUNTDISABLE flag (0x0002) is set
            return (uac & 0x0002) == 0;
        }
        return true;
    }
    
    private DateTime? ParseDate(string dateString)
    {
        if (DateTime.TryParse(dateString, out var date))
            return date;
        return null;
    }
    
    private string ExtractCNFromDN(string distinguishedName)
    {
        if (string.IsNullOrEmpty(distinguishedName))
            return null;
        
        var parts = distinguishedName.Split(',');
        var cnPart = parts.FirstOrDefault(p => p.Trim().StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
        return cnPart?.Substring(3); // Remove "CN=" prefix
    }
}

public class ADUser
{
    public string Username { get; set; }
    public string DisplayName { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
    public string Phone { get; set; }
    public string Department { get; set; }
    public string Title { get; set; }
    public string Manager { get; set; }
    public string DistinguishedName { get; set; }
    public bool IsEnabled { get; set; }
    public DateTime? CreatedDate { get; set; }
    public DateTime? ModifiedDate { get; set; }
    public List<string> Groups { get; set; } = new();
}
```

### 2. Account Management Integration

```csharp
public class AccountManagementService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<AccountManagementService> _logger;
    
    public AccountManagementService(IConfiguration configuration, ILogger<AccountManagementService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }
    
    public async Task<bool> ValidateUserAsync(string username, string password)
    {
        try
        {
            using var context = new PrincipalContext(
                ContextType.Domain,
                _configuration["ActiveDirectory:Domain"],
                _configuration["ActiveDirectory:ServiceAccount"],
                _configuration["ActiveDirectory:ServicePassword"]);
            
            return await Task.Run(() => context.ValidateCredentials(username, password));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating user {Username}", username);
            return false;
        }
    }
    
    public async Task<UserPrincipal> FindUserAsync(string username)
    {
        try
        {
            using var context = new PrincipalContext(
                ContextType.Domain,
                _configuration["ActiveDirectory:Domain"],
                _configuration["ActiveDirectory:ServiceAccount"],
                _configuration["ActiveDirectory:ServicePassword"]);
            
            return await Task.Run(() => UserPrincipal.FindByIdentity(context, username));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error finding user {Username}", username);
            return null;
        }
    }
    
    public async Task<List<string>> GetUserGroupsAsync(string username)
    {
        try
        {
            using var context = new PrincipalContext(
                ContextType.Domain,
                _configuration["ActiveDirectory:Domain"],
                _configuration["ActiveDirectory:ServiceAccount"],
                _configuration["ActiveDirectory:ServicePassword"]);
            
            var user = await Task.Run(() => UserPrincipal.FindByIdentity(context, username));
            if (user == null) return new List<string>();
            
            var groups = new List<string>();
            
            foreach (var group in user.GetGroups())
            {
                groups.Add(group.Name);
            }
            
            return groups;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting groups for user {Username}", username);
            return new List<string>();
        }
    }
    
    public async Task<List<UserPrincipal>> SearchUsersAsync(string searchTerm)
    {
        try
        {
            using var context = new PrincipalContext(
                ContextType.Domain,
                _configuration["ActiveDirectory:Domain"],
                _configuration["ActiveDirectory:ServiceAccount"],
                _configuration["ActiveDirectory:ServicePassword"]);
            
            var userPrincipal = new UserPrincipal(context)
            {
                Name = $"*{searchTerm}*"
            };
            
            using var searcher = new PrincipalSearcher(userPrincipal);
            var results = await Task.Run(() => searcher.FindAll().Cast<UserPrincipal>().ToList());
            
            return results;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error searching users with term {SearchTerm}", searchTerm);
            return new List<UserPrincipal>();
        }
    }
}
```

### 3. AD Authentication Handler

```csharp
public class ActiveDirectoryAuthenticationHandler : AuthenticationHandler<ActiveDirectoryAuthenticationOptions>
{
    private readonly IActiveDirectoryService _adService;
    
    public ActiveDirectoryAuthenticationHandler(
        IOptionsMonitor<ActiveDirectoryAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IActiveDirectoryService adService)
        : base(options, logger, encoder, clock)
    {
        _adService = adService;
    }
    
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            return AuthenticateResult.NoResult();
        }
        
        var authHeader = Request.Headers["Authorization"].ToString();
        
        if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }
        
        var credentials = ExtractCredentials(authHeader);
        if (credentials == null)
        {
            return AuthenticateResult.Fail("Invalid credentials format");
        }
        
        var isValid = await _adService.AuthenticateUserAsync(credentials.Username, credentials.Password);
        
        if (!isValid)
        {
            return AuthenticateResult.Fail("Invalid username or password");
        }
        
        var user = await _adService.GetUserAsync(credentials.Username);
        var groups = await _adService.GetUserGroupsAsync(credentials.Username);
        
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Username),
            new(ClaimTypes.Name, user.DisplayName ?? user.Username),
            new(ClaimTypes.Email, user.Email ?? ""),
            new(ClaimTypes.GivenName, user.FirstName ?? ""),
            new(ClaimTypes.Surname, user.LastName ?? ""),
            new("department", user.Department ?? ""),
            new("title", user.Title ?? "")
        };
        
        // Add group claims
        foreach (var group in groups)
        {
            claims.Add(new Claim(ClaimTypes.Role, group));
            claims.Add(new Claim("group", group));
        }
        
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        
        return AuthenticateResult.Success(ticket);
    }
    
    private (string Username, string Password)? ExtractCredentials(string authHeader)
    {
        try
        {
            var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
            var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            var parts = credentials.Split(':', 2);
            
            if (parts.Length == 2)
            {
                return (parts[0], parts[1]);
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error extracting credentials from auth header");
        }
        
        return null;
    }
}

public class ActiveDirectoryAuthenticationOptions : AuthenticationSchemeOptions
{
    public string Domain { get; set; }
    public string ServiceAccount { get; set; }
    public string ServicePassword { get; set; }
}
```

### 4. Claims Transformation for AD

```csharp
public class ActiveDirectoryClaimsTransformer : IClaimsTransformation
{
    private readonly IActiveDirectoryService _adService;
    private readonly IMemoryCache _cache;
    
    public ActiveDirectoryClaimsTransformer(IActiveDirectoryService adService, IMemoryCache cache)
    {
        _adService = adService;
        _cache = cache;
    }
    
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true)
            return principal;
        
        var username = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(username))
            return principal;
        
        var cacheKey = $"ad_claims_{username}";
        
        if (_cache.TryGetValue(cacheKey, out ClaimsIdentity cachedIdentity))
        {
            return new ClaimsPrincipal(cachedIdentity);
        }
        
        var identity = (ClaimsIdentity)principal.Identity;
        
        // Get fresh AD data
        var user = await _adService.GetUserAsync(username);
        if (user != null)
        {
            // Add/update user attributes
            AddOrUpdateClaim(identity, "ad_display_name", user.DisplayName);
            AddOrUpdateClaim(identity, "ad_email", user.Email);
            AddOrUpdateClaim(identity, "ad_department", user.Department);
            AddOrUpdateClaim(identity, "ad_title", user.Title);
            
            // Add group memberships
            var groups = await _adService.GetUserGroupsAsync(username);
            
            // Remove existing group claims
            var existingGroupClaims = identity.Claims.Where(c => c.Type == "ad_group").ToList();
            foreach (var claim in existingGroupClaims)
            {
                identity.RemoveClaim(claim);
            }
            
            // Add current group claims
            foreach (var group in groups)
            {
                identity.AddClaim(new Claim("ad_group", group));
            }
            
            // Add manager information
            if (!string.IsNullOrEmpty(user.Manager))
            {
                var managerName = ExtractManagerName(user.Manager);
                AddOrUpdateClaim(identity, "ad_manager", managerName);
            }
        }
        
        // Cache for 30 minutes
        _cache.Set(cacheKey, identity, TimeSpan.FromMinutes(30));
        
        return new ClaimsPrincipal(identity);
    }
    
    private void AddOrUpdateClaim(ClaimsIdentity identity, string claimType, string value)
    {
        if (string.IsNullOrEmpty(value)) return;
        
        var existingClaim = identity.FindFirst(claimType);
        if (existingClaim != null)
        {
            identity.RemoveClaim(existingClaim);
        }
        
        identity.AddClaim(new Claim(claimType, value));
    }
    
    private string ExtractManagerName(string managerDN)
    {
        // Extract CN from manager DN
        var cnStart = managerDN.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
        if (cnStart >= 0)
        {
            var cnEnd = managerDN.IndexOf(',', cnStart);
            if (cnEnd > cnStart)
            {
                return managerDN.Substring(cnStart + 3, cnEnd - cnStart - 3);
            }
        }
        return managerDN;
    }
}
```

### 5. Configuration and Startup

```csharp
public void ConfigureServices(IServiceCollection services)
{
    // Active Directory configuration
    services.Configure<ActiveDirectoryOptions>(Configuration.GetSection("ActiveDirectory"));
    
    // Register services
    services.AddScoped<IActiveDirectoryService, ActiveDirectoryService>();
    services.AddScoped<AccountManagementService>();
    services.AddTransient<IClaimsTransformation, ActiveDirectoryClaimsTransformer>();
    
    // Authentication
    services.AddAuthentication("ActiveDirectory")
        .AddScheme<ActiveDirectoryAuthenticationOptions, ActiveDirectoryAuthenticationHandler>(
            "ActiveDirectory", options =>
            {
                options.Domain = Configuration["ActiveDirectory:Domain"];
                options.ServiceAccount = Configuration["ActiveDirectory:ServiceAccount"];
                options.ServicePassword = Configuration["ActiveDirectory:ServicePassword"];
            });
    
    // Authorization with AD groups
    services.AddAuthorization(options =>
    {
        options.AddPolicy("RequireAdministrators", policy =>
            policy.RequireClaim("ad_group", "Domain Admins", "Administrators"));
        
        options.AddPolicy("RequireHRAccess", policy =>
            policy.RequireClaim("ad_group", "HR Department"));
        
        options.AddPolicy("RequireManagers", policy =>
            policy.RequireClaim("ad_group", "Managers"));
    });
}

// Configuration model
public class ActiveDirectoryOptions
{
    public string Server { get; set; }
    public int Port { get; set; } = 389;
    public string Domain { get; set; }
    public string BaseDN { get; set; }
    public string ServiceAccount { get; set; }
    public string ServicePassword { get; set; }
    public bool UseSSL { get; set; } = false;
}
```

### 6. AD Integration Controller

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ActiveDirectoryController : ControllerBase
{
    private readonly IActiveDirectoryService _adService;
    
    public ActiveDirectoryController(IActiveDirectoryService adService)
    {
        _adService = adService;
    }
    
    [HttpGet("user/{username}")]
    public async Task<IActionResult> GetUser(string username)
    {
        var user = await _adService.GetUserAsync(username);
        
        if (user == null)
            return NotFound($"User {username} not found");
        
        return Ok(new
        {
            user.Username,
            user.DisplayName,
            user.Email,
            user.Department,
            user.Title,
            user.IsEnabled,
            GroupCount = user.Groups.Count
        });
    }
    
    [HttpGet("user/{username}/groups")]
    public async Task<IActionResult> GetUserGroups(string username)
    {
        var groups = await _adService.GetUserGroupsAsync(username);
        return Ok(groups);
    }
    
    [HttpGet("search")]
    public async Task<IActionResult> SearchUsers([FromQuery] string term)
    {
        if (string.IsNullOrEmpty(term) || term.Length < 3)
            return BadRequest("Search term must be at least 3 characters");
        
        var users = await _adService.SearchUsersAsync(term);
        
        return Ok(users.Select(u => new
        {
            u.Username,
            u.DisplayName,
            u.Email,
            u.Department
        }));
    }
    
    [HttpGet("group/{groupName}/members")]
    [Authorize(Policy = "RequireAdministrators")]
    public async Task<IActionResult> GetGroupMembers(string groupName)
    {
        var members = await _adService.GetUsersInGroupAsync(groupName);
        
        return Ok(members.Select(m => new
        {
            m.Username,
            m.DisplayName,
            m.Email
        }));
    }
    
    [HttpPost("authenticate")]
    public async Task<IActionResult> Authenticate([FromBody] AuthenticateRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var isValid = await _adService.AuthenticateUserAsync(request.Username, request.Password);
        
        if (isValid)
        {
            var user = await _adService.GetUserAsync(request.Username);
            var groups = await _adService.GetUserGroupsAsync(request.Username);
            
            return Ok(new
            {
                Success = true,
                User = new
                {
                    user.Username,
                    user.DisplayName,
                    user.Email,
                    Groups = groups
                }
            });
        }
        
        return Unauthorized(new { Success = false, Message = "Invalid credentials" });
    }
}

public class AuthenticateRequest
{
    [Required]
    public string Username { get; set; }
    
    [Required]
    public string Password { get; set; }
}
```

## Security Best Practices

### 1. Secure Configuration
```json
{
  "ActiveDirectory": {
    "Server": "dc.company.com",
    "Port": 636,
    "Domain": "company.com",
    "BaseDN": "DC=company,DC=com",
    "ServiceAccount": "CN=ServiceAccount,OU=ServiceAccounts,DC=company,DC=com",
    "ServicePassword": "SecurePasswordStoredInKeyVault",
    "UseSSL": true
  }
}
```

### 2. Connection Security
```csharp
public class SecureActiveDirectoryService : ActiveDirectoryService
{
    protected override LdapConnection CreateConnection()
    {
        var connection = base.CreateConnection();
        
        // Enable SSL/TLS
        connection.SessionOptions.SecureSocketLayer = true;
        
        // Set security options
        connection.SessionOptions.VerifyServerCertificate = (conn, cert) =>
        {
            // Implement certificate validation
            return ValidateServerCertificate(cert);
        };
        
        // Set timeout
        connection.Timeout = TimeSpan.FromSeconds(30);
        
        return connection;
    }
    
    private bool ValidateServerCertificate(X509Certificate certificate)
    {
        // Implement proper certificate validation
        return true; // Simplified
    }
}
```

### 3. Error Handling and Security
```csharp
public class SecurityAwareActiveDirectoryService : IActiveDirectoryService
{
    public async Task<bool> AuthenticateUserAsync(string username, string password)
    {
        // Input validation
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return false;
        
        // Prevent LDAP injection
        username = EscapeLdapSearchFilter(username);
        
        // Rate limiting (implement with distributed cache)
        if (await IsRateLimitedAsync(username))
        {
            _logger.LogWarning("Rate limit exceeded for user {Username}", username);
            return false;
        }
        
        try
        {
            // Actual authentication logic
            return await PerformAuthenticationAsync(username, password);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication error for user {Username}", username);
            return false; // Don't leak error details
        }
    }
    
    private string EscapeLdapSearchFilter(string input)
    {
        return input.Replace("\\", "\\5c")
                   .Replace("*", "\\2a")
                   .Replace("(", "\\28")
                   .Replace(")", "\\29")
                   .Replace("\0", "\\00");
    }
}
```

## Testing Strategies

### 1. Unit Tests
```csharp
[TestFixture]
public class ActiveDirectoryServiceTests
{
    private Mock<IConfiguration> _mockConfig;
    private ActiveDirectoryService _service;
    
    [SetUp]
    public void Setup()
    {
        _mockConfig = new Mock<IConfiguration>();
        _mockConfig.Setup(c => c["ActiveDirectory:Server"]).Returns("test-dc.company.com");
        _mockConfig.Setup(c => c["ActiveDirectory:BaseDN"]).Returns("DC=test,DC=com");
        
        _service = new ActiveDirectoryService(_mockConfig.Object, Mock.Of<ILogger<ActiveDirectoryService>>());
    }
    
    [Test]
    public async Task GetUserAsync_WithValidUsername_ShouldReturnUser()
    {
        // This would require a test AD environment or mocking LDAP calls
        // In practice, you'd use integration tests with a test AD
    }
}
```

### 2. Integration Tests
```csharp
[TestFixture]
[Category("Integration")]
public class ActiveDirectoryIntegrationTests
{
    private IActiveDirectoryService _adService;
    
    [SetUp]
    public void Setup()
    {
        // Setup with test AD configuration
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.test.json")
            .Build();
            
        _adService = new ActiveDirectoryService(configuration, Mock.Of<ILogger<ActiveDirectoryService>>());
    }
    
    [Test]
    public async Task AuthenticateUser_WithValidCredentials_ShouldReturnTrue()
    {
        var result = await _adService.AuthenticateUserAsync("testuser", "testpassword");
        Assert.IsTrue(result);
    }
}
```

---
**Next**: Continue with the remaining authentication and authorization notes