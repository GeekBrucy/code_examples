# Windows Authentication

## Overview
Windows Authentication (also known as Integrated Windows Authentication or IWA) allows users to authenticate using their Windows domain credentials without explicitly entering username/password. It's primarily used in enterprise environments with Active Directory.

## Core Concepts

### 1. Authentication Protocols

#### NTLM (NT LAN Manager)
- Challenge-response authentication protocol
- Older protocol, still widely supported
- Works in workgroup and domain environments
- Less secure than Kerberos

#### Kerberos
- Ticket-based authentication protocol
- Default for Windows 2000+ domains
- More secure than NTLM
- Supports mutual authentication
- Requires time synchronization

### 2. How Windows Authentication Works

#### Process Flow
1. **Challenge**: Server sends authentication challenge
2. **Response**: Client responds with encrypted credentials
3. **Verification**: Server validates credentials with domain controller
4. **Access**: Server grants access based on user's Windows identity

#### Security Context
- Uses Windows security tokens
- Inherits user's Windows permissions
- Supports impersonation and delegation
- Integrates with Windows security model

### 3. Scenarios and Use Cases

#### When to Use Windows Authentication
- **Intranet applications** in domain environments
- **Corporate web applications** for internal users
- **Windows services** requiring user context
- **Desktop applications** accessing network resources

#### Limitations
- **Windows-only**: Requires Windows domain infrastructure
- **Intranet focused**: Not suitable for internet-facing applications
- **Browser support**: Limited cross-browser support
- **Platform dependent**: Primarily Windows-centric

## .NET Implementation

### 1. ASP.NET Core Configuration

#### Basic Setup
```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Enable Windows Authentication
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();

builder.Services.AddAuthorization(options =>
{
    // Require authentication for all requests
    options.FallbackPolicy = options.DefaultPolicy;
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
```

#### With IIS Integration
```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<IISOptions>(options =>
{
    options.AuthenticationDisplayName = "Windows";
    options.AutomaticAuthentication = true;
});

// For IIS hosting
builder.Services.AddAuthentication(IISDefaults.AuthenticationScheme);

var app = builder.Build();
```

### 2. Controller Implementation

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize] // Requires Windows authentication
public class WindowsAuthController : ControllerBase
{
    [HttpGet("user-info")]
    public IActionResult GetUserInfo()
    {
        var windowsIdentity = (WindowsIdentity)User.Identity;
        
        return Ok(new
        {
            Name = windowsIdentity.Name,
            AuthenticationType = windowsIdentity.AuthenticationType,
            IsAuthenticated = windowsIdentity.IsAuthenticated,
            Token = windowsIdentity.Token.ToInt64(),
            Groups = windowsIdentity.Groups?.Select(g => g.Translate(typeof(NTAccount))),
            Claims = User.Claims.Select(c => new { c.Type, c.Value })
        });
    }
    
    [HttpGet("domain-info")]
    public IActionResult GetDomainInfo()
    {
        var identity = (WindowsIdentity)User.Identity;
        var parts = identity.Name.Split('\\');
        
        return Ok(new
        {
            Domain = parts.Length > 1 ? parts[0] : "No Domain",
            Username = parts.Length > 1 ? parts[1] : parts[0],
            FullName = identity.Name,
            IsDomainUser = parts.Length > 1
        });
    }
    
    [HttpPost("impersonate")]
    public IActionResult TestImpersonation()
    {
        var identity = (WindowsIdentity)User.Identity;
        
        using (var impersonatedUser = identity.Impersonate())
        {
            // Code runs under the authenticated user's context
            var currentUser = WindowsIdentity.GetCurrent();
            
            return Ok(new
            {
                OriginalUser = identity.Name,
                ImpersonatedUser = currentUser.Name,
                Message = "Successfully impersonated user"
            });
        }
    }
}
```

### 3. Advanced Authorization

```csharp
// Custom authorization requirement
public class WindowsGroupRequirement : IAuthorizationRequirement
{
    public string GroupName { get; }
    
    public WindowsGroupRequirement(string groupName)
    {
        GroupName = groupName;
    }
}

public class WindowsGroupHandler : AuthorizationHandler<WindowsGroupRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        WindowsGroupRequirement requirement)
    {
        if (context.User.Identity is WindowsIdentity windowsIdentity)
        {
            var principal = new WindowsPrincipal(windowsIdentity);
            
            if (principal.IsInRole(requirement.GroupName))
            {
                context.Succeed(requirement);
            }
        }
        
        return Task.CompletedTask;
    }
}

// Registration in Program.cs
builder.Services.AddScoped<IAuthorizationHandler, WindowsGroupHandler>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.Requirements.Add(new WindowsGroupRequirement("DOMAIN\\Administrators")));
        
    options.AddPolicy("DevelopersOnly", policy =>
        policy.Requirements.Add(new WindowsGroupRequirement("DOMAIN\\Developers")));
});
```

### 4. Middleware for Custom Logic

```csharp
public class WindowsAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<WindowsAuthMiddleware> _logger;
    
    public WindowsAuthMiddleware(RequestDelegate next, ILogger<WindowsAuthMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User.Identity is WindowsIdentity windowsIdentity && 
            windowsIdentity.IsAuthenticated)
        {
            // Log authentication details
            _logger.LogInformation("User {User} authenticated via {AuthType}", 
                windowsIdentity.Name, 
                windowsIdentity.AuthenticationType);
            
            // Add custom claims based on Windows groups
            var claimsIdentity = new ClaimsIdentity(windowsIdentity.Claims);
            
            foreach (var group in windowsIdentity.Groups ?? Enumerable.Empty<SecurityIdentifier>())
            {
                try
                {
                    var groupName = group.Translate(typeof(NTAccount)).ToString();
                    claimsIdentity.AddClaim(new Claim("windows_group", groupName));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not translate group {Group}", group);
                }
            }
            
            context.User = new ClaimsPrincipal(claimsIdentity);
        }
        
        await _next(context);
    }
}

// Registration
app.UseMiddleware<WindowsAuthMiddleware>();
```

## Testing on macOS (Non-Windows Environments)

### 1. Development Strategies

#### Option 1: Windows Virtual Machine
```bash
# Using Parallels, VMware, or VirtualBox
# Set up Windows Server with Active Directory
# Join development machine to domain
# Test Windows Authentication in VM
```

#### Option 2: Docker with Windows Containers
```dockerfile
# Use Windows Server Core container
FROM mcr.microsoft.com/windows/servercore:ltsc2019

# Install IIS and ASP.NET Core
RUN powershell -Command \
    Add-WindowsFeature Web-Server; \
    Add-WindowsFeature Web-Asp-Net45
    
# Copy and configure your application
COPY . /app
WORKDIR /app

EXPOSE 80
CMD ["dotnet", "YourApp.dll"]
```

#### Option 3: Mock Implementation for Development
```csharp
public class MockWindowsAuthenticationService
{
    public class MockWindowsIdentity : IIdentity
    {
        public string AuthenticationType => "Mock Windows";
        public bool IsAuthenticated => true;
        public string Name { get; set; } = "DOMAIN\\mockuser";
    }
    
    public class MockWindowsPrincipal : IPrincipal
    {
        public IIdentity Identity { get; }
        private readonly string[] _roles;
        
        public MockWindowsPrincipal(string[] roles = null)
        {
            Identity = new MockWindowsIdentity();
            _roles = roles ?? new[] { "DOMAIN\\Users", "DOMAIN\\Developers" };
        }
        
        public bool IsInRole(string role) => _roles.Contains(role);
    }
}

// Use in development
#if DEBUG
builder.Services.AddSingleton<IPrincipal>(new MockWindowsPrincipal());
#endif
```

### 2. Integration Testing

```csharp
[TestFixture]
public class WindowsAuthTests
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
                // Mock Windows authentication for testing
                services.AddAuthentication("Test")
                    .AddScheme<TestAuthenticationSchemeOptions, TestAuthenticationHandler>(
                        "Test", options => { });
            });
            
        _server = new TestServer(builder);
        _client = _server.CreateClient();
    }
    
    [Test]
    public async Task WindowsAuth_ShouldReturnUserInfo()
    {
        // Arrange
        _client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Test", "DOMAIN\\testuser");
        
        // Act
        var response = await _client.GetAsync("/api/windowsauth/user-info");
        
        // Assert
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        Assert.That(content, Contains.Substring("testuser"));
    }
}

public class TestAuthenticationHandler : AuthenticationHandler<TestAuthenticationSchemeOptions>
{
    public TestAuthenticationHandler(IOptionsMonitor<TestAuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
    }
    
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authHeader = Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authHeader))
            return Task.FromResult(AuthenticateResult.Fail("No auth header"));
        
        var username = authHeader.Replace("Test ", "");
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.NameIdentifier, username),
            new Claim("windows_group", "DOMAIN\\Users")
        };
        
        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, "Test");
        
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
```

### 3. Cloud Development Environment

#### Using GitHub Codespaces or Azure Dev Box
```yaml
# .devcontainer/devcontainer.json
{
    "name": "Windows Auth Development",
    "image": "mcr.microsoft.com/devcontainers/dotnet:6.0",
    "features": {
        "ghcr.io/devcontainers/features/azure-cli:1": {},
        "ghcr.io/devcontainers/features/docker-in-docker:2": {}
    },
    "postCreateCommand": "bash .devcontainer/setup.sh"
}
```

```bash
# .devcontainer/setup.sh
#!/bin/bash
# Install additional tools for Windows auth testing
dotnet tool install --global dotnet-ef
```

## Configuration Files

### 1. appsettings.json
```json
{
  "Authentication": {
    "Schemes": {
      "Negotiate": {
        "EnableLdapClaimResolution": true,
        "LdapSettings": {
          "Domain": "DOMAIN.COM",
          "MachineAccountName": "MACHINE$"
        }
      }
    }
  },
  "Logging": {
    "LogLevel": {
      "Microsoft.AspNetCore.Authentication": "Debug"
    }
  }
}
```

### 2. web.config (for IIS)
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <security>
      <authentication>
        <windowsAuthentication enabled="true" />
        <anonymousAuthentication enabled="false" />
      </authentication>
    </security>
  </system.webServer>
</configuration>
```

## Security Considerations

### 1. Best Practices
- **Use HTTPS**: Always encrypt Windows auth traffic
- **Validate groups**: Check user group membership
- **Audit access**: Log authentication events
- **Limit scope**: Use least privilege principle
- **Monitor failures**: Track failed authentication attempts

### 2. Common Vulnerabilities
- **Pass-the-hash attacks**: NTLM vulnerability
- **Kerberoasting**: Kerberos service ticket attacks
- **Golden ticket attacks**: Compromised Kerberos tickets
- **Delegation issues**: Unconstrained delegation risks

### 3. Mitigation Strategies
```csharp
// Disable NTLM if possible
builder.Services.Configure<NegotiateOptions>(options =>
{
    options.EnableLdapClaimResolution = true;
    options.LdapSettings.EnableLdapClaimResolution = true;
});

// Add security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    await next();
});
```

## Alternative Solutions for macOS Development

### 1. Azure AD Integration
Instead of Windows Authentication, consider Azure AD:

```csharp
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"));
```

### 2. LDAP Authentication
Direct LDAP integration:

```csharp
builder.Services.AddAuthentication()
    .AddScheme<LdapAuthenticationSchemeOptions, LdapAuthenticationHandler>("LDAP", null);
```

### 3. Hybrid Approach
Support multiple authentication schemes:

```csharp
builder.Services.AddAuthentication()
    .AddNegotiate() // Windows Authentication
    .AddJwtBearer() // JWT for external users
    .AddCookie();   // Fallback authentication

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .AddAuthenticationSchemes("Negotiate", "Bearer", "Cookies")
        .Build();
});
```

## Troubleshooting

### Common Issues
1. **401 Unauthorized**: Check IIS authentication settings
2. **Browser prompts**: IE/Edge required for seamless auth
3. **Cross-domain issues**: Kerberos delegation needed
4. **Time sync**: Kerberos requires synchronized clocks

### Debugging Tools
```csharp
// Add detailed logging
builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.SetMinimumLevel(LogLevel.Debug);
});

// Custom middleware for debugging
app.Use(async (context, next) =>
{
    Console.WriteLine($"Auth Type: {context.User.Identity?.AuthenticationType}");
    Console.WriteLine($"Is Authenticated: {context.User.Identity?.IsAuthenticated}");
    Console.WriteLine($"User: {context.User.Identity?.Name}");
    await next();
});
```

---
**Note for macOS Users**: While you can't run true Windows Authentication on macOS, you can learn the concepts, implement mock versions for development, and use cloud environments or VMs for testing. The authentication patterns and authorization logic remain the same across platforms.

**Next**: Continue to `11-active-directory.md` to learn about Active Directory integration