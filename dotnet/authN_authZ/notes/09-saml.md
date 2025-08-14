# SAML (Security Assertion Markup Language)

## Overview
SAML is an XML-based standard for exchanging authentication and authorization data between parties, particularly between an identity provider (IdP) and a service provider (SP). It's widely used in enterprise environments for Single Sign-On (SSO) solutions.

## Core Concepts

### 1. SAML Components

#### Identity Provider (IdP)
- Authenticates users and issues SAML assertions
- Examples: Active Directory Federation Services (ADFS), Okta, Azure AD
- Maintains user identities and credentials
- Issues digitally signed assertions

#### Service Provider (SP)
- Provides services to users
- Relies on IdP for authentication
- Consumes and validates SAML assertions
- Your application acts as the SP

#### SAML Assertion
- XML document containing authentication/authorization statements
- Digitally signed by IdP for security
- Contains user identity and attributes
- Has expiration time for security

### 2. SAML Flow Types

#### SP-Initiated Flow
1. User accesses SP application
2. SP redirects user to IdP for authentication
3. User authenticates with IdP
4. IdP sends SAML assertion back to SP
5. SP validates assertion and grants access

#### IdP-Initiated Flow
1. User starts at IdP portal
2. User selects SP application
3. IdP sends SAML assertion to SP
4. SP validates assertion and grants access

### 3. SAML Bindings
- **HTTP-POST**: Assertion sent via HTTP POST form
- **HTTP-Redirect**: Assertion sent via HTTP GET redirect
- **SOAP**: Used for artifact resolution
- **HTTP-Artifact**: Two-step process with artifact resolution

### 4. SAML Profiles
- **Web Browser SSO**: Most common, for web applications
- **Enhanced Client/Proxy**: For rich clients
- **Identity Provider Discovery**: For multiple IdPs
- **Single Logout**: Coordinated logout across all SPs

## .NET SAML Implementation

### 1. SAML Service Provider Setup

#### Installation
```bash
dotnet add package Sustainsys.Saml2.AspNetCore2
dotnet add package Sustainsys.Saml2.Metadata
```

#### Basic Configuration
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(sharedOptions =>
    {
        sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        sharedOptions.DefaultChallengeScheme = Saml2Defaults.Scheme;
    })
    .AddCookie()
    .AddSaml2(options =>
    {
        // Service Provider Configuration
        options.SPOptions.EntityId = new EntityId("https://yourapp.com/saml");
        options.SPOptions.ReturnUrl = new Uri("https://yourapp.com/");
        options.SPOptions.PublicOrigin = new Uri("https://yourapp.com");
        
        // Certificate for signing requests (optional)
        options.SPOptions.ServiceCertificates.Add(new X509Certificate2("path/to/certificate.pfx", "password"));
        
        // Security settings
        options.SPOptions.WantAssertionsSigned = true;
        options.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Always;
        
        // Add Identity Provider
        var idp = new IdentityProvider(new EntityId("https://idp.example.com/metadata"), options.SPOptions)
        {
            LoadMetadata = true,
            MetadataLocation = "https://idp.example.com/metadata",
            AllowUnsolicitedAuthnResponse = true,
            
            // Binding preferences
            Binding = Saml2BindingType.HttpPost,
            
            // Single Sign-On Service
            SingleSignOnServiceUrl = new Uri("https://idp.example.com/sso"),
            
            // Single Logout Service
            SingleLogoutServiceUrl = new Uri("https://idp.example.com/slo"),
        };
        
        // Add signing certificate for IdP
        idp.SigningKeys.AddConfiguredKey(new X509Certificate2("path/to/idp-cert.cer"));
        
        options.IdentityProviders.Add(idp);
        
        // Event handlers
        options.Notifications.AcsCommandResultCreated = (commandResult, response) =>
        {
            // Custom processing of SAML response
            var identity = commandResult.Principal.Identities.First();
            
            // Add custom claims
            ProcessSamlAttributes(identity, response);
        };
        
        options.Notifications.LogoutCommandResultCreated = (commandResult, response) =>
        {
            // Custom logout processing
            Console.WriteLine($"User logged out: {response.Status}");
        };
    });
}
```

### 2. Advanced SAML Configuration

#### Custom SAML Service
```csharp
public interface ISamlService
{
    Task<SamlUser> ProcessSamlResponseAsync(Saml2Response samlResponse);
    Task<string> GenerateMetadataAsync();
    Task<bool> ValidateAssertionAsync(Saml2Assertion assertion);
    Task InitiateSingleLogoutAsync(string sessionId);
}

public class SamlService : ISamlService
{
    private readonly IConfiguration _configuration;
    private readonly IUserService _userService;
    private readonly ILogger<SamlService> _logger;
    
    public SamlService(IConfiguration configuration, IUserService userService, ILogger<SamlService> logger)
    {
        _configuration = configuration;
        _userService = userService;
        _logger = logger;
    }
    
    public async Task<SamlUser> ProcessSamlResponseAsync(Saml2Response samlResponse)
    {
        try
        {
            if (samlResponse.Status != Saml2StatusCode.Success)
            {
                throw new InvalidOperationException($"SAML authentication failed: {samlResponse.Status}");
            }
            
            var assertion = samlResponse.Assertions.FirstOrDefault();
            if (assertion == null)
            {
                throw new InvalidOperationException("No SAML assertion found in response");
            }
            
            // Validate assertion
            if (!await ValidateAssertionAsync(assertion))
            {
                throw new SecurityException("SAML assertion validation failed");
            }
            
            // Extract user information
            var samlUser = ExtractUserFromAssertion(assertion);
            
            // Process or create user account
            await ProcessUserAccountAsync(samlUser);
            
            return samlUser;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing SAML response");
            throw;
        }
    }
    
    public async Task<bool> ValidateAssertionAsync(Saml2Assertion assertion)
    {
        // Check assertion validity period
        var now = DateTime.UtcNow;
        if (assertion.Conditions.NotBefore.HasValue && now < assertion.Conditions.NotBefore.Value)
        {
            _logger.LogWarning("SAML assertion not yet valid");
            return false;
        }
        
        if (assertion.Conditions.NotOnOrAfter.HasValue && now >= assertion.Conditions.NotOnOrAfter.Value)
        {
            _logger.LogWarning("SAML assertion has expired");
            return false;
        }
        
        // Validate audience restriction
        var audienceRestrictions = assertion.Conditions.AudienceRestrictions;
        if (audienceRestrictions.Any())
        {
            var expectedAudience = _configuration["Saml:EntityId"];
            var hasValidAudience = audienceRestrictions.Any(ar => 
                ar.Audience.Any(a => a.Uri.ToString() == expectedAudience));
                
            if (!hasValidAudience)
            {
                _logger.LogWarning("SAML assertion audience validation failed");
                return false;
            }
        }
        
        // Additional custom validations
        return await PerformCustomValidationsAsync(assertion);
    }
    
    public async Task<string> GenerateMetadataAsync()
    {
        var spOptions = new SPOptions
        {
            EntityId = new EntityId(_configuration["Saml:EntityId"]),
            ReturnUrl = new Uri(_configuration["Saml:ReturnUrl"]),
            PublicOrigin = new Uri(_configuration["Saml:PublicOrigin"])
        };
        
        // Add certificate if available
        var certPath = _configuration["Saml:SigningCertificate"];
        if (!string.IsNullOrEmpty(certPath))
        {
            var cert = new X509Certificate2(certPath, _configuration["Saml:CertificatePassword"]);
            spOptions.ServiceCertificates.Add(cert);
        }
        
        var metadata = spOptions.CreateMetadata();
        return metadata.ToXmlString();
    }
    
    private SamlUser ExtractUserFromAssertion(Saml2Assertion assertion)
    {
        var attributes = assertion.AttributeStatements
            .SelectMany(s => s.Attributes)
            .ToDictionary(a => a.Name, a => a.Values.FirstOrDefault()?.ToString());
        
        var nameIdentifier = assertion.Subject?.NameId?.Value;
        
        return new SamlUser
        {
            NameIdentifier = nameIdentifier,
            Email = GetAttributeValue(attributes, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "mail", "email"),
            FirstName = GetAttributeValue(attributes, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "givenName", "firstName"),
            LastName = GetAttributeValue(attributes, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "sn", "lastName"),
            DisplayName = GetAttributeValue(attributes, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "displayName", "name"),
            Groups = GetMultiValueAttribute(attributes, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups", "memberOf", "groups"),
            Department = GetAttributeValue(attributes, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department", "department"),
            JobTitle = GetAttributeValue(attributes, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/title", "title"),
            SessionIndex = assertion.AuthnStatements.FirstOrDefault()?.SessionIndex,
            Attributes = attributes
        };
    }
    
    private string GetAttributeValue(Dictionary<string, string> attributes, params string[] possibleNames)
    {
        foreach (var name in possibleNames)
        {
            if (attributes.TryGetValue(name, out var value) && !string.IsNullOrEmpty(value))
                return value;
        }
        return null;
    }
    
    private List<string> GetMultiValueAttribute(Dictionary<string, string> attributes, params string[] possibleNames)
    {
        foreach (var name in possibleNames)
        {
            if (attributes.TryGetValue(name, out var value) && !string.IsNullOrEmpty(value))
            {
                // Handle different formats of multi-value attributes
                return value.Split(new[] { ';', ',', '|' }, StringSplitOptions.RemoveEmptyEntries)
                          .Select(v => v.Trim())
                          .ToList();
            }
        }
        return new List<string>();
    }
    
    private async Task ProcessUserAccountAsync(SamlUser samlUser)
    {
        // Find existing user or create new one
        var existingUser = await _userService.FindByEmailAsync(samlUser.Email);
        
        if (existingUser == null)
        {
            // Create new user account
            await _userService.CreateUserFromSamlAsync(samlUser);
            _logger.LogInformation("Created new user account for {Email}", samlUser.Email);
        }
        else
        {
            // Update existing user with SAML attributes
            await _userService.UpdateUserFromSamlAsync(existingUser, samlUser);
            _logger.LogInformation("Updated existing user account for {Email}", samlUser.Email);
        }
    }
    
    private async Task<bool> PerformCustomValidationsAsync(Saml2Assertion assertion)
    {
        // Add your custom business logic validations here
        // For example, check if user is in allowed groups, departments, etc.
        
        var attributes = assertion.AttributeStatements
            .SelectMany(s => s.Attributes)
            .ToDictionary(a => a.Name, a => a.Values.FirstOrDefault()?.ToString());
        
        // Example: Validate user is in allowed department
        var allowedDepartments = _configuration.GetSection("Saml:AllowedDepartments").Get<string[]>();
        if (allowedDepartments?.Any() == true)
        {
            var userDepartment = GetAttributeValue(attributes, "department");
            if (!allowedDepartments.Contains(userDepartment, StringComparer.OrdinalIgnoreCase))
            {
                _logger.LogWarning("User from department {Department} not allowed", userDepartment);
                return false;
            }
        }
        
        return true;
    }
    
    public async Task InitiateSingleLogoutAsync(string sessionId)
    {
        // Implementation for Single Logout
        // This would typically involve calling the IdP's logout endpoint
        await Task.CompletedTask;
    }
}

public class SamlUser
{
    public string NameIdentifier { get; set; }
    public string Email { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string DisplayName { get; set; }
    public List<string> Groups { get; set; } = new();
    public string Department { get; set; }
    public string JobTitle { get; set; }
    public string SessionIndex { get; set; }
    public Dictionary<string, string> Attributes { get; set; } = new();
}
```

### 3. SAML Controller

```csharp
[Route("saml")]
public class SamlController : Controller
{
    private readonly ISamlService _samlService;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    
    public SamlController(
        ISamlService samlService, 
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager)
    {
        _samlService = samlService;
        _signInManager = signInManager;
        _userManager = userManager;
    }
    
    [HttpGet("login")]
    public IActionResult Login(string returnUrl = null)
    {
        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(LoginCallback)),
            Items = { ["returnUrl"] = returnUrl }
        };
        
        return Challenge(props, Saml2Defaults.Scheme);
    }
    
    [HttpPost("acs")] // Assertion Consumer Service
    public async Task<IActionResult> LoginCallback()
    {
        try
        {
            var result = await HttpContext.AuthenticateAsync(Saml2Defaults.Scheme);
            
            if (!result.Succeeded)
            {
                return BadRequest("SAML authentication failed");
            }
            
            // Extract user information from SAML response
            var samlUser = ExtractSamlUserFromPrincipal(result.Principal);
            
            // Find or create local user account
            var user = await FindOrCreateUserAsync(samlUser);
            
            // Sign in the user locally
            await _signInManager.SignInAsync(user, isPersistent: false);
            
            // Redirect to return URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "/";
            return Redirect(returnUrl);
        }
        catch (Exception ex)
        {
            return BadRequest($"SAML login error: {ex.Message}");
        }
    }
    
    [HttpGet("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        // Sign out locally first
        await _signInManager.SignOutAsync();
        
        // Initiate SAML Single Logout
        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(LogoutCallback))
        };
        
        return SignOut(props, Saml2Defaults.Scheme);
    }
    
    [HttpPost("sls")] // Single Logout Service
    public async Task<IActionResult> LogoutCallback()
    {
        // Handle logout response from IdP
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/");
    }
    
    [HttpGet("metadata")]
    public async Task<IActionResult> Metadata()
    {
        var metadata = await _samlService.GenerateMetadataAsync();
        return Content(metadata, "application/samlmetadata+xml");
    }
    
    private SamlUser ExtractSamlUserFromPrincipal(ClaimsPrincipal principal)
    {
        return new SamlUser
        {
            NameIdentifier = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            Email = principal.FindFirst(ClaimTypes.Email)?.Value,
            FirstName = principal.FindFirst(ClaimTypes.GivenName)?.Value,
            LastName = principal.FindFirst(ClaimTypes.Surname)?.Value,
            DisplayName = principal.FindFirst(ClaimTypes.Name)?.Value,
            Groups = principal.FindAll("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups")
                            .Select(c => c.Value).ToList(),
            Department = principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department")?.Value,
            JobTitle = principal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/title")?.Value
        };
    }
    
    private async Task<ApplicationUser> FindOrCreateUserAsync(SamlUser samlUser)
    {
        // Try to find existing user by email
        var user = await _userManager.FindByEmailAsync(samlUser.Email);
        
        if (user == null)
        {
            // Create new user
            user = new ApplicationUser
            {
                UserName = samlUser.Email,
                Email = samlUser.Email,
                EmailConfirmed = true, // SAML users are pre-verified
                FirstName = samlUser.FirstName,
                LastName = samlUser.LastName,
                Department = samlUser.Department,
                CreatedAt = DateTime.UtcNow
            };
            
            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"Failed to create user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }
        }
        else
        {
            // Update existing user with SAML attributes
            var updated = false;
            
            if (user.FirstName != samlUser.FirstName)
            {
                user.FirstName = samlUser.FirstName;
                updated = true;
            }
            
            if (user.LastName != samlUser.LastName)
            {
                user.LastName = samlUser.LastName;
                updated = true;
            }
            
            if (user.Department != samlUser.Department)
            {
                user.Department = samlUser.Department;
                updated = true;
            }
            
            if (updated)
            {
                await _userManager.UpdateAsync(user);
            }
        }
        
        // Update user roles based on SAML groups
        await UpdateUserRolesFromSamlGroupsAsync(user, samlUser.Groups);
        
        return user;
    }
    
    private async Task UpdateUserRolesFromSamlGroupsAsync(ApplicationUser user, List<string> samlGroups)
    {
        // Define mapping between SAML groups and application roles
        var groupRoleMapping = new Dictionary<string, string>
        {
            ["Domain Admins"] = "Administrator",
            ["HR Department"] = "HR",
            ["Finance Department"] = "Finance",
            ["Managers"] = "Manager",
            ["Employees"] = "Employee"
        };
        
        var currentRoles = await _userManager.GetRolesAsync(user);
        var newRoles = samlGroups
            .Where(g => groupRoleMapping.ContainsKey(g))
            .Select(g => groupRoleMapping[g])
            .Distinct()
            .ToList();
        
        // Remove roles that are no longer applicable
        var rolesToRemove = currentRoles.Except(newRoles).ToList();
        if (rolesToRemove.Any())
        {
            await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
        }
        
        // Add new roles
        var rolesToAdd = newRoles.Except(currentRoles).ToList();
        if (rolesToAdd.Any())
        {
            await _userManager.AddToRolesAsync(user, rolesToAdd);
        }
    }
}
```

### 4. SAML Configuration Models

```csharp
public class SamlOptions
{
    public string EntityId { get; set; }
    public string ReturnUrl { get; set; }
    public string PublicOrigin { get; set; }
    public string SigningCertificatePath { get; set; }
    public string CertificatePassword { get; set; }
    public bool WantAssertionsSigned { get; set; } = true;
    public bool SignAuthRequests { get; set; } = false;
    public List<IdentityProviderOptions> IdentityProviders { get; set; } = new();
    public string[] AllowedDepartments { get; set; }
    public Dictionary<string, string> AttributeMappings { get; set; } = new();
}

public class IdentityProviderOptions
{
    public string EntityId { get; set; }
    public string MetadataUrl { get; set; }
    public string SingleSignOnUrl { get; set; }
    public string SingleLogoutUrl { get; set; }
    public string SigningCertificatePath { get; set; }
    public bool AllowUnsolicitedResponse { get; set; } = false;
    public string Binding { get; set; } = "HttpPost";
}
```

### 5. SAML Middleware

```csharp
public class SamlMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ISamlService _samlService;
    private readonly ILogger<SamlMiddleware> _logger;
    
    public SamlMiddleware(
        RequestDelegate next, 
        ISamlService samlService, 
        ILogger<SamlMiddleware> logger)
    {
        _next = next;
        _samlService = samlService;
        _logger = logger;
    }
    
    public async Task InvokeAsync(HttpContext context)
    {
        // Add SAML-specific security headers
        if (context.Request.Path.StartsWithSegments("/saml"))
        {
            context.Response.Headers.Add("X-Frame-Options", "DENY");
            context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Add("Cache-Control", "no-cache, no-store, must-revalidate");
            context.Response.Headers.Add("Pragma", "no-cache");
        }
        
        // Log SAML requests for debugging
        if (context.Request.Path.StartsWithSegments("/saml/acs") || 
            context.Request.Path.StartsWithSegments("/saml/sls"))
        {
            _logger.LogInformation("SAML request received: {Method} {Path}", 
                context.Request.Method, context.Request.Path);
                
            // Log form data for POST requests (be careful with sensitive data)
            if (context.Request.Method == "POST" && context.Request.HasFormContentType)
            {
                var samlResponse = context.Request.Form["SAMLResponse"];
                if (!string.IsNullOrEmpty(samlResponse))
                {
                    _logger.LogDebug("SAML Response received (length: {Length})", samlResponse.Length);
                }
            }
        }
        
        await _next(context);
    }
}
```

## Security Best Practices

### 1. Certificate Management
```csharp
public class SamlCertificateService
{
    public X509Certificate2 LoadCertificate(string path, string password)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"Certificate file not found: {path}");
        
        var cert = new X509Certificate2(path, password, X509KeyStorageFlags.MachineKeySet);
        
        // Validate certificate
        if (cert.NotAfter < DateTime.UtcNow)
            throw new InvalidOperationException("Certificate has expired");
            
        if (cert.NotBefore > DateTime.UtcNow)
            throw new InvalidOperationException("Certificate is not yet valid");
        
        return cert;
    }
    
    public bool ValidateCertificateChain(X509Certificate2 certificate)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        
        return chain.Build(certificate);
    }
}
```

### 2. SAML Response Validation
```csharp
public class SamlResponseValidator
{
    public async Task<bool> ValidateResponseAsync(Saml2Response response)
    {
        // Validate response status
        if (response.Status != Saml2StatusCode.Success)
            return false;
        
        // Validate response signature
        if (!ValidateSignature(response))
            return false;
        
        // Validate assertions
        foreach (var assertion in response.Assertions)
        {
            if (!await ValidateAssertionAsync(assertion))
                return false;
        }
        
        return true;
    }
    
    private bool ValidateSignature(Saml2Response response)
    {
        // Implement signature validation logic
        // This would involve checking the XML signature against the IdP's certificate
        return true; // Simplified for example
    }
    
    private async Task<bool> ValidateAssertionAsync(Saml2Assertion assertion)
    {
        // Validate assertion conditions, audience restrictions, etc.
        var now = DateTime.UtcNow;
        
        if (assertion.Conditions.NotBefore.HasValue && now < assertion.Conditions.NotBefore.Value)
            return false;
            
        if (assertion.Conditions.NotOnOrAfter.HasValue && now >= assertion.Conditions.NotOnOrAfter.Value)
            return false;
        
        return true;
    }
}
```

### 3. Replay Attack Prevention
```csharp
public class SamlReplayProtection
{
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _replayWindow = TimeSpan.FromMinutes(5);
    
    public SamlReplayProtection(IMemoryCache cache)
    {
        _cache = cache;
    }
    
    public bool IsReplayAttack(string assertionId)
    {
        var cacheKey = $"saml_assertion_{assertionId}";
        
        if (_cache.TryGetValue(cacheKey, out _))
        {
            return true; // Replay attack detected
        }
        
        // Store assertion ID to prevent replay
        _cache.Set(cacheKey, true, _replayWindow);
        return false;
    }
}
```

## Testing Strategies

### 1. Unit Tests
```csharp
[TestFixture]
public class SamlServiceTests
{
    private SamlService _samlService;
    private Mock<IUserService> _mockUserService;
    
    [SetUp]
    public void Setup()
    {
        _mockUserService = new Mock<IUserService>();
        _samlService = new SamlService(null, _mockUserService.Object, null);
    }
    
    [Test]
    public async Task ValidateAssertionAsync_WithValidAssertion_ShouldReturnTrue()
    {
        // Arrange
        var assertion = CreateValidSamlAssertion();
        
        // Act
        var result = await _samlService.ValidateAssertionAsync(assertion);
        
        // Assert
        Assert.IsTrue(result);
    }
    
    [Test]
    public async Task ValidateAssertionAsync_WithExpiredAssertion_ShouldReturnFalse()
    {
        // Arrange
        var assertion = CreateExpiredSamlAssertion();
        
        // Act
        var result = await _samlService.ValidateAssertionAsync(assertion);
        
        // Assert
        Assert.IsFalse(result);
    }
    
    private Saml2Assertion CreateValidSamlAssertion()
    {
        // Create a valid SAML assertion for testing
        return new Saml2Assertion(new Saml2NameIdentifier("test@example.com"))
        {
            Conditions = new Saml2Conditions
            {
                NotBefore = DateTime.UtcNow.AddMinutes(-5),
                NotOnOrAfter = DateTime.UtcNow.AddMinutes(30)
            }
        };
    }
}
```

### 2. Integration Tests
```csharp
[Test]
public async Task SamlLogin_WithValidResponse_ShouldAuthenticateUser()
{
    // This would require setting up a test SAML IdP or using mock responses
    var samlResponse = CreateMockSamlResponse();
    
    var response = await _client.PostAsync("/saml/acs", 
        new FormUrlEncodedContent(new[] 
        {
            new KeyValuePair<string, string>("SAMLResponse", samlResponse)
        }));
    
    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
}
```

## SAML Troubleshooting

### 1. Common Issues and Solutions

#### Clock Skew Issues
```csharp
public class SamlClockSkewHandler
{
    private readonly TimeSpan _allowedClockSkew = TimeSpan.FromMinutes(5);
    
    public bool IsWithinClockSkew(DateTime timestamp)
    {
        var now = DateTime.UtcNow;
        return Math.Abs((timestamp - now).TotalMinutes) <= _allowedClockSkew.TotalMinutes;
    }
}
```

#### Logging for Debugging
```csharp
public class SamlDebugLogger
{
    private readonly ILogger _logger;
    
    public void LogSamlResponse(string samlResponse)
    {
        if (_logger.IsEnabled(LogLevel.Debug))
        {
            try
            {
                var decodedResponse = Convert.FromBase64String(samlResponse);
                var xmlResponse = Encoding.UTF8.GetString(decodedResponse);
                _logger.LogDebug("SAML Response XML: {XmlResponse}", xmlResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to decode SAML response for logging");
            }
        }
    }
}
```

---
**Next**: Continue with the remaining authentication and authorization notes