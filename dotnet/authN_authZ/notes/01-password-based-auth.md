# Password-Based Authentication

## Overview
Password-based authentication is the most traditional and widely used authentication method where users provide a username/email and password combination to verify their identity.

## Core Concepts

### 1. Password Storage Security
**Never store passwords in plain text!**

#### Hash Algorithms (in order of preference)
1. **Argon2** (Winner of password hashing competition)
   - Argon2id is recommended variant
   - Memory-hard function
   - Resistant to GPU/ASIC attacks

2. **bcrypt** (Most widely used)
   - Adaptive hash function
   - Built-in salt generation
   - Configurable work factor

3. **scrypt** (Good alternative)
   - Memory-hard function
   - Good for preventing ASIC attacks

4. **PBKDF2** (Acceptable but older)
   - NIST approved
   - Less resistant to specialized hardware

#### Salt and Pepper
- **Salt**: Random value stored with hash (prevents rainbow table attacks)
- **Pepper**: Secret value stored separately (additional security layer)

### 2. Password Policies

#### Strength Requirements
- **Length**: Minimum 8-12 characters (longer is better)
- **Complexity**: Mix of uppercase, lowercase, numbers, symbols
- **Dictionary checks**: Prevent common passwords
- **Personal info checks**: Prevent using name, email, etc.

#### Security Policies
- **Password history**: Prevent reusing last N passwords
- **Password aging**: Force periodic changes (controversial)
- **Account lockout**: Temporary lockout after failed attempts
- **Progressive delays**: Increasing delays between attempts

### 3. Attack Vectors & Mitigations

#### Common Attacks
1. **Brute Force**: Systematic password guessing
2. **Dictionary Attack**: Using common password lists
3. **Rainbow Tables**: Pre-computed hash lookups
4. **Credential Stuffing**: Using breached password lists
5. **Phishing**: Tricking users into revealing passwords

#### Mitigations
- Strong hashing algorithms with salt
- Rate limiting and account lockout
- CAPTCHA after failed attempts
- Multi-factor authentication
- Security monitoring and alerts

## .NET Implementation

### 1. Using ASP.NET Core Identity

#### Basic Setup
```csharp
// Startup.cs or Program.cs
services.AddDefaultIdentity<IdentityUser>(options => {
    // Password settings
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredUniqueChars = 6;
    
    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    
    // User settings
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>();
```

#### Custom Password Validator
```csharp
public class CustomPasswordValidator : IPasswordValidator<IdentityUser>
{
    public async Task<IdentityResult> ValidateAsync(
        UserManager<IdentityUser> manager, 
        IdentityUser user, 
        string password)
    {
        var errors = new List<IdentityError>();
        
        // Check against user's personal information
        if (password.ToLower().Contains(user.UserName.ToLower()))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordContainsUserName",
                Description = "Password cannot contain username"
            });
        }
        
        // Check against common passwords
        var commonPasswords = new[] { "password", "123456", "qwerty" };
        if (commonPasswords.Contains(password.ToLower()))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordTooCommon",
                Description = "Password is too common"
            });
        }
        
        return errors.Any() 
            ? IdentityResult.Failed(errors.ToArray())
            : IdentityResult.Success;
    }
}
```

### 2. Manual Password Hashing (using bcrypt)

#### Installation
```bash
dotnet add package BCrypt.Net-Next
```

#### Implementation
```csharp
using BCrypt.Net;

public class PasswordService
{
    public string HashPassword(string password)
    {
        // Generate salt and hash password
        return BCrypt.HashPassword(password, BCrypt.GenerateSalt(12));
    }
    
    public bool VerifyPassword(string password, string hash)
    {
        return BCrypt.Verify(password, hash);
    }
    
    public bool NeedsRehash(string hash)
    {
        // Check if hash needs to be regenerated with stronger settings
        return BCrypt.PasswordNeedsRehash(hash, 12);
    }
}
```

### 3. Using Argon2 (Recommended)

#### Installation
```bash
dotnet add package Konscious.Security.Cryptography.Argon2
```

#### Implementation
```csharp
using Konscious.Security.Cryptography.Argon2;
using System.Security.Cryptography;
using System.Text;

public class Argon2PasswordService
{
    public async Task<string> HashPasswordAsync(string password)
    {
        var salt = GenerateSalt();
        var hash = await HashPasswordWithSaltAsync(password, salt);
        
        // Combine salt and hash for storage
        return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
    }
    
    public async Task<bool> VerifyPasswordAsync(string password, string storedHash)
    {
        var parts = storedHash.Split(':');
        if (parts.Length != 2) return false;
        
        var salt = Convert.FromBase64String(parts[0]);
        var hash = Convert.FromBase64String(parts[1]);
        
        var newHash = await HashPasswordWithSaltAsync(password, salt);
        return hash.SequenceEqual(newHash);
    }
    
    private byte[] GenerateSalt()
    {
        var salt = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        return salt;
    }
    
    private async Task<byte[]> HashPasswordWithSaltAsync(string password, byte[] salt)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 2, // 2 cores
            Iterations = 3,          // 3 iterations
            MemorySize = 65536       // 64 MB
        };
        
        return await argon2.GetBytesAsync(32);
    }
}
```

### 4. Login Controller Example

```csharp
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    
    public AuthController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
            return Unauthorized("Invalid credentials");
        
        var result = await _signInManager.CheckPasswordSignInAsync(
            user, model.Password, lockoutOnFailure: true);
        
        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, isPersistent: model.RememberMe);
            return Ok(new { message = "Login successful" });
        }
        
        if (result.IsLockedOut)
            return Unauthorized("Account is locked out");
        
        if (result.RequiresTwoFactor)
            return Ok(new { requiresTwoFactor = true });
        
        return Unauthorized("Invalid credentials");
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var user = new IdentityUser 
        { 
            UserName = model.Email, 
            Email = model.Email 
        };
        
        var result = await _userManager.CreateAsync(user, model.Password);
        
        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);
            return Ok(new { message = "Registration successful" });
        }
        
        return BadRequest(result.Errors);
    }
}

public class LoginModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    
    [Required]
    public string Password { get; set; }
    
    public bool RememberMe { get; set; }
}

public class RegisterModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    
    [Required]
    [StringLength(100, MinimumLength = 8)]
    public string Password { get; set; }
    
    [Required]
    [Compare("Password")]
    public string ConfirmPassword { get; set; }
}
```

## Security Best Practices

### 1. Implementation Guidelines
- Always use secure hashing algorithms (Argon2 > bcrypt > scrypt > PBKDF2)
- Generate unique salt for each password
- Use appropriate work factors/iterations
- Implement rate limiting and account lockout
- Log authentication attempts for monitoring

### 2. User Experience
- Provide clear password requirements
- Show password strength indicators
- Support password managers
- Offer password reset functionality
- Consider passwordless alternatives

### 3. Monitoring and Alerting
- Track failed login attempts
- Monitor for brute force attacks
- Alert on suspicious activities
- Implement geographic anomaly detection

## Common Pitfalls

1. **Storing passwords in plain text** - Never do this!
2. **Using weak hashing algorithms** - MD5, SHA1 are broken
3. **Not using salt** - Vulnerable to rainbow tables
4. **Inadequate rate limiting** - Allows brute force attacks
5. **Poor password policies** - Too restrictive or too permissive
6. **Not handling lockouts properly** - Can create denial of service

## Testing Strategies

### Unit Tests
```csharp
[Test]
public async Task HashPassword_ShouldProduceDifferentHashesForSamePassword()
{
    var service = new Argon2PasswordService();
    var password = "TestPassword123!";
    
    var hash1 = await service.HashPasswordAsync(password);
    var hash2 = await service.HashPasswordAsync(password);
    
    Assert.That(hash1, Is.Not.EqualTo(hash2));
    Assert.That(await service.VerifyPasswordAsync(password, hash1), Is.True);
    Assert.That(await service.VerifyPasswordAsync(password, hash2), Is.True);
}
```

### Integration Tests
- Test complete login flow
- Verify lockout mechanisms
- Test password validation rules
- Verify security headers

## Migration Strategies

### Upgrading Hash Algorithms
```csharp
public async Task<bool> VerifyAndUpgradePassword(string userId, string password)
{
    var user = await _userManager.FindByIdAsync(userId);
    
    // Try new algorithm first
    if (await _argon2Service.VerifyPasswordAsync(password, user.PasswordHash))
        return true;
    
    // Fall back to old algorithm
    if (BCrypt.Verify(password, user.PasswordHash))
    {
        // Upgrade to new algorithm
        user.PasswordHash = await _argon2Service.HashPasswordAsync(password);
        await _userManager.UpdateAsync(user);
        return true;
    }
    
    return false;
}
```

---
**Next**: Continue to `02-mfa-methods.md` to learn about Multi-Factor Authentication