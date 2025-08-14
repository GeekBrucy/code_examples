# Security Best Practices

## Overview
This document outlines comprehensive security best practices for authentication and authorization in .NET applications. These practices are based on industry standards, security frameworks like OWASP, and real-world experience in building secure applications.

## Core Security Principles

### 1. Defense in Depth
Implement multiple layers of security controls rather than relying on a single security measure.

#### Implementation Strategy
- **Perimeter Security**: Firewalls, WAF, DDoS protection
- **Network Security**: VPNs, network segmentation, IDS/IPS
- **Application Security**: Input validation, output encoding, secure coding
- **Data Security**: Encryption at rest and in transit, data classification
- **Identity Security**: Strong authentication, authorization, access controls

### 2. Principle of Least Privilege
Grant users and systems only the minimum permissions necessary to perform their functions.

#### Implementation Guidelines
- Start with no permissions and add only what's required
- Regularly review and remove unnecessary permissions
- Use role-based access control (RBAC) with granular permissions
- Implement just-in-time (JIT) access for privileged operations
- Monitor and audit permission usage

### 3. Zero Trust Architecture
Never trust, always verify - authenticate and authorize every request regardless of location.

#### Core Components
- Identity verification for every user and device
- Least privilege access controls
- Microsegmentation of network and resources
- Continuous monitoring and validation
- Assume breach mentality

## Authentication Security Best Practices

### 1. Password Security Implementation

```csharp
public class SecurePasswordService
{
    private readonly ILogger<SecurePasswordService> _logger;
    private readonly PasswordSecurityOptions _options;
    
    public SecurePasswordService(
        ILogger<SecurePasswordService> logger,
        IOptions<PasswordSecurityOptions> options)
    {
        _logger = logger;
        _options = options.Value;
    }
    
    public PasswordValidationResult ValidatePassword(string password, string username, UserContext user)
    {
        var result = new PasswordValidationResult { IsValid = true };
        
        // Length requirements
        if (password.Length < _options.MinLength)
        {
            result.IsValid = false;
            result.Errors.Add($"Password must be at least {_options.MinLength} characters long");
        }
        
        if (password.Length > _options.MaxLength)
        {
            result.IsValid = false;
            result.Errors.Add($"Password must not exceed {_options.MaxLength} characters");
        }
        
        // Complexity requirements
        if (_options.RequireUppercase && !password.Any(char.IsUpper))
        {
            result.IsValid = false;
            result.Errors.Add("Password must contain at least one uppercase letter");
        }
        
        if (_options.RequireLowercase && !password.Any(char.IsLower))
        {
            result.IsValid = false;
            result.Errors.Add("Password must contain at least one lowercase letter");
        }
        
        if (_options.RequireDigit && !password.Any(char.IsDigit))
        {
            result.IsValid = false;
            result.Errors.Add("Password must contain at least one digit");
        }
        
        if (_options.RequireSpecialCharacter && !password.Any(c => !char.IsLetterOrDigit(c)))
        {
            result.IsValid = false;
            result.Errors.Add("Password must contain at least one special character");
        }
        
        // Dictionary attacks prevention
        if (IsCommonPassword(password))
        {
            result.IsValid = false;
            result.Errors.Add("Password is too common. Please choose a more unique password");
        }
        
        // Personal information checks
        if (ContainsPersonalInfo(password, username, user))
        {
            result.IsValid = false;
            result.Errors.Add("Password must not contain personal information");
        }
        
        // Sequential or repeated character checks
        if (HasSequentialOrRepeatedCharacters(password))
        {
            result.IsValid = false;
            result.Errors.Add("Password must not contain sequential or repeated characters");
        }
        
        // Entropy calculation
        var entropy = CalculatePasswordEntropy(password);
        if (entropy < _options.MinEntropy)
        {
            result.IsValid = false;
            result.Errors.Add($"Password entropy too low. Current: {entropy:F1}, Required: {_options.MinEntropy}");
        }
        
        result.Entropy = entropy;
        result.Strength = CalculatePasswordStrength(password, entropy);
        
        return result;
    }
    
    public string HashPassword(string password)
    {
        // Use Argon2id (recommended) or bcrypt
        var salt = GenerateSecureSalt();
        
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = _options.Argon2Parallelism,
            MemorySize = _options.Argon2MemorySize,
            Iterations = _options.Argon2Iterations
        };
        
        var hash = argon2.GetBytes(_options.HashLength);
        
        // Combine salt and hash for storage
        var combined = new byte[salt.Length + hash.Length];
        Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
        Buffer.BlockCopy(hash, 0, combined, salt.Length, hash.Length);
        
        return Convert.ToBase64String(combined);
    }
    
    public bool VerifyPassword(string password, string hashedPassword)
    {
        try
        {
            var combined = Convert.FromBase64String(hashedPassword);
            var salt = new byte[_options.SaltLength];
            var hash = new byte[combined.Length - _options.SaltLength];
            
            Buffer.BlockCopy(combined, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(combined, salt.Length, hash, 0, hash.Length);
            
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = _options.Argon2Parallelism,
                MemorySize = _options.Argon2MemorySize,
                Iterations = _options.Argon2Iterations
            };
            
            var computedHash = argon2.GetBytes(_options.HashLength);
            
            return CryptographicOperations.FixedTimeEquals(hash, computedHash);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying password");
            return false;
        }
    }
    
    private byte[] GenerateSecureSalt()
    {
        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[_options.SaltLength];
        rng.GetBytes(salt);
        return salt;
    }
    
    private bool IsCommonPassword(string password)
    {
        // Check against common password lists (load from file or database)
        var commonPasswords = LoadCommonPasswords();
        return commonPasswords.Contains(password.ToLowerInvariant());
    }
    
    private bool ContainsPersonalInfo(string password, string username, UserContext user)
    {
        var personalInfo = new List<string>
        {
            username?.ToLowerInvariant(),
            user?.FirstName?.ToLowerInvariant(),
            user?.LastName?.ToLowerInvariant(),
            user?.Email?.Split('@').FirstOrDefault()?.ToLowerInvariant(),
            user?.DateOfBirth?.ToString("yyyyMMdd"),
            user?.DateOfBirth?.ToString("ddMMyyyy"),
            user?.PhoneNumber?.Replace("-", "").Replace(" ", "")
        };
        
        var lowerPassword = password.ToLowerInvariant();
        
        return personalInfo.Where(info => !string.IsNullOrEmpty(info))
                          .Any(info => lowerPassword.Contains(info) || info.Contains(lowerPassword));
    }
    
    private bool HasSequentialOrRepeatedCharacters(string password)
    {
        // Check for repeated characters (more than 2 consecutive)
        for (int i = 0; i < password.Length - 2; i++)
        {
            if (password[i] == password[i + 1] && password[i + 1] == password[i + 2])
                return true;
        }
        
        // Check for sequential characters (keyboard patterns)
        var sequences = new[]
        {
            "abcdefghijklmnopqrstuvwxyz",
            "qwertyuiopasdfghjklzxcvbnm",
            "1234567890",
            "!@#$%^&*()"
        };
        
        foreach (var sequence in sequences)
        {
            for (int i = 0; i < sequence.Length - 2; i++)
            {
                var subSeq = sequence.Substring(i, 3);
                if (password.ToLowerInvariant().Contains(subSeq) || 
                    password.ToLowerInvariant().Contains(new string(subSeq.Reverse().ToArray())))
                    return true;
            }
        }
        
        return false;
    }
    
    private double CalculatePasswordEntropy(string password)
    {
        var characterSets = 0;
        
        if (password.Any(char.IsLower)) characterSets += 26;
        if (password.Any(char.IsUpper)) characterSets += 26;
        if (password.Any(char.IsDigit)) characterSets += 10;
        if (password.Any(c => !char.IsLetterOrDigit(c))) characterSets += 32; // Common special chars
        
        return password.Length * Math.Log2(characterSets);
    }
    
    private PasswordStrength CalculatePasswordStrength(string password, double entropy)
    {
        if (entropy >= 80) return PasswordStrength.VeryStrong;
        if (entropy >= 60) return PasswordStrength.Strong;
        if (entropy >= 40) return PasswordStrength.Medium;
        if (entropy >= 25) return PasswordStrength.Weak;
        return PasswordStrength.VeryWeak;
    }
    
    private HashSet<string> LoadCommonPasswords()
    {
        // Load from embedded resource or database
        return new HashSet<string>
        {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "password1"
        };
    }
}

public class PasswordSecurityOptions
{
    public int MinLength { get; set; } = 12;
    public int MaxLength { get; set; } = 256;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireDigit { get; set; } = true;
    public bool RequireSpecialCharacter { get; set; } = true;
    public double MinEntropy { get; set; } = 50.0;
    public int SaltLength { get; set; } = 32;
    public int HashLength { get; set; } = 32;
    public int Argon2Iterations { get; set; } = 3;
    public int Argon2MemorySize { get; set; } = 65536; // 64 MB
    public int Argon2Parallelism { get; set; } = 1;
}

public class PasswordValidationResult
{
    public bool IsValid { get; set; }
    public List<string> Errors { get; set; } = new();
    public double Entropy { get; set; }
    public PasswordStrength Strength { get; set; }
}

public enum PasswordStrength
{
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong
}
```

### 2. Multi-Factor Authentication Security

```csharp
public class SecureMfaService
{
    private readonly ILogger<SecureMfaService> _logger;
    private readonly MfaSecurityOptions _options;
    private readonly IDistributedCache _cache;
    
    public async Task<MfaSetupResult> SetupTotpAsync(string userId, string secret = null)
    {
        try
        {
            // Generate secure secret if not provided
            if (string.IsNullOrEmpty(secret))
            {
                using var rng = RandomNumberGenerator.Create();
                var secretBytes = new byte[20]; // 160 bits
                rng.GetBytes(secretBytes);
                secret = Base32Encode(secretBytes);
            }
            
            // Validate secret entropy
            if (!HasSufficientEntropy(secret))
            {
                throw new SecurityException("TOTP secret has insufficient entropy");
            }
            
            // Store encrypted secret
            var encryptedSecret = await EncryptSecretAsync(secret);
            await StoreTotpSecretAsync(userId, encryptedSecret);
            
            // Generate backup codes
            var backupCodes = GenerateBackupCodes();
            var encryptedBackupCodes = await EncryptBackupCodesAsync(backupCodes);
            await StoreBackupCodesAsync(userId, encryptedBackupCodes);
            
            // Generate QR code data
            var issuer = _options.Issuer;
            var accountName = await GetUserAccountNameAsync(userId);
            var qrCodeUrl = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(accountName)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}";
            
            return new MfaSetupResult
            {
                Success = true,
                Secret = secret,
                QrCodeUrl = qrCodeUrl,
                BackupCodes = backupCodes
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting up TOTP for user {UserId}", userId);
            return new MfaSetupResult { Success = false, Error = "Failed to setup TOTP" };
        }
    }
    
    public async Task<MfaVerificationResult> VerifyTotpAsync(string userId, string code, bool consumeBackupCode = false)
    {
        try
        {
            // Rate limiting
            var rateLimitKey = $"mfa_attempts:{userId}";
            var attempts = await GetMfaAttemptsAsync(rateLimitKey);
            
            if (attempts >= _options.MaxAttempts)
            {
                _logger.LogWarning("MFA rate limit exceeded for user {UserId}", userId);
                return new MfaVerificationResult 
                { 
                    Success = false, 
                    Error = "Too many failed attempts. Please try again later." 
                };
            }
            
            // Increment attempt counter
            await IncrementMfaAttemptsAsync(rateLimitKey);
            
            bool isValid = false;
            
            if (consumeBackupCode)
            {
                isValid = await VerifyBackupCodeAsync(userId, code);
            }
            else
            {
                isValid = await VerifyTotpCodeAsync(userId, code);
            }
            
            if (isValid)
            {
                // Reset attempt counter on success
                await ResetMfaAttemptsAsync(rateLimitKey);
                
                // Log successful verification
                _logger.LogInformation("MFA verification successful for user {UserId}", userId);
                
                return new MfaVerificationResult { Success = true };
            }
            else
            {
                _logger.LogWarning("MFA verification failed for user {UserId}", userId);
                return new MfaVerificationResult 
                { 
                    Success = false, 
                    Error = "Invalid verification code" 
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying MFA for user {UserId}", userId);
            return new MfaVerificationResult 
            { 
                Success = false, 
                Error = "MFA verification error" 
            };
        }
    }
    
    private async Task<bool> VerifyTotpCodeAsync(string userId, string code)
    {
        var encryptedSecret = await GetTotpSecretAsync(userId);
        if (string.IsNullOrEmpty(encryptedSecret))
            return false;
        
        var secret = await DecryptSecretAsync(encryptedSecret);
        var secretBytes = Base32Decode(secret);
        
        // Check current time window and adjacent windows for clock skew
        var unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var timeWindow = unixTime / 30; // 30-second window
        
        for (int i = -_options.TimeWindowTolerance; i <= _options.TimeWindowTolerance; i++)
        {
            var testWindow = timeWindow + i;
            var expectedCode = GenerateTotpCode(secretBytes, testWindow);
            
            if (CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(code), 
                Encoding.UTF8.GetBytes(expectedCode)))
            {
                // Check for replay attacks
                if (await IsCodeAlreadyUsedAsync(userId, code, testWindow))
                {
                    _logger.LogWarning("TOTP replay attack detected for user {UserId}", userId);
                    return false;
                }
                
                // Mark code as used
                await MarkCodeAsUsedAsync(userId, code, testWindow);
                
                return true;
            }
        }
        
        return false;
    }
    
    private async Task<bool> VerifyBackupCodeAsync(string userId, string code)
    {
        var encryptedBackupCodes = await GetBackupCodesAsync(userId);
        var backupCodes = await DecryptBackupCodesAsync(encryptedBackupCodes);
        
        // Use constant-time comparison
        foreach (var backupCode in backupCodes)
        {
            if (CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(code.Replace("-", "")), 
                Encoding.UTF8.GetBytes(backupCode.Replace("-", ""))))
            {
                // Remove used backup code
                backupCodes.Remove(backupCode);
                var newEncryptedCodes = await EncryptBackupCodesAsync(backupCodes);
                await StoreBackupCodesAsync(userId, newEncryptedCodes);
                
                _logger.LogInformation("Backup code used for user {UserId}", userId);
                return true;
            }
        }
        
        return false;
    }
    
    private string GenerateTotpCode(byte[] secret, long timeWindow)
    {
        var timeBytes = BitConverter.GetBytes(timeWindow);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(timeBytes);
        
        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(timeBytes);
        
        var offset = hash[^1] & 0x0F;
        var truncatedHash = ((hash[offset] & 0x7F) << 24) |
                           ((hash[offset + 1] & 0xFF) << 16) |
                           ((hash[offset + 2] & 0xFF) << 8) |
                           (hash[offset + 3] & 0xFF);
        
        var code = truncatedHash % 1000000;
        return code.ToString("D6");
    }
    
    private List<string> GenerateBackupCodes()
    {
        var codes = new List<string>();
        using var rng = RandomNumberGenerator.Create();
        
        for (int i = 0; i < _options.BackupCodeCount; i++)
        {
            var codeBytes = new byte[5]; // 40 bits
            rng.GetBytes(codeBytes);
            
            var code = Convert.ToBase64String(codeBytes)
                             .Replace("+", "")
                             .Replace("/", "")
                             .Replace("=", "")
                             .Substring(0, 8);
            
            // Format as XXXX-XXXX
            code = $"{code.Substring(0, 4)}-{code.Substring(4, 4)}";
            codes.Add(code);
        }
        
        return codes;
    }
    
    private bool HasSufficientEntropy(string secret)
    {
        // Calculate entropy of the secret
        var uniqueChars = secret.Distinct().Count();
        var entropy = secret.Length * Math.Log2(uniqueChars);
        
        return entropy >= _options.MinSecretEntropy;
    }
    
    // Additional helper methods...
    private string Base32Encode(byte[] bytes) { /* Implementation */ return ""; }
    private byte[] Base32Decode(string base32) { /* Implementation */ return new byte[0]; }
    private async Task<string> EncryptSecretAsync(string secret) { /* Implementation */ return ""; }
    private async Task<string> DecryptSecretAsync(string encrypted) { /* Implementation */ return ""; }
    private async Task<List<string>> EncryptBackupCodesAsync(List<string> codes) { /* Implementation */ return new List<string>(); }
    private async Task<List<string>> DecryptBackupCodesAsync(List<string> encrypted) { /* Implementation */ return new List<string>(); }
}

public class MfaSecurityOptions
{
    public string Issuer { get; set; } = "Your App";
    public int MaxAttempts { get; set; } = 5;
    public int TimeWindowTolerance { get; set; } = 1; // Allow 1 window before/after
    public int BackupCodeCount { get; set; } = 8;
    public double MinSecretEntropy { get; set; } = 80.0;
    public TimeSpan RateLimitWindow { get; set; } = TimeSpan.FromMinutes(15);
}
```

### 3. Token Security Best Practices

```csharp
public class SecureTokenService
{
    private readonly TokenSecurityOptions _options;
    private readonly ILogger<SecureTokenService> _logger;
    private readonly IDistributedCache _cache;
    
    public async Task<TokenResult> GenerateTokenAsync(TokenRequest request)
    {
        try
        {
            // Validate request
            var validationResult = ValidateTokenRequest(request);
            if (!validationResult.IsValid)
            {
                return new TokenResult { Success = false, Error = validationResult.Error };
            }
            
            // Generate secure tokens
            var accessToken = await GenerateAccessTokenAsync(request);
            var refreshToken = await GenerateRefreshTokenAsync(request);
            
            // Store token metadata for security tracking
            await StoreTokenMetadataAsync(accessToken, refreshToken, request);
            
            return new TokenResult
            {
                Success = true,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = _options.AccessTokenLifetime.TotalSeconds,
                TokenType = "Bearer"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating token for user {UserId}", request.UserId);
            return new TokenResult { Success = false, Error = "Token generation failed" };
        }
    }
    
    private async Task<string> GenerateAccessTokenAsync(TokenRequest request)
    {
        var now = DateTimeOffset.UtcNow;
        var expiry = now.Add(_options.AccessTokenLifetime);
        
        // Create claims with security context
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, request.UserId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Exp, expiry.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Iss, _options.Issuer),
            new(JwtRegisteredClaimNames.Aud, _options.Audience),
            
            // Security context claims
            new("ip_address", request.IpAddress ?? "unknown"),
            new("user_agent_hash", ComputeHash(request.UserAgent ?? "")),
            new("session_id", request.SessionId ?? ""),
            new("auth_method", request.AuthenticationMethod ?? "unknown"),
            new("security_level", request.SecurityLevel.ToString())
        };
        
        // Add user roles and permissions
        foreach (var role in request.Roles ?? new List<string>())
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        
        foreach (var scope in request.Scopes ?? new List<string>())
        {
            claims.Add(new Claim("scope", scope));
        }
        
        // Create token descriptor with security settings
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expiry.DateTime,
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            SigningCredentials = new SigningCredentials(
                _options.SigningKey, 
                SecurityAlgorithms.RsaSha256), // Use RS256, not HS256
            EncryptingCredentials = _options.EncryptionKey != null 
                ? new EncryptingCredentials(
                    _options.EncryptionKey, 
                    JwtConstants.DirectKeyUseAlg, 
                    SecurityAlgorithms.Aes256CbcHmacSha512) 
                : null
        };
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        
        return tokenHandler.WriteToken(token);
    }
    
    private async Task<string> GenerateRefreshTokenAsync(TokenRequest request)
    {
        // Generate cryptographically secure random refresh token
        using var rng = RandomNumberGenerator.Create();
        var refreshTokenBytes = new byte[64]; // 512 bits
        rng.GetBytes(refreshTokenBytes);
        
        var refreshToken = Convert.ToBase64String(refreshTokenBytes)
                                 .Replace("+", "-")
                                 .Replace("/", "_")
                                 .Replace("=", "");
        
        // Store refresh token with metadata
        var refreshTokenData = new RefreshTokenData
        {
            Token = refreshToken,
            UserId = request.UserId,
            ClientId = request.ClientId,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.Add(_options.RefreshTokenLifetime),
            IpAddress = request.IpAddress,
            UserAgent = request.UserAgent,
            SessionId = request.SessionId,
            IsRevoked = false
        };
        
        await StoreRefreshTokenAsync(refreshTokenData);
        
        return refreshToken;
    }
    
    public async Task<TokenValidationResult> ValidateTokenAsync(string token, TokenValidationParameters parameters = null)
    {
        try
        {
            parameters ??= GetDefaultValidationParameters();
            
            var tokenHandler = new JwtSecurityTokenHandler();
            
            // Validate token structure and signature
            var principal = tokenHandler.ValidateToken(token, parameters, out var validatedToken);
            
            if (validatedToken is not JwtSecurityToken jwtToken)
            {
                return new TokenValidationResult 
                { 
                    IsValid = false, 
                    Error = "Invalid token format" 
                };
            }
            
            // Additional security validations
            var securityValidation = await PerformSecurityValidationsAsync(jwtToken, principal);
            if (!securityValidation.IsValid)
            {
                return securityValidation;
            }
            
            // Check token revocation
            var jti = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            if (!string.IsNullOrEmpty(jti) && await IsTokenRevokedAsync(jti))
            {
                return new TokenValidationResult 
                { 
                    IsValid = false, 
                    Error = "Token has been revoked" 
                };
            }
            
            return new TokenValidationResult
            {
                IsValid = true,
                Principal = principal,
                SecurityToken = validatedToken
            };
        }
        catch (SecurityTokenExpiredException)
        {
            return new TokenValidationResult 
            { 
                IsValid = false, 
                Error = "Token has expired" 
            };
        }
        catch (SecurityTokenSignatureKeyNotFoundException)
        {
            return new TokenValidationResult 
            { 
                IsValid = false, 
                Error = "Token signature key not found" 
            };
        }
        catch (SecurityTokenInvalidSignatureException)
        {
            return new TokenValidationResult 
            { 
                IsValid = false, 
                Error = "Token signature is invalid" 
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating token");
            return new TokenValidationResult 
            { 
                IsValid = false, 
                Error = "Token validation failed" 
            };
        }
    }
    
    private async Task<TokenValidationResult> PerformSecurityValidationsAsync(JwtSecurityToken token, ClaimsPrincipal principal)
    {
        // Validate token age (not too old)
        var iat = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iat)?.Value;
        if (long.TryParse(iat, out var issuedAt))
        {
            var tokenAge = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - issuedAt;
            if (tokenAge > _options.MaxTokenAge.TotalSeconds)
            {
                return new TokenValidationResult 
                { 
                    IsValid = false, 
                    Error = "Token is too old" 
                };
            }
        }
        
        // Validate security context if available
        var ipAddress = principal.FindFirst("ip_address")?.Value;
        var currentIpHash = ComputeHash(GetCurrentIpAddress());
        var tokenIpHash = ComputeHash(ipAddress ?? "");
        
        if (_options.ValidateIpAddress && !CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(currentIpHash), 
            Encoding.UTF8.GetBytes(tokenIpHash)))
        {
            _logger.LogWarning("Token IP address mismatch. Expected: {Expected}, Actual: {Actual}", 
                tokenIpHash, currentIpHash);
            
            return new TokenValidationResult 
            { 
                IsValid = false, 
                Error = "Token IP address validation failed" 
            };
        }
        
        // Validate user agent if required
        var userAgentHash = principal.FindFirst("user_agent_hash")?.Value;
        var currentUserAgentHash = ComputeHash(GetCurrentUserAgent());
        
        if (_options.ValidateUserAgent && !string.IsNullOrEmpty(userAgentHash) &&
            !CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(currentUserAgentHash), 
                Encoding.UTF8.GetBytes(userAgentHash)))
        {
            _logger.LogWarning("Token user agent mismatch");
            
            return new TokenValidationResult 
            { 
                IsValid = false, 
                Error = "Token user agent validation failed" 
            };
        }
        
        return new TokenValidationResult { IsValid = true };
    }
    
    public async Task<bool> RevokeTokenAsync(string tokenId)
    {
        try
        {
            await AddToRevocationListAsync(tokenId);
            _logger.LogInformation("Token {TokenId} has been revoked", tokenId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking token {TokenId}", tokenId);
            return false;
        }
    }
    
    private TokenValidationParameters GetDefaultValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _options.Issuer,
            ValidateAudience = true,
            ValidAudience = _options.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _options.SigningKey,
            TokenDecryptionKey = _options.EncryptionKey,
            ClockSkew = TimeSpan.FromMinutes(5), // Allow 5 minutes clock skew
            RequireExpirationTime = true,
            RequireSignedTokens = true
        };
    }
    
    private string ComputeHash(string input)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input ?? ""));
        return Convert.ToBase64String(hashBytes);
    }
    
    // Additional helper methods...
    private TokenValidation ValidateTokenRequest(TokenRequest request) { return new TokenValidation { IsValid = true }; }
    private async Task StoreTokenMetadataAsync(string accessToken, string refreshToken, TokenRequest request) { }
    private async Task StoreRefreshTokenAsync(RefreshTokenData data) { }
    private async Task<bool> IsTokenRevokedAsync(string jti) { return false; }
    private async Task AddToRevocationListAsync(string tokenId) { }
    private string GetCurrentIpAddress() { return ""; }
    private string GetCurrentUserAgent() { return ""; }
}

public class TokenSecurityOptions
{
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public SecurityKey SigningKey { get; set; }
    public SecurityKey EncryptionKey { get; set; }
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan MaxTokenAge { get; set; } = TimeSpan.FromHours(24);
    public bool ValidateIpAddress { get; set; } = false;
    public bool ValidateUserAgent { get; set; } = false;
}
```

### 4. Input Validation and Output Encoding

```csharp
public class SecurityValidationService
{
    private readonly ILogger<SecurityValidationService> _logger;
    private readonly ValidationOptions _options;
    
    public ValidationResult ValidateInput(string input, InputType inputType, ValidationContext context = null)
    {
        var result = new ValidationResult { IsValid = true };
        
        if (string.IsNullOrEmpty(input))
        {
            return inputType == InputType.Required 
                ? new ValidationResult { IsValid = false, Error = "Input is required" }
                : result;
        }
        
        // Length validation
        if (input.Length > _options.MaxInputLength)
        {
            result.IsValid = false;
            result.Error = $"Input exceeds maximum length of {_options.MaxInputLength}";
            return result;
        }
        
        // Content validation based on input type
        switch (inputType)
        {
            case InputType.Email:
                result = ValidateEmail(input);
                break;
            case InputType.Url:
                result = ValidateUrl(input);
                break;
            case InputType.AlphaNumeric:
                result = ValidateAlphaNumeric(input);
                break;
            case InputType.Numeric:
                result = ValidateNumeric(input);
                break;
            case InputType.Json:
                result = ValidateJson(input);
                break;
            case InputType.Html:
                result = ValidateHtml(input);
                break;
            case InputType.SqlSafe:
                result = ValidateSqlSafe(input);
                break;
            case InputType.PathSafe:
                result = ValidatePathSafe(input);
                break;
            case InputType.Username:
                result = ValidateUsername(input);
                break;
            case InputType.Password:
                result = ValidatePasswordInput(input);
                break;
        }
        
        // Additional security checks
        if (result.IsValid)
        {
            result = PerformSecurityChecks(input, context);
        }
        
        return result;
    }
    
    public string SanitizeInput(string input, SanitizationType sanitizationType)
    {
        if (string.IsNullOrEmpty(input))
            return input;
        
        return sanitizationType switch
        {
            SanitizationType.Html => SanitizeHtml(input),
            SanitizationType.Sql => SanitizeSql(input),
            SanitizationType.JavaScript => SanitizeJavaScript(input),
            SanitizationType.Url => SanitizeUrl(input),
            SanitizationType.FileName => SanitizeFileName(input),
            SanitizationType.AlphaNumeric => SanitizeAlphaNumeric(input),
            _ => input
        };
    }
    
    public string EncodeForOutput(string input, OutputContext outputContext)
    {
        if (string.IsNullOrEmpty(input))
            return input;
        
        return outputContext switch
        {
            OutputContext.Html => System.Web.HttpUtility.HtmlEncode(input),
            OutputContext.HtmlAttribute => System.Web.HttpUtility.HtmlAttributeEncode(input),
            OutputContext.JavaScript => JavaScriptEncoder.Default.Encode(input),
            OutputContext.Url => Uri.EscapeDataString(input),
            OutputContext.Json => JsonEncodedText.Encode(input).Value,
            OutputContext.Css => CssEncode(input),
            OutputContext.Xml => System.Security.SecurityElement.Escape(input),
            _ => input
        };
    }
    
    private ValidationResult ValidateEmail(string email)
    {
        try
        {
            var addr = new MailAddress(email);
            if (addr.Address != email)
            {
                return new ValidationResult { IsValid = false, Error = "Invalid email format" };
            }
            
            // Additional email security checks
            if (IsDisposableEmail(email))
            {
                return new ValidationResult { IsValid = false, Error = "Disposable email addresses are not allowed" };
            }
            
            return new ValidationResult { IsValid = true };
        }
        catch (FormatException)
        {
            return new ValidationResult { IsValid = false, Error = "Invalid email format" };
        }
    }
    
    private ValidationResult ValidateUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return new ValidationResult { IsValid = false, Error = "Invalid URL format" };
        }
        
        // Security checks for URLs
        if (!_options.AllowedSchemes.Contains(uri.Scheme.ToLowerInvariant()))
        {
            return new ValidationResult { IsValid = false, Error = "URL scheme not allowed" };
        }
        
        // Check for suspicious URLs
        if (IsSuspiciousUrl(uri))
        {
            return new ValidationResult { IsValid = false, Error = "Suspicious URL detected" };
        }
        
        return new ValidationResult { IsValid = true };
    }
    
    private ValidationResult PerformSecurityChecks(string input, ValidationContext context)
    {
        // Check for known attack patterns
        var attackPatterns = new[]
        {
            @"<script[^>]*>.*?</script>", // XSS
            @"javascript:", // JavaScript injection
            @"vbscript:", // VBScript injection
            @"on\w+\s*=", // Event handlers
            @"union\s+select", // SQL injection
            @"drop\s+table", // SQL injection
            @"exec\s*\(", // Command injection
            @"eval\s*\(", // Code injection
            @"\.\.\/", // Directory traversal
            @"\.\.\\", // Directory traversal (Windows)
            @"\/etc\/passwd", // Unix system file access
            @"C:\\Windows\\", // Windows system file access
        };
        
        var lowerInput = input.ToLowerInvariant();
        
        foreach (var pattern in attackPatterns)
        {
            if (Regex.IsMatch(lowerInput, pattern, RegexOptions.IgnoreCase))
            {
                _logger.LogWarning("Potential security threat detected in input: {Pattern}", pattern);
                return new ValidationResult 
                { 
                    IsValid = false, 
                    Error = "Input contains potentially malicious content" 
                };
            }
        }
        
        return new ValidationResult { IsValid = true };
    }
    
    private string SanitizeHtml(string input)
    {
        // Use a library like HtmlSanitizer for production
        return System.Web.HttpUtility.HtmlEncode(input);
    }
    
    private string SanitizeSql(string input)
    {
        // Remove or escape SQL metacharacters
        return input.Replace("'", "''")
                   .Replace("--", "")
                   .Replace("/*", "")
                   .Replace("*/", "")
                   .Replace(";", "");
    }
    
    private string SanitizeJavaScript(string input)
    {
        // Remove JavaScript dangerous characters
        return Regex.Replace(input, @"[<>""'&]", match => match.Value switch
        {
            "<" => "&lt;",
            ">" => "&gt;",
            "\"" => "&quot;",
            "'" => "&#x27;",
            "&" => "&amp;",
            _ => match.Value
        });
    }
    
    private string CssEncode(string input)
    {
        // CSS encoding implementation
        return Regex.Replace(input, @"[^\w\-]", match => 
            $"\\{((int)match.Value[0]):X}");
    }
    
    private bool IsDisposableEmail(string email) => false; // Implement disposable email detection
    private bool IsSuspiciousUrl(Uri uri) => false; // Implement suspicious URL detection
}

public enum InputType
{
    Text,
    Email,
    Url,
    AlphaNumeric,
    Numeric,
    Json,
    Html,
    SqlSafe,
    PathSafe,
    Username,
    Password,
    Required
}

public enum SanitizationType
{
    Html,
    Sql,
    JavaScript,
    Url,
    FileName,
    AlphaNumeric
}

public enum OutputContext
{
    Html,
    HtmlAttribute,
    JavaScript,
    Url,
    Json,
    Css,
    Xml
}
```

## Authorization Security Best Practices

### 1. Secure Authorization Implementation

```csharp
public class SecureAuthorizationService
{
    private readonly ILogger<SecureAuthorizationService> _logger;
    private readonly IAuthorizationPolicyProvider _policyProvider;
    private readonly IMemoryCache _cache;
    
    public async Task<AuthorizationResult> AuthorizeAsync(
        ClaimsPrincipal user, 
        object resource, 
        IEnumerable<IAuthorizationRequirement> requirements,
        AuthorizationContext authContext = null)
    {
        try
        {
            // Security logging
            var userId = user?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
            var resourceId = GetResourceIdentifier(resource);
            var requirementNames = string.Join(", ", requirements.Select(r => r.GetType().Name));
            
            _logger.LogDebug("Authorization check: User {UserId}, Resource {ResourceId}, Requirements {Requirements}",
                userId, resourceId, requirementNames);
            
            // Pre-authorization security checks
            var preAuthResult = await PerformPreAuthorizationChecksAsync(user, resource, authContext);
            if (!preAuthResult.Success)
            {
                _logger.LogWarning("Pre-authorization check failed for user {UserId}: {Reason}",
                    userId, preAuthResult.Reason);
                return AuthorizationResult.Failed();
            }
            
            // Check cache for recent authorization decisions
            var cacheKey = GenerateAuthorizationCacheKey(user, resource, requirements);
            if (_cache.TryGetValue(cacheKey, out AuthorizationResult cachedResult))
            {
                _logger.LogDebug("Authorization result found in cache for user {UserId}", userId);
                return cachedResult;
            }
            
            // Perform authorization evaluation
            var authResult = await EvaluateAuthorizationAsync(user, resource, requirements, authContext);
            
            // Cache successful results (not failures for security)
            if (authResult.Succeeded)
            {
                _cache.Set(cacheKey, authResult, TimeSpan.FromMinutes(5));
            }
            
            // Security audit logging
            await LogAuthorizationResultAsync(user, resource, requirements, authResult, authContext);
            
            return authResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during authorization evaluation");
            return AuthorizationResult.Failed(); // Fail secure
        }
    }
    
    private async Task<PreAuthorizationResult> PerformPreAuthorizationChecksAsync(
        ClaimsPrincipal user, 
        object resource, 
        AuthorizationContext authContext)
    {
        // Check if user is authenticated (if required)
        if (user?.Identity?.IsAuthenticated != true)
        {
            return new PreAuthorizationResult 
            { 
                Success = false, 
                Reason = "User not authenticated" 
            };
        }
        
        // Check for account lockout or suspension
        var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(userId) && await IsUserSuspendedAsync(userId))
        {
            return new PreAuthorizationResult 
            { 
                Success = false, 
                Reason = "User account is suspended" 
            };
        }
        
        // Check for session validity
        var sessionId = user.FindFirst("session_id")?.Value;
        if (!string.IsNullOrEmpty(sessionId) && !await IsSessionValidAsync(sessionId))
        {
            return new PreAuthorizationResult 
            { 
                Success = false, 
                Reason = "Session is invalid or expired" 
            };
        }
        
        // Check for IP address restrictions
        if (authContext?.IpAddress != null && !await IsIpAddressAllowedAsync(userId, authContext.IpAddress))
        {
            return new PreAuthorizationResult 
            { 
                Success = false, 
                Reason = "Access from this IP address is not allowed" 
            };
        }
        
        // Check for time-based restrictions
        if (!IsWithinAllowedTimeWindow(user, authContext))
        {
            return new PreAuthorizationResult 
            { 
                Success = false, 
                Reason = "Access not allowed at this time" 
            };
        }
        
        // Check for resource-specific restrictions
        if (resource != null && !await IsResourceAccessibleAsync(user, resource))
        {
            return new PreAuthorizationResult 
            { 
                Success = false, 
                Reason = "Resource is not accessible" 
            };
        }
        
        return new PreAuthorizationResult { Success = true };
    }
    
    private async Task<AuthorizationResult> EvaluateAuthorizationAsync(
        ClaimsPrincipal user,
        object resource,
        IEnumerable<IAuthorizationRequirement> requirements,
        AuthorizationContext authContext)
    {
        var context = new AuthorizationHandlerContext(requirements, user, resource);
        
        // Evaluate each requirement
        foreach (var requirement in requirements)
        {
            var handlers = await GetHandlersAsync(requirement);
            
            foreach (var handler in handlers)
            {
                try
                {
                    await handler.HandleAsync(context);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in authorization handler {HandlerType}", handler.GetType().Name);
                    // Continue with other handlers - don't fail on handler errors
                }
            }
            
            // Check if requirement was satisfied
            if (!context.HasSucceeded && context.Requirements.Contains(requirement))
            {
                _logger.LogDebug("Authorization requirement {RequirementType} was not satisfied",
                    requirement.GetType().Name);
                return AuthorizationResult.Failed();
            }
        }
        
        return context.HasSucceeded ? AuthorizationResult.Succeeded() : AuthorizationResult.Failed();
    }
    
    private async Task LogAuthorizationResultAsync(
        ClaimsPrincipal user,
        object resource,
        IEnumerable<IAuthorizationRequirement> requirements,
        AuthorizationResult result,
        AuthorizationContext authContext)
    {
        var userId = user?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
        var resourceId = GetResourceIdentifier(resource);
        var requirementNames = string.Join(", ", requirements.Select(r => r.GetType().Name));
        
        if (result.Succeeded)
        {
            _logger.LogInformation("Authorization succeeded: User {UserId}, Resource {ResourceId}, Requirements {Requirements}",
                userId, resourceId, requirementNames);
        }
        else
        {
            _logger.LogWarning("Authorization failed: User {UserId}, Resource {ResourceId}, Requirements {Requirements}",
                userId, resourceId, requirementNames);
            
            // Additional security logging for failed attempts
            await LogSecurityEventAsync(new SecurityEvent
            {
                EventType = "AuthorizationFailure",
                UserId = userId,
                ResourceId = resourceId,
                Requirements = requirementNames,
                IpAddress = authContext?.IpAddress,
                UserAgent = authContext?.UserAgent,
                Timestamp = DateTime.UtcNow
            });
        }
    }
    
    private string GenerateAuthorizationCacheKey(
        ClaimsPrincipal user, 
        object resource, 
        IEnumerable<IAuthorizationRequirement> requirements)
    {
        var userId = user?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
        var resourceId = GetResourceIdentifier(resource);
        var requirementHash = ComputeRequirementsHash(requirements);
        
        return $"auth:{userId}:{resourceId}:{requirementHash}";
    }
    
    private string ComputeRequirementsHash(IEnumerable<IAuthorizationRequirement> requirements)
    {
        var requirementString = string.Join("|", requirements.Select(r => r.GetType().FullName).OrderBy(x => x));
        
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(requirementString));
        return Convert.ToBase64String(hashBytes);
    }
    
    private string GetResourceIdentifier(object resource)
    {
        return resource switch
        {
            IIdentifiable identifiable => identifiable.Id.ToString(),
            string str => str,
            int id => id.ToString(),
            Guid guid => guid.ToString(),
            _ => resource?.GetType().Name ?? "unknown"
        };
    }
    
    // Helper methods
    private async Task<bool> IsUserSuspendedAsync(string userId) => false;
    private async Task<bool> IsSessionValidAsync(string sessionId) => true;
    private async Task<bool> IsIpAddressAllowedAsync(string userId, string ipAddress) => true;
    private bool IsWithinAllowedTimeWindow(ClaimsPrincipal user, AuthorizationContext context) => true;
    private async Task<bool> IsResourceAccessibleAsync(ClaimsPrincipal user, object resource) => true;
    private async Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync(IAuthorizationRequirement requirement) => new List<IAuthorizationHandler>();
    private async Task LogSecurityEventAsync(SecurityEvent securityEvent) { }
}

public class AuthorizationContext
{
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public string SessionId { get; set; }
    public DateTime RequestTime { get; set; } = DateTime.UtcNow;
    public Dictionary<string, object> AdditionalData { get; set; } = new();
}

public class PreAuthorizationResult
{
    public bool Success { get; set; }
    public string Reason { get; set; }
}

public class SecurityEvent
{
    public string EventType { get; set; }
    public string UserId { get; set; }
    public string ResourceId { get; set; }
    public string Requirements { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public DateTime Timestamp { get; set; }
}

public interface IIdentifiable
{
    object Id { get; }
}
```

## Security Testing Best Practices

### 1. Security Test Framework

```csharp
[TestFixture]
public class SecurityTestFramework
{
    protected TestServer _server;
    protected HttpClient _client;
    protected IServiceScope _scope;
    
    [SetUp]
    public virtual void Setup()
    {
        var builder = new WebHostBuilder()
            .UseStartup<TestStartup>()
            .ConfigureTestServices(services =>
            {
                // Override services for testing
                services.AddSingleton<ISecurityTestHelper, SecurityTestHelper>();
            });
        
        _server = new TestServer(builder);
        _client = _server.CreateClient();
        _scope = _server.Services.CreateScope();
    }
    
    [TearDown]
    public virtual void TearDown()
    {
        _scope?.Dispose();
        _client?.Dispose();
        _server?.Dispose();
    }
    
    protected async Task<HttpResponseMessage> AuthenticatedRequest(HttpMethod method, string uri, object content = null)
    {
        var token = await GetValidTokenAsync();
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        
        var request = new HttpRequestMessage(method, uri);
        
        if (content != null)
        {
            request.Content = new StringContent(
                JsonSerializer.Serialize(content),
                Encoding.UTF8,
                "application/json");
        }
        
        return await _client.SendAsync(request);
    }
    
    protected async Task<string> GetValidTokenAsync()
    {
        // Generate valid test token
        var tokenService = _scope.ServiceProvider.GetRequiredService<ITokenService>();
        var tokenResult = await tokenService.GenerateTokenAsync(new TokenRequest
        {
            UserId = "test-user",
            Roles = new[] { "User" },
            Scopes = new[] { "api.read", "api.write" }
        });
        
        return tokenResult.AccessToken;
    }
    
    protected void AssertSecurityHeaders(HttpResponseMessage response)
    {
        Assert.That(response.Headers.Contains("X-Content-Type-Options"), Is.True, "Missing X-Content-Type-Options header");
        Assert.That(response.Headers.Contains("X-Frame-Options"), Is.True, "Missing X-Frame-Options header");
        Assert.That(response.Headers.Contains("X-XSS-Protection"), Is.True, "Missing X-XSS-Protection header");
        
        var contentTypeOptions = response.Headers.GetValues("X-Content-Type-Options").FirstOrDefault();
        Assert.That(contentTypeOptions, Is.EqualTo("nosniff"));
        
        var frameOptions = response.Headers.GetValues("X-Frame-Options").FirstOrDefault();
        Assert.That(frameOptions, Is.EqualTo("DENY"));
    }
}

[TestFixture]
public class AuthenticationSecurityTests : SecurityTestFramework
{
    [Test]
    public async Task Login_WithSqlInjectionAttempt_ShouldRejectRequest()
    {
        var maliciousPayload = new
        {
            username = "admin'; DROP TABLE users; --",
            password = "password"
        };
        
        var response = await _client.PostAsJsonAsync("/api/auth/login", maliciousPayload);
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        AssertSecurityHeaders(response);
    }
    
    [Test]
    public async Task Login_WithXssAttempt_ShouldSanitizeInput()
    {
        var maliciousPayload = new
        {
            username = "<script>alert('xss')</script>",
            password = "password"
        };
        
        var response = await _client.PostAsJsonAsync("/api/auth/login", maliciousPayload);
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        
        var content = await response.Content.ReadAsStringAsync();
        Assert.That(content, Does.Not.Contain("<script>"));
    }
    
    [Test]
    public async Task ProtectedEndpoint_WithoutToken_ShouldReturn401()
    {
        var response = await _client.GetAsync("/api/protected");
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        AssertSecurityHeaders(response);
    }
    
    [Test]
    public async Task ProtectedEndpoint_WithExpiredToken_ShouldReturn401()
    {
        var expiredToken = GenerateExpiredToken();
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", expiredToken);
        
        var response = await _client.GetAsync("/api/protected");
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }
    
    [Test]
    public async Task ProtectedEndpoint_WithTamperedToken_ShouldReturn401()
    {
        var validToken = await GetValidTokenAsync();
        var tamperedToken = validToken.Substring(0, validToken.Length - 10) + "TAMPERED==";
        
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tamperedToken);
        
        var response = await _client.GetAsync("/api/protected");
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }
    
    [Test]
    public async Task Login_ExceedingRateLimit_ShouldReturn429()
    {
        var loginPayload = new
        {
            username = "testuser",
            password = "wrongpassword"
        };
        
        // Send multiple requests to exceed rate limit
        var tasks = Enumerable.Range(0, 10)
            .Select(_ => _client.PostAsJsonAsync("/api/auth/login", loginPayload));
        
        var responses = await Task.WhenAll(tasks);
        
        var tooManyRequestsCount = responses.Count(r => r.StatusCode == HttpStatusCode.TooManyRequests);
        Assert.That(tooManyRequestsCount, Is.GreaterThan(0), "Rate limiting not working");
    }
    
    private string GenerateExpiredToken()
    {
        // Generate a token that's already expired
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes("test-signing-key-for-expired-token-generation");
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("sub", "test-user") }),
            Expires = DateTime.UtcNow.AddMinutes(-10), // Expired 10 minutes ago
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}

[TestFixture]
public class AuthorizationSecurityTests : SecurityTestFramework
{
    [Test]
    public async Task AdminEndpoint_WithUserRole_ShouldReturn403()
    {
        // Get token with User role (not Admin)
        var userToken = await GetUserTokenAsync();
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
        
        var response = await _client.GetAsync("/api/admin/users");
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }
    
    [Test]
    public async Task UserResource_AccessByDifferentUser_ShouldReturn403()
    {
        var userToken = await GetUserTokenAsync("user1");
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
        
        // Try to access another user's resource
        var response = await _client.GetAsync("/api/users/user2/profile");
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }
    
    [Test]
    public async Task ResourceAccess_WithInsufficientScope_ShouldReturn403()
    {
        var limitedToken = await GetTokenWithScopesAsync("api.read"); // Missing api.write
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", limitedToken);
        
        var response = await _client.PostAsJsonAsync("/api/data", new { value = "test" });
        
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }
    
    private async Task<string> GetUserTokenAsync(string userId = "test-user")
    {
        var tokenService = _scope.ServiceProvider.GetRequiredService<ITokenService>();
        var tokenResult = await tokenService.GenerateTokenAsync(new TokenRequest
        {
            UserId = userId,
            Roles = new[] { "User" },
            Scopes = new[] { "api.read", "api.write" }
        });
        
        return tokenResult.AccessToken;
    }
    
    private async Task<string> GetTokenWithScopesAsync(params string[] scopes)
    {
        var tokenService = _scope.ServiceProvider.GetRequiredService<ITokenService>();
        var tokenResult = await tokenService.GenerateTokenAsync(new TokenRequest
        {
            UserId = "test-user",
            Roles = new[] { "User" },
            Scopes = scopes
        });
        
        return tokenResult.AccessToken;
    }
}
```

## Monitoring and Logging Best Practices

### 1. Security Event Monitoring

```csharp
public class SecurityEventMonitor
{
    private readonly ILogger<SecurityEventMonitor> _logger;
    private readonly IMetricsCollector _metrics;
    private readonly IAlertingService _alerting;
    private readonly SecurityEventOptions _options;
    
    public async Task LogSecurityEventAsync(SecurityEventData eventData)
    {
        try
        {
            // Structured logging
            _logger.LogInformation("Security Event: {EventType} | User: {UserId} | Resource: {ResourceId} | Result: {Result} | IP: {IpAddress}",
                eventData.EventType,
                eventData.UserId ?? "anonymous",
                eventData.ResourceId ?? "unknown",
                eventData.Success ? "SUCCESS" : "FAILURE",
                eventData.IpAddress);
            
            // Metrics collection
            _metrics.IncrementCounter("security_events_total", new Dictionary<string, string>
            {
                ["event_type"] = eventData.EventType,
                ["result"] = eventData.Success ? "success" : "failure"
            });
            
            // Check for security threats
            await AnalyzeSecurityThreatAsync(eventData);
            
            // Store for analysis
            await StoreSecurityEventAsync(eventData);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error logging security event");
        }
    }
    
    private async Task AnalyzeSecurityThreatAsync(SecurityEventData eventData)
    {
        // Detect potential attacks
        var threatIndicators = new List<string>();
        
        // Brute force detection
        if (eventData.EventType == "LoginFailed")
        {
            var recentFailures = await GetRecentFailedLoginsAsync(eventData.IpAddress, TimeSpan.FromMinutes(15));
            if (recentFailures >= _options.BruteForceThreshold)
            {
                threatIndicators.Add("Potential brute force attack");
                await _alerting.SendAlertAsync($"Brute force attack detected from {eventData.IpAddress}");
            }
        }
        
        // Unusual access patterns
        if (eventData.EventType == "ResourceAccess" && !eventData.Success)
        {
            var recentDenials = await GetRecentAccessDenialsAsync(eventData.UserId, TimeSpan.FromMinutes(10));
            if (recentDenials >= _options.AccessDenialThreshold)
            {
                threatIndicators.Add("Unusual access denial pattern");
            }
        }
        
        // Geographic anomalies
        if (!string.IsNullOrEmpty(eventData.IpAddress))
        {
            var isAnomalous = await DetectGeographicAnomalyAsync(eventData.UserId, eventData.IpAddress);
            if (isAnomalous)
            {
                threatIndicators.Add("Geographic anomaly detected");
            }
        }
        
        // Log threats
        if (threatIndicators.Any())
        {
            _logger.LogWarning("Security threats detected for event {EventId}: {Threats}",
                eventData.EventId, string.Join(", ", threatIndicators));
        }
    }
    
    // Helper methods
    private async Task<int> GetRecentFailedLoginsAsync(string ipAddress, TimeSpan timeWindow) => 0;
    private async Task<int> GetRecentAccessDenialsAsync(string userId, TimeSpan timeWindow) => 0;
    private async Task<bool> DetectGeographicAnomalyAsync(string userId, string ipAddress) => false;
    private async Task StoreSecurityEventAsync(SecurityEventData eventData) { }
}

public class SecurityEventData
{
    public string EventId { get; set; } = Guid.NewGuid().ToString();
    public string EventType { get; set; }
    public string UserId { get; set; }
    public string ResourceId { get; set; }
    public bool Success { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public Dictionary<string, object> AdditionalData { get; set; } = new();
}

public class SecurityEventOptions
{
    public int BruteForceThreshold { get; set; } = 5;
    public int AccessDenialThreshold { get; set; } = 10;
    public TimeSpan MonitoringWindow { get; set; } = TimeSpan.FromMinutes(15);
}
```

---
**Summary**: This comprehensive security best practices guide covers password security, MFA implementation, token security, input validation, authorization security, security testing, and monitoring. Each section provides production-ready code examples with proper error handling, logging, and security considerations.

**Next**: Continue with implementation patterns