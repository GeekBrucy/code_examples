# Testing Authentication Scheme Behavior

This document explains how to test the difference between `[Authorize]` and `[Authorize(AuthenticationSchemes = "Certificate")]`.

## Current Setup

Right now, your API has **only Certificate authentication** configured. Let's test the behavior:

### Test 1: Call endpoint without certificate

```bash
# Call the "any-auth" endpoint (uses [Authorize])
curl -k https://localhost:5001/api/authschemecomparison/any-auth

# Expected: 401 Unauthorized
# Reason: No authentication provided, and [Authorize] requires ANY auth
```

```bash
# Call the "certificate-only" endpoint (uses [Authorize(AuthenticationSchemes = "Certificate")])
curl -k https://localhost:5001/api/authschemecomparison/certificate-only

# Expected: 403 Forbidden
# Reason: No certificate provided, but Certificate auth is specifically required
```

**Key Difference:**
- `401` = "You need to authenticate" (generic)
- `403` = "You need to authenticate with a specific method" (certificate)

### Test 2: Call endpoints WITH certificate

```bash
# Both endpoints should work with a valid certificate
curl -k \
  --cert certificates/client.pfx:password123 \
  https://localhost:5001/api/authschemecomparison/any-auth

# Expected: 200 OK

curl -k \
  --cert certificates/client.pfx:password123 \
  https://localhost:5001/api/authschemecomparison/certificate-only

# Expected: 200 OK
```

**Current Result:** Both work the same because only Certificate auth exists.

---

## Experiment: Add JWT Authentication

To see the real difference, let's simulate adding JWT authentication.

### Step 1: Add JWT package

```bash
dotnet add API/API.csproj package Microsoft.AspNetCore.Authentication.JwtBearer
```

### Step 2: Modify Program.cs

Add JWT authentication alongside Certificate:

```csharp
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options => { ... })  // Existing certificate config
    .AddJwtBearer(options =>              // ADD THIS
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = false,
            // For demo purposes - accept any token
            SignatureValidator = (token, parameters) => new JwtSecurityToken(token)
        };
    });
```

### Step 3: Test behavior differences

**Create a fake JWT token:**
```bash
# This is a fake token just for demo
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

**Test `/any-auth` endpoint (without scheme specification):**
```bash
# Call with JWT token
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:5001/api/authschemecomparison/any-auth

# Expected: 200 OK ✅
# Reason: [Authorize] accepts ANY valid authentication, including JWT
```

**Test `/certificate-only` endpoint (with scheme specification):**
```bash
# Call with JWT token
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost:5001/api/authschemecomparison/certificate-only

# Expected: 403 Forbidden ❌
# Reason: [Authorize(AuthenticationSchemes = "Certificate")] REJECTS JWT
# Only certificates are accepted!
```

---

## The Security Implication

### Scenario: B2B Partner API

Imagine you have a B2B partner integration that:
- **MUST** use client certificates (regulatory requirement)
- Validates the partner's identity through certificate chain
- Performs mutual TLS (mTLS)

**If you use `[Authorize]`:**
```csharp
[Authorize]  // ❌ DANGEROUS if you add JWT later
public IActionResult TransferMoney([FromBody] TransferRequest request)
{
    // This should ONLY be accessible via certificate
    // But if you add JWT for mobile app, this becomes accessible via JWT too!
}
```

**If someone adds JWT authentication later:**
- Mobile app developers add JWT for their iOS/Android app
- Suddenly, the `/TransferMoney` endpoint accepts JWT tokens
- Your B2B partner's certificate validation is BYPASSED
- Compliance violation! 🚨

**If you use `[Authorize(AuthenticationSchemes = "Certificate")]`:**
```csharp
[Authorize(AuthenticationSchemes = "Certificate")]  // ✅ SAFE
public IActionResult TransferMoney([FromBody] TransferRequest request)
{
    // This endpoint will ONLY accept certificates
    // Even if JWT, Cookie, or any other auth is added
    // Certificate validation is guaranteed!
}
```

**When JWT is added:**
- Mobile app can use their JWT tokens for other endpoints
- But `/TransferMoney` still requires certificates
- B2B compliance is maintained ✅

---

## Summary Table

| Scenario | `[Authorize]` | `[Authorize(AuthenticationSchemes = "Certificate")]` |
|----------|---------------|-----------------------------------------------------|
| **Only Certificate configured** | Works ✅ | Works ✅ |
| **Certificate + JWT configured** | Accepts BOTH ⚠️ | Accepts ONLY Certificate ✅ |
| **No auth provided** | 401 Unauthorized | 403 Forbidden |
| **JWT token provided** | Accepts if JWT configured ⚠️ | Rejects always ✅ |
| **Certificate provided** | Accepts ✅ | Accepts ✅ |
| **Security** | Can change unexpectedly | Guaranteed behavior |

---

## Best Practice Recommendations

### ✅ DO: Specify scheme when authentication method matters

```csharp
// For certificate-required endpoints
[Authorize(AuthenticationSchemes = "Certificate")]

// For JWT-required endpoints
[Authorize(AuthenticationSchemes = "Bearer")]

// For flexible endpoints accepting multiple
[Authorize(AuthenticationSchemes = "Certificate,Bearer")]
```

### ⚠️ CAREFUL: Using [Authorize] alone

```csharp
// Only use when ANY valid authentication is acceptable
[Authorize]  // OK for general protected resources
```

### ❌ DON'T: Rely on "only one auth configured"

```csharp
// Don't assume this is safe because you only have Certificate today
[Authorize]  // Someone might add JWT tomorrow!
```

---

## Your Project

Since this is a **certificate authentication learning project**, using:

```csharp
[Authorize(AuthenticationSchemes = "Certificate")]
```

...is the **correct choice** because:

1. **Educational value** - Shows proper authentication specification
2. **Best practice** - Explicit is better than implicit
3. **Future-proof** - Won't break if you experiment with other auth types
4. **Security** - Guarantees certificate validation
5. **Documentation** - Code clearly states the requirement

---

## Testing Your Understanding

Try this experiment:

1. Remove the scheme from one endpoint:
   ```csharp
   [Authorize]  // Change from Certificate to generic
   public IActionResult Test() { }
   ```

2. Add a simple API key authentication:
   ```csharp
   builder.Services.AddAuthentication()
       .AddCertificate(...)
       .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>("ApiKey", null);
   ```

3. Call the endpoint with an API key instead of certificate

4. Observe:
   - Endpoint with `[Authorize]` → Accepts API key ✅
   - Endpoint with `[Authorize(AuthenticationSchemes = "Certificate")]` → Rejects API key ❌

This demonstrates why specifying the scheme is important for security and intent!
