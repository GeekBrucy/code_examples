# .NET Certificate Authentication Example

This project demonstrates how to implement **certificate-based authentication** in ASP.NET Core with **certificate chain validation** without requiring system-wide certificate installation.

## Overview

This solution explores:
- ✅ X.509 certificate authentication in ASP.NET Core
- ✅ Custom certificate chain validation (Root CA → Intermediate CA → Client Certificate)
- ✅ Programmatic trust (no system certificate store installation required)
- ✅ Unit and integration testing with generated test certificates
- ✅ Secure endpoints with certificate-based authorization

## Project Structure

```
16_cert_auth/
├── API/                                    # Web API project
│   ├── Controllers/
│   │   ├── SecureController.cs            # Protected and public endpoints
│   │   └── WeatherForecastController.cs   # Example API
│   ├── Services/
│   │   ├── ICertificateValidationService.cs
│   │   └── CertificateValidationService.cs # Custom certificate validation
│   ├── Program.cs                         # Certificate auth configuration
│   └── appsettings.Development.json       # Certificate paths and settings
│
├── API.Tests/                             # Test project
│   ├── CertificateValidationServiceTests.cs    # Unit tests
│   └── SecureControllerIntegrationTests.cs     # Integration tests
│
├── generate-certs.sh                      # Certificate generation (Bash)
├── generate-certs.ps1                     # Certificate generation (PowerShell)
└── certificates/                          # Generated certificates (git-ignored)
    ├── root-ca.crt                        # Root Certificate Authority
    ├── intermediate-ca.crt                # Intermediate CA
    ├── client.pfx                         # Valid client certificate with chain
    └── invalid-client.pfx                 # Self-signed cert for negative testing
```

## Getting Started

### 1. Generate Test Certificates

First, generate a complete certificate chain for local development:

**On macOS/Linux:**
```bash
chmod +x generate-certs.sh
./generate-certs.sh
```

**On Windows (PowerShell):**
```powershell
.\generate-certs.ps1
```

This creates:
- **Root CA** - Your trusted root certificate authority
- **Intermediate CA** - Signed by Root CA
- **Client Certificate** - Signed by Intermediate CA (forms complete chain)
- **Invalid Certificate** - Self-signed (for testing rejection)

**Note:** All certificates are stored in `./certificates/` and are **NOT** installed system-wide.

### 2. Restore Dependencies

```bash
dotnet restore
```

### 3. Run the API

```bash
cd API
dotnet run
```

The API will start on `https://localhost:5001` (or configured port).

### 4. Run Tests

```bash
cd API.Tests
dotnet test
```

## How It Works

### Certificate Chain Validation

The application validates client certificates against a **programmatically loaded CA chain**:

1. **Client presents certificate** during TLS handshake
2. **Kestrel extracts certificate** (configured with `ClientCertificateMode.AllowCertificate`)
3. **Authentication middleware invokes** `CertificateValidationService`
4. **Service validates**:
   - Certificate validity period (NotBefore/NotAfter)
   - Certificate chain (Client → Intermediate CA → Root CA)
   - Chain terminates at a trusted root (loaded from `appsettings.json`)
   - Optional: Extended Key Usage (Client Authentication)
   - Optional: Revocation checking (disabled by default for local dev)

5. **If valid**: User is authenticated with claims from certificate
6. **If invalid**: Request is rejected with detailed error

### Key Configuration

**appsettings.Development.json:**
```json
{
  "CertificateAuthentication": {
    "AllowSelfSigned": true,           // For development only
    "CheckRevocation": false,          // Disable for local testing
    "TrustedCertificates": [
      "certificates/root-ca.crt",      // Your root CA
      "certificates/intermediate-ca.crt"
    ]
  }
}
```

**Program.cs** configures:
- Certificate authentication with custom validation events
- Kestrel to allow/require client certificates
- Custom claims extraction from certificate

### No System Installation Required

The `CertificateValidationService` uses:
```csharp
chain.ChainPolicy.ExtraStore.AddRange(_trustedCertificates);
```

This allows validation against **local certificate files** without modifying the system certificate store.

## API Endpoints

### Public Endpoints (No Authentication)

- **GET** `/api/secure/public` - Public endpoint, no certificate required

### Protected Endpoints (Certificate Required)

- **GET** `/api/secure/protected` - Returns authenticated user info from certificate
- **GET** `/api/secure/validate` - Validates certificate and returns detailed results
- **GET** `/api/secure/admin` - Role-based endpoint (checks OU in certificate)

## Testing with Certificates

### Using curl

```bash
# Public endpoint (no cert required)
curl -k https://localhost:5001/api/secure/public

# Protected endpoint (with valid certificate)
curl -k \
  --cert certificates/client.crt \
  --key certificates/client.key \
  https://localhost:5001/api/secure/protected

# Or using PFX
curl -k \
  --cert certificates/client.pfx:password123 \
  https://localhost:5001/api/secure/protected
```

### Using Postman

1. Go to **Settings → Certificates**
2. Add client certificate:
   - **Host**: `localhost:5001`
   - **PFX file**: `certificates/client.pfx`
   - **Passphrase**: `password123`
3. Make requests to protected endpoints

### Using HttpClient (C#)

```csharp
var handler = new HttpClientHandler();
var clientCert = new X509Certificate2("certificates/client.pfx", "password123");
handler.ClientCertificates.Add(clientCert);

using var client = new HttpClient(handler);
var response = await client.GetAsync("https://localhost:5001/api/secure/protected");
```

## Unit Tests

### CertificateValidationServiceTests

Tests the validation logic in isolation:
- ✅ Certificate expiration detection
- ✅ Not-yet-valid certificate detection
- ✅ Certificate detail extraction
- ✅ Chain validation
- ✅ Configuration handling

### SecureControllerIntegrationTests

End-to-end tests with generated certificates:
- ✅ Public endpoints accessible without certificate
- ✅ Protected endpoints reject requests without certificate
- ✅ Certificate validation endpoint returns details
- ✅ Valid certificate authentication flow

## Security Considerations

### Development vs Production

**Development (Current Setup):**
- `AllowSelfSigned: true` - Accepts self-signed CAs
- `CheckRevocation: false` - No OCSP/CRL checking
- Certificates stored in project folder

**Production:**
- `AllowSelfSigned: false` - Require trusted CA
- `CheckRevocation: true` - Enable revocation checking
- Use proper CA (internal PKI or public CA)
- Secure certificate storage (Azure Key Vault, AWS Secrets Manager, etc.)
- Implement certificate rotation
- Monitor certificate expiration

### Certificate Storage

**⚠️ IMPORTANT:**
- Generated certificates contain **private keys**
- **NEVER** commit certificates to version control
- `.gitignore` is configured to exclude all certificate files
- In production, use secure secret management

## Certificate Chain Structure

```
Root CA (root-ca.crt)
  ├─ Subject: CN=Test Root CA
  ├─ Self-signed
  └─ Valid: 10 years
     │
     └─ Intermediate CA (intermediate-ca.crt)
        ├─ Issuer: CN=Test Root CA
        ├─ Subject: CN=Test Intermediate CA
        └─ Valid: 5 years
           │
           └─ Client Certificate (client.crt)
              ├─ Issuer: CN=Test Intermediate CA
              ├─ Subject: CN=test-client, O=TestClient
              ├─ Extended Key Usage: Client Authentication
              └─ Valid: 1 year
```

## Advanced Scenarios

### Role-Based Authorization

Extract roles from certificate attributes:

```csharp
// Example: Use OU (Organizational Unit) for roles
var ou = GetOrganizationalUnit(clientCert);

if (ou == "Admin")
{
    // Grant admin access
}
```

### Certificate Revocation

Enable in production:

```json
{
  "CertificateAuthentication": {
    "CheckRevocation": true
  }
}
```

Requires:
- OCSP responder or CRL distribution point
- Network access to revocation services

### Multiple Certificate Chains

Support multiple CAs:

```json
{
  "TrustedCertificates": [
    "certs/ca1-root.crt",
    "certs/ca1-intermediate.crt",
    "certs/ca2-root.crt",
    "certs/ca2-intermediate.crt"
  ]
}
```

## Troubleshooting

### Certificate not trusted

**Error:** "Certificate chain does not terminate at a trusted root"

**Solution:**
- Verify `appsettings.json` contains correct CA paths
- Ensure `root-ca.crt` and `intermediate-ca.crt` exist
- Check `AllowSelfSigned` is `true` for development

### Client certificate not sent

**Error:** "No client certificate provided"

**Solution:**
- Verify Kestrel is configured with `ClientCertificateMode.AllowCertificate`
- Check client is sending certificate (curl `-v` flag for verbose output)
- Ensure certificate file has private key (use `.pfx` format)

### Certificate expired

**Solution:**
- Regenerate certificates: `./generate-certs.sh`
- Certificates are valid for 1 year by default

### Tests failing

**Error:** "Certificate files not found"

**Solution:**
- Run certificate generation script first
- Verify `certificates/` folder exists in project root
- Check file permissions

## References

- [ASP.NET Core Certificate Authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/certauth)
- [X.509 Certificates](https://en.wikipedia.org/wiki/X.509)
- [OpenSSL Certificate Management](https://www.openssl.org/docs/)

## License

This is an example project for educational purposes.
