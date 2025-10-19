# Certificate Generation Script for .NET Certificate Authentication Testing (PowerShell)
# This script creates a complete certificate chain without requiring system installation
# Chain: Root CA -> Intermediate CA -> Client Certificate

$ErrorActionPreference = "Stop"

$CERT_DIR = ".\certificates"
New-Item -ItemType Directory -Force -Path $CERT_DIR | Out-Null

Write-Host "🔐 Generating Certificate Chain for Local Development..." -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 1. Generate Root CA (Certificate Authority)
# =============================================================================
Write-Host "📜 Step 1: Creating Root CA..." -ForegroundColor Yellow

& openssl genrsa -out "$CERT_DIR\root-ca.key" 4096

& openssl req -x509 -new -nodes `
    -key "$CERT_DIR\root-ca.key" `
    -sha256 `
    -days 3650 `
    -out "$CERT_DIR\root-ca.crt" `
    -subj "/C=US/ST=Test/L=Test/O=TestRootCA/CN=Test Root CA"

Write-Host "✅ Root CA created: root-ca.crt" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 2. Generate Intermediate CA
# =============================================================================
Write-Host "📜 Step 2: Creating Intermediate CA..." -ForegroundColor Yellow

& openssl genrsa -out "$CERT_DIR\intermediate-ca.key" 4096

& openssl req -new `
    -key "$CERT_DIR\intermediate-ca.key" `
    -out "$CERT_DIR\intermediate-ca.csr" `
    -subj "/C=US/ST=Test/L=Test/O=TestIntermediateCA/CN=Test Intermediate CA"

# Create extension file for intermediate CA
@"
basicConstraints=CA:TRUE
keyUsage=critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
"@ | Out-File -FilePath "$CERT_DIR\intermediate-ca.ext" -Encoding ASCII

& openssl x509 -req `
    -in "$CERT_DIR\intermediate-ca.csr" `
    -CA "$CERT_DIR\root-ca.crt" `
    -CAkey "$CERT_DIR\root-ca.key" `
    -CAcreateserial `
    -out "$CERT_DIR\intermediate-ca.crt" `
    -days 1825 `
    -sha256 `
    -extfile "$CERT_DIR\intermediate-ca.ext"

Write-Host "✅ Intermediate CA created: intermediate-ca.crt" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 3. Generate Client Certificate
# =============================================================================
Write-Host "📜 Step 3: Creating Client Certificate..." -ForegroundColor Yellow

& openssl genrsa -out "$CERT_DIR\client.key" 2048

& openssl req -new `
    -key "$CERT_DIR\client.key" `
    -out "$CERT_DIR\client.csr" `
    -subj "/C=US/ST=Test/L=Test/O=TestClient/CN=test-client"

# Create extension file for client certificate
@"
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
"@ | Out-File -FilePath "$CERT_DIR\client.ext" -Encoding ASCII

& openssl x509 -req `
    -in "$CERT_DIR\client.csr" `
    -CA "$CERT_DIR\intermediate-ca.crt" `
    -CAkey "$CERT_DIR\intermediate-ca.key" `
    -CAcreateserial `
    -out "$CERT_DIR\client.crt" `
    -days 365 `
    -sha256 `
    -extfile "$CERT_DIR\client.ext"

Write-Host "✅ Client certificate created: client.crt" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 4. Create Certificate Chain Files
# =============================================================================
Write-Host "📜 Step 4: Creating certificate chain bundles..." -ForegroundColor Yellow

# Create full chain file (client -> intermediate -> root)
Get-Content "$CERT_DIR\client.crt", "$CERT_DIR\intermediate-ca.crt", "$CERT_DIR\root-ca.crt" | Set-Content "$CERT_DIR\client-full-chain.crt"

# Create CA bundle (intermediate -> root)
Get-Content "$CERT_DIR\intermediate-ca.crt", "$CERT_DIR\root-ca.crt" | Set-Content "$CERT_DIR\ca-bundle.crt"

Write-Host "✅ Certificate chains created" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 5. Create PFX files for .NET (with private keys)
# =============================================================================
Write-Host "📜 Step 5: Creating PFX files for .NET..." -ForegroundColor Yellow

& openssl pkcs12 -export `
    -out "$CERT_DIR\client.pfx" `
    -inkey "$CERT_DIR\client.key" `
    -in "$CERT_DIR\client.crt" `
    -certfile "$CERT_DIR\ca-bundle.crt" `
    -passout pass:password123

& openssl pkcs12 -export `
    -out "$CERT_DIR\root-ca.pfx" `
    -inkey "$CERT_DIR\root-ca.key" `
    -in "$CERT_DIR\root-ca.crt" `
    -passout pass:password123

Write-Host "✅ PFX files created (password: password123)" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 6. Generate an Invalid Client Certificate (for negative testing)
# =============================================================================
Write-Host "📜 Step 6: Creating invalid client certificate (for testing)..." -ForegroundColor Yellow

& openssl genrsa -out "$CERT_DIR\invalid-client.key" 2048

& openssl req -x509 -new `
    -key "$CERT_DIR\invalid-client.key" `
    -out "$CERT_DIR\invalid-client.crt" `
    -days 365 `
    -subj "/C=US/ST=Test/L=Test/O=InvalidClient/CN=invalid-client"

& openssl pkcs12 -export `
    -out "$CERT_DIR\invalid-client.pfx" `
    -inkey "$CERT_DIR\invalid-client.key" `
    -in "$CERT_DIR\invalid-client.crt" `
    -passout pass:password123

Write-Host "✅ Invalid certificate created for negative testing" -ForegroundColor Green
Write-Host ""

# =============================================================================
# Summary
# =============================================================================
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "✨ Certificate Generation Complete!" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "📁 All certificates are in: $CERT_DIR" -ForegroundColor White
Write-Host ""
Write-Host "Certificate Chain Structure:" -ForegroundColor White
Write-Host "  Root CA: root-ca.crt"
Write-Host "  ├─ Intermediate CA: intermediate-ca.crt"
Write-Host "  │  └─ Client Certificate: client.crt"
Write-Host ""
Write-Host "Files for .NET Application:" -ForegroundColor White
Write-Host "  • root-ca.crt          - Root CA to trust programmatically"
Write-Host "  • ca-bundle.crt        - Full CA chain (intermediate + root)"
Write-Host "  • client.pfx           - Client cert with chain (password: password123)"
Write-Host "  • invalid-client.pfx   - Invalid cert for negative tests"
Write-Host ""
Write-Host "Key Files (keep these secret in production!):" -ForegroundColor Yellow
Write-Host "  • *.key files          - Private keys"
Write-Host "  • *.pfx files          - PKCS#12 with private keys"
Write-Host ""
Write-Host "⚠️  Note: These certificates are for LOCAL DEVELOPMENT ONLY" -ForegroundColor Red
Write-Host "⚠️  PFX Password: password123" -ForegroundColor Red
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
