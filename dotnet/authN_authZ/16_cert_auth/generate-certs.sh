#!/bin/bash

# Certificate Generation Script for .NET Certificate Authentication Testing
# This script creates a complete certificate chain without requiring system installation
# Chain: Root CA -> Intermediate CA -> Client Certificate

set -e

CERT_DIR="./certificates"
mkdir -p "$CERT_DIR"

echo "🔐 Generating Certificate Chain for Local Development..."
echo ""

# =============================================================================
# 1. Generate Root CA (Certificate Authority)
# =============================================================================
echo "📜 Step 1: Creating Root CA..."

openssl genrsa -out "$CERT_DIR/root-ca.key" 4096

openssl req -x509 -new -nodes \
    -key "$CERT_DIR/root-ca.key" \
    -sha256 \
    -days 3650 \
    -out "$CERT_DIR/root-ca.crt" \
    -subj "/C=US/ST=Test/L=Test/O=TestRootCA/CN=Test Root CA"

echo "✅ Root CA created: root-ca.crt"
echo ""

# =============================================================================
# 2. Generate Intermediate CA
# =============================================================================
echo "📜 Step 2: Creating Intermediate CA..."

# Generate intermediate CA private key
openssl genrsa -out "$CERT_DIR/intermediate-ca.key" 4096

# Create intermediate CA certificate signing request (CSR)
openssl req -new \
    -key "$CERT_DIR/intermediate-ca.key" \
    -out "$CERT_DIR/intermediate-ca.csr" \
    -subj "/C=US/ST=Test/L=Test/O=TestIntermediateCA/CN=Test Intermediate CA"

# Create extension file for intermediate CA
cat > "$CERT_DIR/intermediate-ca.ext" << EOF
basicConstraints=CA:TRUE
keyUsage=critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

# Sign intermediate CA with root CA
openssl x509 -req \
    -in "$CERT_DIR/intermediate-ca.csr" \
    -CA "$CERT_DIR/root-ca.crt" \
    -CAkey "$CERT_DIR/root-ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/intermediate-ca.crt" \
    -days 1825 \
    -sha256 \
    -extfile "$CERT_DIR/intermediate-ca.ext"

echo "✅ Intermediate CA created: intermediate-ca.crt"
echo ""

# =============================================================================
# 3. Generate Client Certificate
# =============================================================================
echo "📜 Step 3: Creating Client Certificate..."

# Generate client private key
openssl genrsa -out "$CERT_DIR/client.key" 2048

# Create client certificate signing request (CSR)
openssl req -new \
    -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -subj "/C=US/ST=Test/L=Test/O=TestClient/CN=test-client"

# Create extension file for client certificate
cat > "$CERT_DIR/client.ext" << EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

# Sign client certificate with intermediate CA
openssl x509 -req \
    -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/intermediate-ca.crt" \
    -CAkey "$CERT_DIR/intermediate-ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/client.crt" \
    -days 365 \
    -sha256 \
    -extfile "$CERT_DIR/client.ext"

echo "✅ Client certificate created: client.crt"
echo ""

# =============================================================================
# 4. Create Certificate Chain Files
# =============================================================================
echo "📜 Step 4: Creating certificate chain bundles..."

# Create full chain file (client -> intermediate -> root)
cat "$CERT_DIR/client.crt" "$CERT_DIR/intermediate-ca.crt" "$CERT_DIR/root-ca.crt" > "$CERT_DIR/client-full-chain.crt"

# Create CA bundle (intermediate -> root)
cat "$CERT_DIR/intermediate-ca.crt" "$CERT_DIR/root-ca.crt" > "$CERT_DIR/ca-bundle.crt"

echo "✅ Certificate chains created"
echo ""

# =============================================================================
# 5. Create PFX files for .NET (with private keys)
# =============================================================================
echo "📜 Step 5: Creating PFX files for .NET..."

# Client certificate PFX (with full chain)
openssl pkcs12 -export \
    -out "$CERT_DIR/client.pfx" \
    -inkey "$CERT_DIR/client.key" \
    -in "$CERT_DIR/client.crt" \
    -certfile "$CERT_DIR/ca-bundle.crt" \
    -passout pass:password123

# Root CA PFX
openssl pkcs12 -export \
    -out "$CERT_DIR/root-ca.pfx" \
    -inkey "$CERT_DIR/root-ca.key" \
    -in "$CERT_DIR/root-ca.crt" \
    -passout pass:password123

echo "✅ PFX files created (password: password123)"
echo ""

# =============================================================================
# 6. Generate an Invalid Client Certificate (for negative testing)
# =============================================================================
echo "📜 Step 6: Creating invalid client certificate (for testing)..."

# Generate invalid client private key
openssl genrsa -out "$CERT_DIR/invalid-client.key" 2048

# Create self-signed certificate (not signed by our CA chain)
openssl req -x509 -new \
    -key "$CERT_DIR/invalid-client.key" \
    -out "$CERT_DIR/invalid-client.crt" \
    -days 365 \
    -subj "/C=US/ST=Test/L=Test/O=InvalidClient/CN=invalid-client"

# Create PFX for invalid certificate
openssl pkcs12 -export \
    -out "$CERT_DIR/invalid-client.pfx" \
    -inkey "$CERT_DIR/invalid-client.key" \
    -in "$CERT_DIR/invalid-client.crt" \
    -passout pass:password123

echo "✅ Invalid certificate created for negative testing"
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✨ Certificate Generation Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📁 All certificates are in: $CERT_DIR"
echo ""
echo "Certificate Chain Structure:"
echo "  Root CA: root-ca.crt"
echo "  ├─ Intermediate CA: intermediate-ca.crt"
echo "  │  └─ Client Certificate: client.crt"
echo ""
echo "Files for .NET Application:"
echo "  • root-ca.crt          - Root CA to trust programmatically"
echo "  • ca-bundle.crt        - Full CA chain (intermediate + root)"
echo "  • client.pfx           - Client cert with chain (password: password123)"
echo "  • invalid-client.pfx   - Invalid cert for negative tests"
echo ""
echo "Key Files (keep these secret in production!):"
echo "  • *.key files          - Private keys"
echo "  • *.pfx files          - PKCS#12 with private keys"
echo ""
echo "⚠️  Note: These certificates are for LOCAL DEVELOPMENT ONLY"
echo "⚠️  PFX Password: password123"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
