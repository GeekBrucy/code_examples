ran `dotnet dev-certs https -ep saml-idp-signing.pfx -p "devpassword"`

# Test with certificate

Generate IdP signing cert

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout idp.key \
  -out idp.crt \
  -days 365 \
  -nodes \
  -subj "/CN=SamlIdp"
```
Convert to PFX:

```bash
openssl pkcs12 -export \
  -inkey idp.key \
  -in idp.crt \
  -out idp.pfx \
  -password pass:devpassword
```
Use idp.pfx in IdP.

---

Generate a different cert for testing failure

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout wrong.key \
  -out wrong.crt \
  -days 365 \
  -nodes \
  -subj "/CN=WrongIdp"
```
```bash
openssl pkcs12 -export \
  -inkey wrong.key \
  -in wrong.crt \
  -out wrong.pfx \
  -password pass:devpassword
```
Use wrong.pfx in SP.

---
# Step 1 — Generate a real IdP signing certificate (once)
Run this outside both projects (any folder is fine).

Generate private key + self-signed cert
```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout idp.key \
  -out idp.crt \
  -days 365 \
  -nodes \
  -subj "/CN=SamlIdp"
```
Convert to PFX (for IdP only)
```bash
openssl pkcs12 -export \
  -inkey idp.key \
  -in idp.crt \
  -out idp-signing.pfx \
  -password pass:devpassword
```
Now you have:
	•	idp-signing.pfx → IdP
	•	idp.crt → SP

# Step 2 — IdP: load PFX (private key)

Put this file into IdP project root

```
saml/idp-signing.pfx
```

Your existing CertStore is already correct.
Just confirm it loads idp-signing.pfx.

✅ IdP keeps the private key
❌ SP must NOT have this file

# Step 3 — SP: load CER only (public key)
Put this file into SP project root
```
client/idp-signing.crt
```
Replace IdpCertStore in SP with this

```csharp
using System.Security.Cryptography.X509Certificates;

namespace Client.Saml;

public sealed class IdpCertStore
{
    public X509Certificate2 IdpSigningCert { get; }

    public IdpCertStore(IWebHostEnvironment env)
    {
        var path = Path.Combine(env.ContentRootPath, "idp-signing.crt");
        if (!File.Exists(path))
            throw new FileNotFoundException($"IdP cert not found: {path}");

        IdpSigningCert = new X509Certificate2(path);
    }
}
```

No password.
No private key.
No export flags.

# Step 4 — Verify the split is real (important)

In Idp:
```csharp
Console.WriteLine($"[IdP] Signing cert thumbprint = {_certs.SigningCert.Thumbprint}");
```

In SP:
```csharp
Console.WriteLine($"[SP] Trusted IdP cert thumbprint = {_idpCerts.IdpSigningCert.Thumbprint}");
```

They must match.

Now delete idp.key and keep only:
	•	idp-signing.pfx in IdP
	•	idp.crt in SP