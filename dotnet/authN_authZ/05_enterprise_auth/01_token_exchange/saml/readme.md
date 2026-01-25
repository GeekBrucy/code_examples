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