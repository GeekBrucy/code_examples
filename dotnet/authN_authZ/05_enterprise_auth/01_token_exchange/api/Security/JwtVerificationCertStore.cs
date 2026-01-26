using System.Security.Cryptography.X509Certificates;

namespace Api.Security;

public sealed class JwtVerificationCertStore
{
    public X509Certificate2 PublicCert { get; }

    public JwtVerificationCertStore(IWebHostEnvironment env)
    {
        var path = Path.Combine(env.ContentRootPath, "jwt-signing.crt");
        if (!File.Exists(path))
            throw new FileNotFoundException($"JWT public cert not found: {path}");

        var raw = File.ReadAllBytes(path);
        PublicCert = X509CertificateLoader.LoadCertificate(raw);
    }
}