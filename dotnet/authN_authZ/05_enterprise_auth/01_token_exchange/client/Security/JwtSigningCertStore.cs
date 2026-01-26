using System.Security.Cryptography.X509Certificates;

namespace Client.Security;

public sealed class JwtSigningCertStore
{
    public X509Certificate2 SigningCert { get; }

    public JwtSigningCertStore(IWebHostEnvironment env)
    {
        var path = Path.Combine(env.ContentRootPath, "jwt-signing.pfx");
        if (!File.Exists(path))
            throw new FileNotFoundException($"JWT signing cert not found: {path}");

        SigningCert = X509CertificateLoader.LoadPkcs12FromFile(
            path,
            "devpassword",
            X509KeyStorageFlags.Exportable
        );
    }
}