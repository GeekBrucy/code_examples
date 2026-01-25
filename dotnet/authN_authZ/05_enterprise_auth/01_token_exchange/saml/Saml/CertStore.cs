using System.Security.Cryptography.X509Certificates;

namespace saml.Saml
{
    public class CertStore
    {
        public X509Certificate2 SigningCert { get; }

        public CertStore(IWebHostEnvironment env)
        {
            var path = Path.Combine(env.ContentRootPath, "idp-signing.pfx");

            if (!File.Exists(path))
                throw new FileNotFoundException($"Signing cert not found: {path}");

            SigningCert = X509CertificateLoader.LoadPkcs12FromFile
            (
                path,
                "devpassword",
                X509KeyStorageFlags.MachineKeySet |
                // X509KeyStorageFlags.EphemeralKeySet |
                X509KeyStorageFlags.Exportable
            );
        }
    }
}