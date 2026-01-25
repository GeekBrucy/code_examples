using System.Security.Cryptography.X509Certificates;

namespace client.Saml
{
    public sealed class IdpCertStore
    {
        public X509Certificate2 IdpSigningCert { get; set; }
        public IdpCertStore(IWebHostEnvironment env)
        {
            var path = Path.Combine(env.ContentRootPath, "saml-idp-signing.pfx");
            if (!File.Exists(path))
                throw new FileNotFoundException($"IdP cert not found: {path}");

            IdpSigningCert = X509CertificateLoader.LoadPkcs12FromFile
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