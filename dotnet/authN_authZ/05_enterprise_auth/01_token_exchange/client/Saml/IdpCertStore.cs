using System.Security.Cryptography.X509Certificates;

namespace client.Saml
{
    public sealed class IdpCertStore
    {
        public X509Certificate2 IdpSigningCert { get; }

        public IdpCertStore(IWebHostEnvironment env)
        {
            var path = Path.Combine(env.ContentRootPath, "idp.crt");
            if (!File.Exists(path))
                throw new FileNotFoundException($"IdP cert not found: {path}");

            IdpSigningCert = new X509Certificate2(path);
        }
    }
}