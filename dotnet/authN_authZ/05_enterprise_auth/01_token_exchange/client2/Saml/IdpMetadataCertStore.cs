using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

namespace client2.Saml;

public sealed class IdpMetadataCertStore
{
    public X509Certificate2 SigningCert { get; }

    public IdpMetadataCertStore(string metadataXml, string expectedEntityId)
    {
        const string EntityIdAttribute = "entityID";
        var doc = XDocument.Parse(metadataXml);
        XNamespace md = "urn:oasis:names:tc:SAML:2.0:metadata";
        XNamespace ds = "http://www.w3.org/2000/09/xmldsig#";

        var entityId = doc.Root?.Attribute(EntityIdAttribute)?.Value;
        if (string.IsNullOrWhiteSpace(entityId))
            throw new InvalidOperationException("Idp metadata missing entityId");

        if (!string.Equals(entityId, expectedEntityId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Idp entityId mismatch. Expected '{expectedEntityId}', got '{entityId}'");

        var certB64 =
            doc.Descendants(md + "KeyDescriptor")
                .Where(k => (string?)k.Attribute("use") == "signing" || k.Attribute("use") == null)
                .Descendants(ds + "X509Certificate")
                .Select(x => (x.Value ?? "").Replace("\n", "").Replace("\r", "").Trim())
                .FirstOrDefault(s => !string.IsNullOrWhiteSpace(s));
        if (string.IsNullOrWhiteSpace(certB64))
            throw new InvalidOperationException("No ds:X509Certificate found in Idp metadata");

        var raw = Convert.FromBase64String(certB64);
        SigningCert = X509CertificateLoader.LoadCertificate(raw);
    }
}
