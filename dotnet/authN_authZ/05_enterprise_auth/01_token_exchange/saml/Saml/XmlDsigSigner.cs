using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace saml.Saml
{
    public static class XmlDsigSigner
    {
        public static string SignAssertion(string samlResponseXml, X509Certificate2 signingCert)
        {
            var xmlDoc = new XmlDocument
            {
                PreserveWhitespace = true
            };
            xmlDoc.LoadXml(samlResponseXml);

            // Find the Assertion element to sign
            var nsm = new XmlNamespaceManager(xmlDoc.NameTable);
            nsm.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

            var assertion = xmlDoc.SelectSingleNode("//saml:Assertion", nsm) as XmlElement
                ?? throw new InvalidOperationException("No saml:Assertion element found.");

            var assertionId = assertion.GetAttribute("ID");
            if (string.IsNullOrWhiteSpace(assertionId))
                throw new InvalidOperationException("Assertion has no ID attribute.");

            // Sign the Assertion
            var signedXml = new SignedXml(assertion)
            {
                SigningKey = signingCert.GetRSAPrivateKey()
                    ?? throw new InvalidOperationException("Signing cert does not have an RSA private key.")
            };

            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

            // Reference by ID
            var reference = new Reference("#" + assertionId);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = SignedXml.XmlDsigSHA256Url;

            signedXml.AddReference(reference);

            // Include the cert in KeyInfo (simplest for now)
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(signingCert));
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();

            var signatureElement = signedXml.GetXml();

            // Append <ds:Signature> inside <Assertion>
            assertion.InsertAfter(xmlDoc.ImportNode(signatureElement, true), assertion.FirstChild);

            return xmlDoc.OuterXml;
        }
    }
}