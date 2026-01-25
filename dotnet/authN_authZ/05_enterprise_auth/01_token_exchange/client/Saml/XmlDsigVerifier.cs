using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace client.Saml
{
    public static class XmlDsigVerifier
    {
        public static bool VerifyAssertionSignature(string samlResponseXml, X509Certificate2 idpCert)
        {
            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(samlResponseXml);

            var nsm = new XmlNamespaceManager(xmlDoc.NameTable);
            nsm.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            var assertion = xmlDoc.SelectSingleNode("//saml:Assertion", nsm) as XmlElement
                ?? throw new InvalidOperationException("No saml:Assertion found.");

            var signatureNode = assertion.SelectSingleNode("ds:Signature", nsm) as XmlElement
                ?? throw new InvalidOperationException("No ds:Signature found under Assertion.");

            var signedXml = new SignedXml(assertion);
            signedXml.LoadXml(signatureNode);

            return signedXml.CheckSignature(idpCert, true);
        }
    }
}