using System.Security.Cryptography;
using System.Xml.Linq;

namespace saml.Saml
{
    public static class SamlResponseBuilder
    {
        public static string BuildUnsignedResponseXml(
            string inResponseTo,
            string destinationAcsUrl,
            string spEntityId,
            string subjectNameId
        )
        {
            var now = DateTime.UtcNow;
            var issueInstant = now.ToString("o");
            var notOnOrAfter = now.AddMinutes(5).ToString("o");

            var responseId = "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            var assertionId = "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

            XNamespace samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
            XNamespace saml = "urn:oasis:names:tc:SAML:2.0:assertion";

            var doc =
                new XDocument(
                    new XElement(samlp + "Response",
                        new XAttribute("ID", responseId),
                        new XAttribute("Version", "2.0"),
                        new XAttribute("IssueInstant", issueInstant),
                        new XAttribute("Destination", destinationAcsUrl),
                        new XAttribute("InResponseTo", inResponseTo),

                        // IdP issuer (we'll set later from options; caller can replace if desired)
                        new XElement(saml + "Issuer", "SamlIdp"),

                        new XElement(samlp + "Status",
                            new XElement(samlp + "StatusCode",
                                new XAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
                            )
                        ),

                        new XElement(saml + "Assertion",
                            new XAttribute("ID", assertionId),
                            new XAttribute("Version", "2.0"),
                            new XAttribute("IssueInstant", issueInstant),

                            new XElement(saml + "Issuer", "SamlIdp"),

                            new XElement(saml + "Subject",
                                new XElement(saml + "NameID",
                                    new XAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
                                    subjectNameId
                                ),
                                new XElement(saml + "SubjectConfirmation",
                                    new XAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer"),
                                    new XElement(saml + "SubjectConfirmationData",
                                        new XAttribute("InResponseTo", inResponseTo),
                                        new XAttribute("NotOnOrAfter", notOnOrAfter),
                                        new XAttribute("Recipient", destinationAcsUrl)
                                    )
                                )
                            ),

                            new XElement(saml + "Conditions",
                                new XAttribute("NotBefore", now.AddMinutes(-1).ToString("o")),
                                new XAttribute("NotOnOrAfter", notOnOrAfter),
                                new XElement(saml + "AudienceRestriction",
                                    new XElement(saml + "Audience", spEntityId)
                                )
                            ),

                            new XElement(saml + "AuthnStatement",
                                new XAttribute("AuthnInstant", issueInstant),
                                new XElement(saml + "AuthnContext",
                                    new XElement(saml + "AuthnContextClassRef",
                                        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
                                )
                            ),
                            new XElement(saml + "AttributeStatement",
                                new XElement(saml + "Attribute",
                                    new XAttribute("Name", "email"),
                                    new XElement(saml + "AttributeValue", $"{subjectNameId}@example.com")
                                ),
                                new XElement(saml + "Attribute",
                                    new XAttribute("Name", "given_name"),
                                    new XElement(saml + "AttributeValue", "Demo")
                                ),
                                new XElement(saml + "Attribute",
                                    new XAttribute("Name", "family_name"),
                                    new XElement(saml + "AttributeValue", "User")
                                ),
                                new XElement(saml + "Attribute",
                                    new XAttribute("Name", "role"),
                                    new XElement(saml + "AttributeValue", "Admin"),
                                    new XElement(saml + "AttributeValue", "Reader")
                                )
                            )
                        )
                    )
                );

            // Compact string
            return doc.ToString(SaveOptions.DisableFormatting);
        }
    }
}