namespace client.Saml
{
    public class SpOptions
    {
        // SP identifier
        public string EntityId { get; init; } = "https://localhost:5003/saml";

        // Where your SP receives the SAMLResponse
        public string AssertionConsumerServiceUrl { get; init; } = "https://localhost:5003/saml/acs";

        // Your IdP SSO endpoint (your saml project)
        public string IdpSsoUrl { get; init; } = "https://localhost:5001/saml/sso";
    }
}