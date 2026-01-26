namespace client2.Saml;

public class SpOptions
{
    // SP identifier
    public string EntityId { get; init; } = "https://localhost:5013/saml";

    // Where your SP receives the SAMLResponse
    public string AssertionConsumerServiceUrl { get; init; } = "https://localhost:5013/saml/acs";

    // ComponentSpace IdP SSO endpoint
    public string IdpSsoUrl { get; init; } = "https://localhost:5009/saml/sso";
}
