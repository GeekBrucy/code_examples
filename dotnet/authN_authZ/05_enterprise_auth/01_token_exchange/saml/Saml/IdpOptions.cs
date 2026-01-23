namespace saml.Saml
{
    public sealed class IdpOptions
    {
        // This is your IdP "issuer" identifier (EntityID in metadata)
        public string EntityId { get; init; } = "https://localhost:5001/saml";

        // Where SPs will send AuthnRequests
        public string SingleSignOnServiceUrl { get; init; } = "https://localhost:5001/saml/sso";
    }
}