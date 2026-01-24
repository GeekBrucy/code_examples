namespace saml.Saml
{
    public sealed class PostModel
    {
        public required string AcsUrl { get; init; }
        public required string SamlResponse { get; init; } // base64
        public string? RelayState { get; init; }
    }
}