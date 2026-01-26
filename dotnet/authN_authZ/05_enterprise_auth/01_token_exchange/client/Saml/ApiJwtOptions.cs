namespace client.Saml
{
    public sealed class ApiJwtOptions
    {
        public string Issuer { get; init; } = "";
        public string Audience { get; init; } = "";
        public string SigningKey { get; init; } = "";
        public int ExpiresMinutes { get; init; } = 5;
    }
}