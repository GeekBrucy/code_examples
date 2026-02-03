namespace _01_custom_auth.Domain
{
    public class Session
    {
        public Guid Id { get; set; } = Guid.NewGuid();

        public Guid UserId { get; set; }
        public User? User { get; set; }

        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset ExpiresAt { get; set; }

        public DateTimeOffset? RevokedAt { get; set; }

        // Optional, keep nullable for now
        public string? UserAgentHash { get; set; }
        public string? IpHash { get; set; }
    }
}