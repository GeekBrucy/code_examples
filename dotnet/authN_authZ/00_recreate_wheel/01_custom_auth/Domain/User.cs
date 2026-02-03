namespace _01_custom_auth.Domain
{
    public class User
    {
        public Guid Id { get; set; } = Guid.NewGuid();

        public string Email { get; set; } = string.Empty; // store normalized (lowercase+trim)
        public string PasswordHash { get; set; } = string.Empty;
        public string PasswordSalt { get; set; } = string.Empty;

        public int PasswordIterations { get; set; }

        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public int FailedLoginCount { get; set; }
        public DateTimeOffset? LockoutUntil { get; set; }

        public List<Session> Sessions { get; set; } = new();
    }
}