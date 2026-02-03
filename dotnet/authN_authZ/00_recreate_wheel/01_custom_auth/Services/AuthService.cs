using _01_custom_auth.Domain;
using _01_custom_auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace _01_custom_auth.Services
{
    /*
	1.	Normalize email (trim/lowercase) and validate inputs.
	2.	Check if the email already exists (unique constraint).
	3.	Hash password via PasswordHasher (get hash/salt/iterations).
	4.	Create user row with hash fields.
	5.	Save changes.
	6.	Return user id (or a result object).

    Later (login step), AuthService will:
	1.	Normalize email
	2.	Load user by email
	3.	Check lockout rules
	4.	Verify password
	5.	Create session + set cookie
    */
    public sealed class AuthService
    {
        private readonly AppDbContext _db;
        private readonly PasswordHasher _hasher;

        public AuthService(AppDbContext db, PasswordHasher hasher)
        {
            _db = db;
            _hasher = hasher;
        }

        public async Task<Guid> RegisterAsync(string email, string password, CancellationToken ct = default)
        {
            email = NormalizeEmail(email);
            if (string.IsNullOrWhiteSpace(email))
                throw new ArgumentException("Email is required", nameof(email));
            if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
                throw new ArgumentException("Password must be at least 8 chars", nameof(password));
            bool exists = await _db.Users.AnyAsync(u => u.Email == email, ct);

            if (exists)
                throw new InvalidOperationException("Email already registered.");

            var (hash, salt, iterations) = _hasher.Hash(password);

            var user = new User
            {
                Email = email,
                PasswordHash = hash,
                PasswordSalt = salt,
                PasswordIterations = iterations,
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync(ct);

            return user.Id;
        }

        private static string NormalizeEmail(string email)
            => (email ?? string.Empty).Trim().ToLowerInvariant();
    }
}