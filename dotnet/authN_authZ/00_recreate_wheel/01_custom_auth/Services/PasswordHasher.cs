using System.Security.Cryptography;

namespace _01_custom_auth.Services
{
    /*
	1.	Validate password input (non-empty).
	2.	Generate a cryptographically secure random salt.
	3.	Choose PBKDF2 parameters:
	•	PRF (e.g., HMACSHA256)
	•	iterations
	•	derived key length
	4.	Derive the key (the “hash”) using PBKDF2(password, salt, iterations,…).
	5.	Store (hash, salt, iterations, algorithm/version).
	6.	Verify:
	•	recompute PBKDF2 with stored salt+iterations
	•	compare with constant-time equality (avoid timing leaks)
    
    */
    public sealed class PasswordHasher
    {
        private const int SaltSizeBytes = 16; // 128-bit
        private const int KeySizeBytes = 32; // 256-bit
        private const int Iterations = 200_000; // reasonable baseline; tune later

        public (string hashBase64, string saltBase64, int iterations) Hash(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be empty.", nameof(password));

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);

            byte[] key = Rfc2898DeriveBytes.Pbkdf2(
                password: password,
                salt: salt,
                iterations: Iterations,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: KeySizeBytes
            );

            return (Convert.ToBase64String(key), Convert.ToBase64String(salt), Iterations);
        }

        public bool Verify(string password, string storedHashBase64, string storedSaltBase64, int iterations)
        {
            if (string.IsNullOrWhiteSpace(password)) return false;
            if (string.IsNullOrWhiteSpace(storedHashBase64)) return false;
            if (string.IsNullOrWhiteSpace(storedSaltBase64)) return false;
            if (iterations <= 0) return false;

            byte[] salt = Convert.FromBase64String(storedSaltBase64);
            byte[] expected = Convert.FromBase64String(storedHashBase64);

            byte[] actual = Rfc2898DeriveBytes.Pbkdf2(
                password: password,
                salt: salt,
                iterations: iterations,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: expected.Length
            );

            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
    }
}