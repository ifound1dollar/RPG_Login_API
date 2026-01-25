using System.Security.Cryptography;

namespace RPG_Login_API.Utility
{
    public static class PasswordUtility
    {
        private const int SALT_SIZE = 16;
        private const int HASH_SIZE = 20;
        private const int ITERATIONS = 600000;      // Current OWASP standard as of December 2025



        /// <summary>
        /// Generates a new hash for the passed-in password. Also generates a salt that is stored within
        ///  the combined hash.
        /// </summary>
        /// <param name="password"> The raw password to be hashed. </param>
        /// <returns> The newly generated (and salted) password hash, prepended with hashing algorithm data. </returns>
        public static string GenerateNewPasswordHash(string password)
        {
            // Generate salt.
            byte[] salt = RandomNumberGenerator.GetBytes(SALT_SIZE);

            // Generate hash using PBKDF2.
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, ITERATIONS, HashAlgorithmName.SHA256, HASH_SIZE);

            // Combine salt and hash.
            byte[] combined = new byte[SALT_SIZE + HASH_SIZE];
            Array.Copy(salt, 0, combined, 0, SALT_SIZE);
            Array.Copy(hash, 0, combined, SALT_SIZE, HASH_SIZE);

            // Convert to base64, then add algorithm information and return string.
            string asBase64 = Convert.ToBase64String(combined);
            return string.Format("$pbkdf2-sha256${0}${1}", ITERATIONS, asBase64);
        }

        /// <summary>
        /// Compares a raw (new) password against an existing (stored) password hash. Performs salting and hashing
        ///  internally to run secure comparison.
        /// </summary>
        /// <param name="newPassword"> The raw (new) password being compared. </param>
        /// <param name="hashedPassword"> The stored password hash being compared against. </param>
        /// <returns> Whether the passed-in raw (new) password matches the stored password hash (whether the password is valid). </returns>
        public static bool ComparePasswordToHash(string newPassword, string hashedPassword)
        {
            // Extract iterations and base64 string by splitting on the '$' character.
            string[] split = hashedPassword.Split('$');     // First two elements are the algorithm (starts with $ so [0] is empty string).
            if (!int.TryParse(split[2], out int iterations)) return false;
            string base64 = split[3];

            // Extract hash bytes from entire base64 string.
            byte[] originalBytes = Convert.FromBase64String(base64);

            // Extract salt from beginning of combined byte[], pulling SALT_SIZE bytes.
            byte[] salt = new byte[SALT_SIZE];
            Array.Copy(originalBytes, 0, salt, 0, SALT_SIZE);

            // Generate new hash with extracted salt and input password. Use local iterations because algorithm must match.
            byte[] newBytes = Rfc2898DeriveBytes.Pbkdf2(newPassword, salt, iterations, HashAlgorithmName.SHA256, HASH_SIZE);

            // Compare existing hash against newly-generated hash, returning based on whether they match.
            // NOTE: We only need to compare AFTER the first SALT_SIZE bytes, because the newBytes array has
            //  not been prepended with the salt (originalBytes has).
            for (int i = 0; i < HASH_SIZE; i++)
            {
                if (originalBytes[i + SALT_SIZE] != newBytes[i]) return false;
            }
            return true;        // Will only reach here if there is no mismatch found.
        }
    }
}
