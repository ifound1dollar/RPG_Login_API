using MailKit.Search;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using OtpNet;
using QRCoder;
using RPG_Login_API.Configuration;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;
using System.Security.Cryptography;
using System.Text;

namespace RPG_Login_API.Services
{
    public class MfaCodeService : IMfaCodeService
    {
        // https://www.youtube.com/watch?v=pNEaBQIJ_Dg

        private readonly IOptions<MfaServiceSettings> _settings;
        private readonly ILogger _logger;

        public MfaCodeService(IOptions<MfaServiceSettings> settings, ILogger<MfaCodeService> logger)
        {
            _settings = settings;
            _logger = logger;

            // TEMP DELETE THIS
            //SecureRandom random = new();
            //CipherKeyGenerator keyGen = new();
            //keyGen.Init(new KeyGenerationParameters(random, 256));
            //byte[] key = keyGen.GenerateKey();
            //Console.WriteLine(Convert.ToBase64String(key));
        }



        public bool ValidateMfaCode(UserAccountModel userAccount, string mfaCode, bool isForActive)
        {
            mfaCode = mfaCode.Trim();

            // Retrieve encrypted key from database, then securely decrypt it for comparison use.
            string encryptedKey = (isForActive) ? userAccount.ActiveMfaKey : userAccount.PendingMfaKey;
            if (string.IsNullOrEmpty(encryptedKey)) return false;
            byte[] rawKey = DecryptMfaKey(encryptedKey);

            // Use library to validate submitted code using the active MFA key. RfcSpecifiedNetworkDelay allows +-1 code buffer.
            var totp = new Totp(rawKey);
            bool isValid = totp.VerifyTotp(mfaCode, out var timeStepMatched, VerificationWindow.RfcSpecifiedNetworkDelay);

            return isValid;
        }

        public bool ValidateRecoveryCode(UserAccountModel userAccount, string recoveryCode)
        {
            // Remove any whitespace from user-submitted recovery code, and make uppercase (code is in hex form).
            string cleanCode = recoveryCode.Replace(" ", "");
            cleanCode = cleanCode.ToUpperInvariant();

            // Retrieve hashed code from database and compare, then return whether they match.
            string hashedCode = userAccount.MfaRecoveryCodeHash;
            bool isValid = HashUtility.CompareMfaRecoveryCodeToHash(cleanCode, hashedCode);

            return isValid;
        }

        public string GenerateMfaSecretKeyEncryptedBase64()
        {
            // Generate MFA key.
            byte[] mfaKey = KeyGeneration.GenerateRandomKey();
            return EncryptMfaKey(mfaKey);
        }

        public string GenerateMfaRecoveryCode()
        {
            byte[] randomBytes = new byte[12];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToHexString(randomBytes).ToUpperInvariant();
        }

        public string GenerateOtpUriForUser(string username, string encryptedSecretKeyBase64)
        {
            // Decrypt encrypted key and convert to base32, as required by the OTP service.
            byte[] keyBytes = DecryptMfaKey(encryptedSecretKeyBase64);
            string base32Key = Base32Encoding.ToString(keyBytes);

            // Generate an OTP URI, used by authenticator apps.
            string issuer = Uri.EscapeDataString(_settings.Value.Issuer);
            string user = Uri.EscapeDataString(username);
            string otpUri =
                $"""
                otpauth://totp/{issuer}:{user}?secret={base32Key}&issuer={issuer}&digits=6&period=30
                """;

            return otpUri;
        }



        #region Private: Utility

        private string EncryptMfaKey(byte[] rawKeyBytes)
        {
            // Encrypting with AES-GCM. 256-bit key. 12-byte nonce.

            // Create nonce and convert string encryption key to byte[].
            byte[] nonce = new byte[12];
            new SecureRandom().NextBytes(nonce);
            byte[] key = Convert.FromBase64String(_settings.Value.Base64Key);

            // Generate and initialize cipher with encryption parameters.
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, nonce);
            cipher.Init(true, parameters);

            // Actually perform encryption.
            byte[] cipherText = new byte[cipher.GetOutputSize(rawKeyBytes.Length)];
            int len = cipher.ProcessBytes(rawKeyBytes, 0, rawKeyBytes.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            // Combine nonce with ciphertext (required for decryption), then return combined as UTF8 string.
            byte[] combined = new byte[nonce.Length + cipherText.Length];
            Array.Copy(nonce, 0, combined, 0, nonce.Length);
            Array.Copy(cipherText, 0, combined, nonce.Length, cipherText.Length);

            return Convert.ToBase64String(combined);
        }

        private byte[] DecryptMfaKey(string encryptedKey)
        {
            // Decrypting with AES-GCM. 256-bit key. 12-byte nonce.

            // Convert input string to byte[].
            byte[] encryptedKeyBytes = Convert.FromBase64String(encryptedKey);

            // Convert string encryption key to byte[].
            byte[] key = Convert.FromBase64String(_settings.Value.Base64Key);

            // Pull nonce from first 12 bytes of encrypted key, and store remainder of actual key in separate byte[].
            byte[] nonce = new byte[12];
            Array.Copy(encryptedKeyBytes, nonce, nonce.Length);
            byte[] splitBytes = new byte[encryptedKeyBytes.Length - nonce.Length];
            Array.Copy(encryptedKeyBytes, nonce.Length, splitBytes, 0, splitBytes.Length);

            // Generate and initialize cipher with decryption parameters.
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, nonce);
            cipher.Init(false, parameters);

            // Actually perform decryption.
            byte[] plainText = new byte[cipher.GetOutputSize(splitBytes.Length)];
            int len = cipher.ProcessBytes(splitBytes, 0, splitBytes.Length, plainText, 0);
            cipher.DoFinal(plainText, len);

            return plainText;
        }

        #endregion
    }
}
