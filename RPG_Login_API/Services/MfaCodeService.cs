using MailKit.Search;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
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

        private readonly IDatabaseService _databaseService;
        private readonly IOptions<MfaServiceSettings> _settings;
        private readonly ILogger _logger;

        public MfaCodeService(IDatabaseService databaseService, IOptions<MfaServiceSettings> settings, ILogger<MfaCodeService> logger)
        {
            _databaseService = databaseService;
            _settings = settings;
            _logger = logger;
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

        public bool ValidateRecoveryKey(UserAccountModel userAccount, string recoveryKey)
        {
            // Remove any whitespace from user-submitted recovery key. Recovery key will otherwise already be in hex form.
            string trimmedKey = recoveryKey.Replace(" ", "");

            // Retrieve hashed key from database and compare, then return whether they match.
            string hashedKey = userAccount.MfaRecoveryKeyHash;
            bool isValid = HashUtility.CompareMfaRecoveryKeyToHash(recoveryKey, hashedKey);

            return isValid;
        }

        public async Task<MfaSetupResponseModel?> GenerateNewMfaKeyForUser(UserAccountModel userAccount)
        {
            // Generate MFA key.
            byte[] mfaKey = KeyGeneration.GenerateRandomKey();
            string base32Key = Base32Encoding.ToString(mfaKey);

            // Generate an OTP URI, used by authenticator apps.
            string issuer = Uri.EscapeDataString(_settings.Value.Issuer);
            string user = Uri.EscapeDataString(userAccount.Username);
            string otpUri =
                $"""
                otpauth://totp/{issuer}:{user}?secret={base32Key}&issuer={issuer}&digits=6&period=30
                """;

            // Generate QR code from the URI above.
            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(otpUri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            byte[] qrCodeBytes = qrCode.GetGraphic(16);
            string qrCodeBase64 = Convert.ToBase64String(qrCodeBytes);

            // Encrypt base32 MFA key and write to pending MFA key field in database.
            userAccount.PendingMfaKey = EncryptMfaKey(base32Key);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // Return QR code in model as base64 string (ensure to set http json attributes)
            var response = new MfaSetupResponseModel
            {
                QrCodeBase64 = qrCodeBase64
            };
            return response;
        }

        public async Task<MfaRecoveryKeyResponseModel?> MovePendingMfaToActive(UserAccountModel userAccount)
        {
            // Verify that pending key is not empty (in case this method was called erroneously by a logged-in user).
            if (string.IsNullOrEmpty(userAccount.PendingMfaKey))
            {
                return null;
            }

            // If pending key exists, directly replace active key with pending key and clear pending.
            userAccount.ActiveMfaKey = userAccount.PendingMfaKey;
            userAccount.PendingMfaKey = string.Empty;

            // Generate recovery key for this user.
            byte[] randomBytes = new byte[8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            string recoveryKey = Convert.ToHexString(randomBytes).ToUpperInvariant();

            // Hash and salt new recovery key, then write it to the database.
            string hashedKey = HashUtility.GenerateNewMfaRecoveryKeyHash(recoveryKey);
            userAccount.MfaRecoveryKeyHash = hashedKey;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // Finally, return the raw (hex) key to the user so they can save it.
            return new MfaRecoveryKeyResponseModel
            {
                RecoveryKey = recoveryKey
            };
        }



        #region Private: Utility

        private string GenerateMfaRecoveryKey()
        {
            return string.Empty;
        }

        private string EncryptMfaKey(string rawKey)
        {
            // Encrypting with AES-GCM. 256-bit key. 12-byte nonce.

            // Convert string to byte[].
            byte[] rawKeyBytes = Encoding.UTF8.GetBytes(rawKey);

            // Create nonce and convert string encryption key to byte[].
            byte[] nonce = new byte[12];
            new SecureRandom().NextBytes(nonce);
            byte[] key = Encoding.UTF8.GetBytes(_settings.Value.SymmetricKey);

            // Generate and initialize cipher with encryption parameters.
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, nonce);
            cipher.Init(true, parameters);

            // Actually perform encryption.
            byte[] cipherText = new byte[cipher.GetOutputSize(rawKeyBytes.Length)];
            int len = cipher.ProcessBytes(rawKeyBytes, 0, rawKeyBytes.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            // Convert output byte[] back to string and return.
            return Encoding.UTF8.GetString(cipherText);
        }

        private byte[] DecryptMfaKey(string encryptedKey)
        {
            // Decrypting with AES-GCM. 256-bit key. 12-byte nonce.

            // Convert input string to byte[].
            byte[] encryptedKeyBytes = Encoding.UTF8.GetBytes(encryptedKey);

            // Create nonce and convert string encryption key to byte[].
            byte[] nonce = new byte[12];
            new SecureRandom().NextBytes(nonce);
            byte[] key = Encoding.UTF8.GetBytes(_settings.Value.SymmetricKey);

            // Generate and initialize cipher with decryption parameters.
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, nonce);
            cipher.Init(false, parameters);

            // Actually perform decryption.
            byte[] plainText = new byte[cipher.GetOutputSize(encryptedKeyBytes.Length)];
            int len = cipher.ProcessBytes(encryptedKeyBytes, 0, encryptedKeyBytes.Length, plainText, 0);
            cipher.DoFinal(plainText, len);

            return plainText;
        }

        #endregion
    }
}
