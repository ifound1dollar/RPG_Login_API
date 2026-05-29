using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;

namespace RPG_Login_API.Services.Interfaces
{
    public interface IMfaCodeService
    {
        public bool ValidateMfaCode(UserAccountModel userAccount, string mfaCode, bool isForActive);
        public bool ValidateRecoveryCode(UserAccountModel userAccount, string recoveryKey);

        public string GenerateMfaSecretKeyEncryptedBase64();
        public string GenerateMfaRecoveryCode();
        public string GenerateOtpUriForUser(string username, string encryptedSecretKeyBase64);
    }
}
