using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;

namespace RPG_Login_API.Services.Interfaces
{
    public interface IMfaCodeService
    {
        public bool ValidateMfaCode(UserAccountModel userAccount, string mfaCode, bool isForActive);
        public bool ValidateRecoveryCode(UserAccountModel userAccount, string recoveryKey);

        public Task<MfaSetupResponseModel?> GenerateNewMfaKeyForUser(UserAccountModel userAccount);

        public Task<MfaRecoveryCodeResponseModel?> MovePendingMfaToActive(UserAccountModel userAccount);
    }
}
