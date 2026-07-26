using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;

namespace RPG_Login_API.Services.Interfaces
{
    public interface IUtilityService
    {
        public Task<UserAccountModel?> TryRetrieveAccountAsync(string username, string context);
        public Task<bool> EnsureAccountIsNotLockedAsync(UserAccountModel userAccount, string context);
        public AccessResponseModel GenerateAccessResponse(UserAccountModel userAccount, bool isInitialLoginStep);
        public Task<bool> IsUsernameAvailableAsync(string username, string context);
        public Task<bool> IsEmailAvailableAsync(string email, string username, string context);

        public Task<bool> EnsureRefreshTokenIsValidAsync(string refreshToken, UserAccountModel userAccount);

        public bool IsUsernameProfane(string username, string context);
        public bool IsPasswordInsecure(string password, string username, string context);
        public bool ComparePasswordForAccount(string password, string compareToHash, string username, string context);
    }

    // FIND USER | Try to find user in database. Return null if we cannot find by username.
    

    //// ENSURE ACCOUNT IS NOT CURRENTLY LOCKED
    


}
