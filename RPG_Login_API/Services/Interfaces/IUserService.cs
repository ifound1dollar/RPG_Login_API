using RPG_Login_API.Models.UserResponses;

namespace RPG_Login_API.Services.Interfaces
{
    /// <summary>
    /// This interface is used by the LoginApiService to support Dependency Injection in a way that allows
    ///  for mocking during testing. Declares all public methods necessary for service functionality.
    /// </summary>
    public interface IUserService
    {
        public Task<(int, object?)> UserLoginFromRefreshAsync(string refreshTokenString);
        public Task<(int, object?)> UserLoginAsync(string username, string password);
        public Task<(int, object?)> UserSubmitMfaCodeForLoginAsync(string username, string mfaCode);
        public Task<(int, object?)> UserRegisterAsync(string username, string email, string password);
        public Task<(int, object?)> UserLogoutAsync(string username);

        public Task<(int, object?)> UserResendEmailVerificationCode(string username, bool isForNewAccount);
        public Task<(int, object?)> UserVerifyAccountEmailAsync(string username, string confirmationCode, bool isForNewAccount);

        public Task UserForgotPasswordAsync(string usernameOrEmail);
        public Task<(int, object?)> UserInitiatePasswordResetAsync(string usernameOrEmail, string confirmationCode);
        public Task<(int, object?)> UserSubmitNewPasswordAsync(string username, string newPassword);
        public Task<(int, object?)> UserChangeUsernameAsync(string existingUsername, string newUsername);
        public Task<(int, object?)> UserRequestEmailChangeAsync(string username);
        public Task<(int, object?)> UserInitiateEmailChangeAsync(string username, string confirmationCode);
        public Task<(int, object?)> UserSubmitNewEmailAsync(string username, string newEmail);

        public Task<(int, object?)> UserSetupMfaAsync(string username);
        public Task<(int, object?)> UserVerifyMfaSetupAsync(string username, string mfaCode);
        public Task<(int, object?)> UserRecoverMfaAsync(string username, string recoveryKey);
        public Task<(int, object?)> UserRegenerateMfaRecoveryCodeAsync(string username);

        public Task<(int, object?)> UserPingInLauncherAsync(string username);
        public Task<(int, object?)> UserNotifyLauncherExitAsync(string username);

    }
}
