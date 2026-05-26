using RPG_Login_API.Models.UserResponses;

namespace RPG_Login_API.Services.Interfaces
{
    /// <summary>
    /// This interface is used by the LoginApiService to support Dependency Injection in a way that allows
    ///  for mocking during testing. Declares all public methods necessary for service functionality.
    /// </summary>
    public interface ILoginApiService
    {
        public Task<(int, string, LoginResponseModel?)> UserLoginFromRefreshAsync(string refreshTokenString);
        public Task<(int, string, LoginResponseModel?)> UserLoginAsync(string username, string password);
        public Task<(int, string, LoginResponseModel?)> UserRegisterAsync(string username, string email, string password);
        public Task<(int, string)> UserLogoutAsync(string username);

        public Task<(int, string)> UserResendEmailVerificationCode(string username, bool isForNewAccount);
        public Task<(int, string, LoginResponseModel?)> UserVerifyAccountEmailAsync(string username, string confirmationCode, bool isForNewAccount);

        public Task UserForgotPasswordAsync(string usernameOrEmail);
        public Task<(int, string, PasswordResetTokenResponseModel?)> UserInitiatePasswordResetAsync(string usernameOrEmail, string confirmationCode);
        public Task<(int, string)> UserSubmitNewPasswordAsync(string username, string newPassword);
        public Task<(int, string, LoginResponseModel?)> UserChangeUsernameAsync(string existingUsername, string newUsername);
        public Task<(int, string)> UserRequestEmailChangeAsync(string username);
        public Task<(int, string, EmailChangeTokenResponseModel?)> UserInitiateEmailChangeAsync(string username, string confirmationCode);
        public Task<(int, string)> UserSubmitNewEmailAsync(string username, string newEmail);

        public Task<(int, string)> UserPingInLauncherAsync(string username);
        public Task<(int, string)> UserNotifyLauncherExitAsync(string username);

    }
}
