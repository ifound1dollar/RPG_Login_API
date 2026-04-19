using RPG_Login_API.Models.UserResponses;

namespace RPG_Login_API.Services.Interfaces
{
    /// <summary>
    /// This interface is used by the LoginApiService to support Dependency Injection in a way that allows
    ///  for mocking during testing. Declares all public methods necessary for service functionality.
    /// </summary>
    public interface ILoginApiService
    {
        public Task<LoginResponseModel?> UserLoginFromRefreshAsync(string refreshTokenString);
        public Task<LoginResponseModel?> UserLoginAsync(string username, string password);
        public Task<LoginResponseModel?> UserRegisterAsync(string username, string email, string password);
        public Task UserLogoutAsync(string username, string tokenGuid);
        public Task UserSendConfirmationCodeAsync(string usernameOrEmail);
        public Task<LoginResponseModel?> UserVerifyAccountEmailAsync(string username, string confirmationCode);
        public Task<PasswordResetTokenResponseModel?> UserRequestPasswordResetAsync(string usernameOrEmail, string confirmationCode);
        public Task<bool> UserResetPasswordAsync(string username, string tokenGuid, string newPassword);
        public Task<LoginResponseModel?> UserChangeUsernameAsync(string existingUsername, string newUsername);

        public Task<bool> CheckWhetherUserExistsAsync(string usernameOrEmail);
        public Task<bool> CheckIfUsernameAndEmailAvailableAsync(string username, string email);
        public Task<bool> CheckWhetherUserCanChangePasswordAsync(string usernameOrEmail);
        public Task<bool> CheckWhetherUserCanChangeUsernameAsync(string existingUsername);
    }
}
