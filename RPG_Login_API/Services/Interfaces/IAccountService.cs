namespace RPG_Login_API.Services.Interfaces
{
    public interface IAccountService
    {
        public Task<(int, object?)> ChangeUsernameAsync(string existingUsername, string currentPassword, string newUsername);
        public Task<(int, object?)> ChangePasswordAsync(string username, string currentPassword, string newPassword);

        public Task<(int, object?)> SubmitChangedEmailAsync(string username, string currentPassword, string newEmail);
        public Task<(int, object?)> ResendChangedEmailVerificationCodeAsync(string username);
        public Task<(int, object?)> VerifyChangedEmailAsync(string username, string confirmationCode);

        public Task<(int, object?)> SubmitSecondaryEmailAsync(string username, string currentPassword, string secondaryEmail);
        public Task<(int, object?)> ResendSecondaryEmailVerificationCodeAsync(string username);
        public Task<(int, object?)> VerifySecondaryEmailAsync(string username, string confirmationCode);
    }
}
