namespace RPG_Login_API.Services.Interfaces
{
    public interface IRecoveryService
    {
        public Task ForgotPasswordAsync(string usernameOrEmail);
        public Task<(int, object?)> InitiateResetPasswordAsync(string usernameOrEmail, string confirmationCode);
        public Task<(int, object?)> SubmitResetPasswordAsync(string username, string newPassword);
    }
}
