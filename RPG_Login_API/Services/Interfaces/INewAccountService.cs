namespace RPG_Login_API.Services.Interfaces
{
    public interface INewAccountService
    {
        public Task<(int, object?)> RegisterAsync(string username, string email, string password);
        public Task<(int, object?)> ResendEmailVerificationCodeAsync(string username);
        public Task<(int, object?)> VerifyEmailForNewAccountAsync(string username, string confirmationCode);
    }
}
