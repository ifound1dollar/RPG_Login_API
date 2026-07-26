namespace RPG_Login_API.Services.Interfaces
{
    public interface ILoginService
    {
        public Task<(int, object?)> LoginFromRefreshAsync(string refreshTokenString);
        public Task<(int, object?)> LoginAsync(string username, string password);
        public Task<(int, object?)> SubmitMfaCodeForLoginAsync(string username, string mfaCode);
        public Task<(int, object?)> LogoutAsync(string username);
    }
}
