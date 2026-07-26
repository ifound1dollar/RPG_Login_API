namespace RPG_Login_API.Services.Interfaces
{
    public interface IMfaSetupService
    {
        public Task<(int, object?)> SetupMfaAsync(string username);
        public Task<(int, object?)> VerifyMfaSetupAsync(string username, string mfaCode);
        public Task<(int, object?)> RecoverMfaAsync(string username, string mfaRecoveryCode);
        public Task<(int, object?)> RegenerateMfaRecoveryCodeAsync(string username);

        public Task<(int, object?)> RequestMfaHardResetAsync(string username);
        public Task<(int, object?)> InitiateMfaHardResetAsync(string username, string confirmationCode);
        public Task CancelMfaHardResetAsync (string username);
    }
}
