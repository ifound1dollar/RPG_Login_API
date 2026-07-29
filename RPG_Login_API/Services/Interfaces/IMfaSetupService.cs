namespace RPG_Login_API.Services.Interfaces
{
    public interface IMfaSetupService
    {
        public Task<(int, object?)> BeginMfaSetup(string username);
        public Task<(int, object?)> VerifyMfaSetupAsync(string username, string mfaCode);
        public Task<(int, object?)> RecoverMfaAsync(string username, string mfaRecoveryCode);
        public Task<(int, object?)> RegenerateMfaRecoveryCodeAsync(string username);

        public Task<(int, object?)> RequestMfaHardResetAsync(string username, bool isForPrimaryEmail);
        public Task<(int, object?)> ResendMfaHardResetCodeAsync(string username, bool isForPrimaryEmail);
        public Task<(int, object?)> InitiateMfaHardResetAsync(string username, bool isForPrimaryEmail, string confirmationCode);
        public Task<(int, object?)> CancelMfaHardResetAsync(string username, string cancelCode);
    }
}
