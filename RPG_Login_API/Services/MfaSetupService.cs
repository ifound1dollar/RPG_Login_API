using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;

namespace RPG_Login_API.Services
{
    public class MfaSetupService : IMfaSetupService
    {
        private readonly IDatabaseService _databaseService;
        private readonly IMfaCodeService _mfaCodeService;
        private readonly IUtilityService _utilityService;
        private readonly ILogger _logger;

        public MfaSetupService(IDatabaseService databaseService, IMfaCodeService mfaCodeService, IUtilityService utilityService,
            ILogger<MfaSetupService> logger)
        {
            _databaseService = databaseService;
            _mfaCodeService = mfaCodeService;
            _utilityService = utilityService;

            _logger = logger;
        }



        public async Task<(int, object?)> BeginMfaSetup(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountAsync(username, "begin MFA setup");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "begin MFA setup")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // Generate new encrypted MFA secret key and update document with this pending key.
            userAccount.PendingMfaKey = _mfaCodeService.GenerateMfaSecretKeyEncryptedBase64();
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // Finally, generate an OTP URI for this user, then return an MfaSetupResponseModel with the URI.
            string otpUri = _mfaCodeService.GenerateOtpUriForUser(userAccount.Username, userAccount.PendingMfaKey);
            var response = new MfaSetupResponseModel { OtpAuthLink = otpUri };

            _logger.LogInformation($"begin MFA setup successful (username: {username})");
            return (200, response);
        }

        public async Task<(int, object?)> VerifyMfaSetupAsync(string username, string mfaCode)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountAsync(username, "verify MFA setup");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "verify MFA setup")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // Validate submitted code against the pending key (verifying setup checks pending only).
            if (!_mfaCodeService.ValidateMfaCode(userAccount, mfaCode, isForActive: false))
            {
                return (401, "Incorrect multi-factor authentication code.");
            }

            // Verify that pending key is not empty (in case this method was called erroneously by a logged-in user).
            if (!EnsurePendingMfaKeyExists(userAccount))
            {
                return (500, "An unexpected error occurred during MFA setup verification, please try again.");
            }

            // Else request is valid, so generate full access response with recovery code.
            var accessResponse = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: false);    // verify MFA = full login
            var response = new MfaRecoveryCodeResponseModel(accessResponse)
            {
                RecoveryCode = _mfaCodeService.GenerateMfaRecoveryCode()    // Generate new here, rest of response is passed into constructor.
            };

            // Move pending MFA key to active, then update database with new MFA recovery code hash and refresh token hash.
            userAccount.ActiveMfaKey = userAccount.PendingMfaKey;
            userAccount.PendingMfaKey = string.Empty;
            userAccount.MfaRecoveryCodeHash = HashUtility.GenerateNewMfaRecoveryCodeHash(response.RecoveryCode);
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"verify MFA setup successful (username: {username})");
            return (200, response);
        }

        public async Task<(int, object?)> RecoverMfaAsync(string username, string recoveryKey)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountAsync(username, "recover MFA configuration");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "recover MFA configuration")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // Compare submitted recovery key against key in database.
            if (!_mfaCodeService.ValidateRecoveryCode(userAccount, recoveryKey))
            {
                return (401, "Incorrect recovery key.");
            }

            // Else correct key, so generate new encrypted MFA secret key and update document with this pending key.
            userAccount.PendingMfaKey = _mfaCodeService.GenerateMfaSecretKeyEncryptedBase64();
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // Finally, generate an OTP URI for this user, then return an MfaSetupResponseModel with the URI.
            string otpUri = _mfaCodeService.GenerateOtpUriForUser(userAccount.Username, userAccount.PendingMfaKey);
            var response = new MfaSetupResponseModel { OtpAuthLink = otpUri };

            _logger.LogInformation($"recover MFA configuration successful (username: {username})");
            return (200, response);
        }

        public async Task<(int, object?)> RegenerateMfaRecoveryCodeAsync(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountAsync(username, "regenerate MFA recovery code");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "regenerate MFA recovery code")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // Generate full login response with newly-generated recovery code.
            var loginResponse = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: false);
            var response = new MfaRecoveryCodeResponseModel(loginResponse)
            {
                RecoveryCode = _mfaCodeService.GenerateMfaRecoveryCode()    // Generate new here, rest of response is passed into constructor.
            };

            // Update database with new MFA recovery code hash and refresh token hash.
            userAccount.MfaRecoveryCodeHash = HashUtility.GenerateNewMfaRecoveryCodeHash(response.RecoveryCode);
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"regenerate MFA recovery code successful (username: {username})");
            return (200, response);
        }

        public async Task<(int, object?)> RequestMfaHardResetAsync(string username)
        {
            // TODO: IMPLEMENT REQUEST MFA HARD RESET
            throw new NotImplementedException();
        }

        public async Task<(int, object?)> InitiateMfaHardResetAsync(string username, string confirmationCode)
        {
            // TODO: IMPLEMENT INITIATE MFA HARD RESET
            throw new NotImplementedException();
        }

        public async Task CancelMfaHardResetAsync(string username)
        {
            // TODO: IMPLEMENT CANCEL MFA HARD RESET
            throw new NotImplementedException();
        }



        #region Private: Local utility methods

        private bool EnsurePendingMfaKeyExists(UserAccountModel userAccount)
        {
            if (string.IsNullOrEmpty(userAccount.PendingMfaKey))
            {
                _logger.LogInformation($"verify MFA setup failed: tried to verify a pending MFA code that does not exist (username: {userAccount.Username})");
                return false;
            }
            return true;
        }

        #endregion
    }
}
