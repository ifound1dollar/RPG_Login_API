using RPG_Login_API.Data;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.Responses;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;
using System.Security.Cryptography;

namespace RPG_Login_API.Services
{
    public class MfaService : IMfaService
    {
        private readonly IDatabaseService _databaseService;
        private readonly IMfaCodeService _mfaCodeService;
        private readonly IEmailService _emailService;
        private readonly IUtilityService _utilityService;
        private readonly ILogger _logger;

        public MfaService(IDatabaseService databaseService, IMfaCodeService mfaCodeService, IEmailService emailService,
            IUtilityService utilityService, ILogger<MfaService> logger)
        {
            _databaseService = databaseService;
            _mfaCodeService = mfaCodeService;
            _emailService = emailService;
            _utilityService = utilityService;

            _logger = logger;
        }



        public async Task<(int, object?)> BeginMfaSetup(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "begin MFA setup");
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
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "verify MFA setup");
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
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "recover MFA configuration");
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
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "regenerate MFA recovery code");
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
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "request MFA hard reset");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "request MFA hard reset")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // SEND REQUEST EMAIL TO PRIMARY EMAIL | Always send to primary email.
            (int code, string message) = await _emailService.SendMfaHardResetRequestToEmailAsync(userAccount.PrimaryEmail, isPrimaryEmail: true,
                ConfirmationCodeData.CodeContext.MfaHardReset);

            // ALSO TRY TO SEND TO SECONDARY EMAIL | Try to send to secondary, but do not return any information on it.
            if (!string.IsNullOrEmpty(userAccount.SecondaryEmail))
            {
                _ = _emailService.SendMfaHardResetRequestToEmailAsync(userAccount.SecondaryEmail, isPrimaryEmail: false,
                    ConfirmationCodeData.CodeContext.MfaHardReset);
            }

            // We actually utilize the 'send code' response because this endpoint is only accessible to validated users (partial login).
            _logger.LogInformation($"request MFA hard reset successful (username: {username}");
            return (code, message);
        }

        public async Task<(int, object?)> InitiateMfaHardResetAsync(string username, string confirmationCode)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "initiate MFA hard reset");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT ALREADY LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "initiate MFA hard reset")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // COMPARE CODE AGAINST EITHER PRIMARY OR SECONDARY | Both will exist if valid, but each with a different code.
            bool isPrimary = true;
            if (!_emailService.ValidateSubmittedCode(userAccount.PrimaryEmail, confirmationCode, ConfirmationCodeData.CodeContext.MfaHardReset))
            {
                // Try secondary. Checks if secondary email is empty within method.
                if (!_emailService.ValidateSubmittedCode(userAccount.SecondaryEmail, confirmationCode, ConfirmationCodeData.CodeContext.MfaHardReset))
                {
                    return (401, "Invalid or expired confirmation code.");
                }
                isPrimary = false;
            }

            // ENSURE THERE IS AN EXISTING MFA SETUP | Do not allow hard reset of a nonexistent MFA setup.
            if (!EnsureActiveMfaSetupExists(userAccount))
            {
                return (422, "Cannot reset MFA configuration which does not exist.");
            }

            // SUCCESS: LOCK ACCOUNT AND SET DATABASE FIELDS
            userAccount.RefreshTokenHash = string.Empty;
            userAccount.MfaHardResetInitiatedTime = DateTime.UtcNow;
            userAccount.MfaHardResetLockedUntilTime = (isPrimary) ? DateTime.UtcNow.AddDays(7) : DateTime.UtcNow.AddHours(24);
            userAccount.MfaHardResetCancelCode = GenerateMfaHardResetCancelCode();
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // SEND EMAIL WITH CANCEL LINK TO BOTH PRIMARY AND SECONDARY EMAIL | Do not await.
            _ = _emailService.SendMfaHardResetInitiatedToEmailAsync(userAccount.PrimaryEmail, username, userAccount.MfaHardResetCancelCode, userAccount.MfaHardResetLockedUntilTime);
            if (!string.IsNullOrEmpty(userAccount.SecondaryEmail))
            {
                _ = _emailService.SendMfaHardResetInitiatedToEmailAsync(userAccount.SecondaryEmail, username, userAccount.MfaHardResetCancelCode,
                    userAccount.MfaHardResetLockedUntilTime);
            }

            _logger.LogInformation($"initiate MFA hard reset successful (username: {username}, locked until: {userAccount.MfaHardResetLockedUntilTime.ToString()})");
            return (200, "Successfully initiated MFA hard reset, please check account email.");
        }

        public async Task<(int, object?)> CancelMfaHardResetAsync(string username, string cancelCode)
        {
            // NOTE: This allows anonymous access by email. Thus, do not provide any information unless code is correct.

            // FIND ACCOUNT | Try to retrieve user account from username in cancellation URL query parameter.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "cancel MFA hard reset");
            if (userAccount == null)
            {
                return (401, "Cancellation code is invalid or no longer in effect.");
            }

            // COMPARE CANCEL CODES, IF EXISTS IN DATABASE | Even if after locked until time, allow cancellation if field is set.
            //  Note that the cancel code field will no longer be set once the account's MFA setup is actually reset on login.
            if (!CompareSubmittedMfaHardResetCancelCode(userAccount, cancelCode))
            {
                return (401, "Cancellation code is invalid or no longer in effect.");
            }

            // SUCCESS: UNLOCK ACCOUNT AND ENFORCE PASSWORD CHANGE
            userAccount.MfaHardResetInitiatedTime = DateTime.MinValue;
            userAccount.MfaHardResetLockedUntilTime = DateTime.MinValue;
            userAccount.MfaHardResetCancelCode = string.Empty;
            userAccount.DoesPasswordNeedReset = true;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // NOTIFY BOTH EMAILS OF SUCCESSFUL CANCEL
            _ = _emailService.SendMfaHardResetCancelledNotifToEmailAsync(userAccount.PrimaryEmail);
            if (!string.IsNullOrEmpty(userAccount.SecondaryEmail))
            {
                _ = _emailService.SendMfaHardResetCancelledNotifToEmailAsync(userAccount.SecondaryEmail);
            }

            _logger.LogInformation($"cancel MFA hard reset successful (username: {userAccount.Username})");
            return (200, "Successfully canceled the pending MFA hard reset. Please re-login and reset your password.");
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

        private bool EnsureActiveMfaSetupExists(UserAccountModel userAccount)
        {
            if (string.IsNullOrEmpty(userAccount.ActiveMfaKey))
            {
                _logger.LogInformation($"initiate MFA hard reset failed: no current active MFA setup exists for this account (username: {userAccount.Username})");
                return false;
            }
            return true;
        }

        private string GetValidTargetEmailForMfaHardResetRequest(UserAccountModel userAccount, bool isForPrimaryEmail)
        {
            if (isForPrimaryEmail)
            {
                return userAccount.PrimaryEmail;
            }
            else
            {
                if (string.IsNullOrEmpty(userAccount.SecondaryEmail))
                {
                    _logger.LogInformation($"request MFA hard reset failed: tried to send request email to secondary email which does not exist (username: {userAccount.Username})");
                    return string.Empty;
                }
                return userAccount.SecondaryEmail;
            }
        }

        private static string GenerateMfaHardResetCancelCode(int length = 32)
        {
            string alphanumericChars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
            if (length < 0) throw new ArgumentException("Length must be greater than or equal to 0");

            char[] result = new char[length];
            for (int i = 0; i < length; i++)
            {
                int index = RandomNumberGenerator.GetInt32(alphanumericChars.Length);
                result[i] = alphanumericChars[index];
            }

            return new string(result);
        }

        private bool CompareSubmittedMfaHardResetCancelCode(UserAccountModel userAccount, string cancelCode)
        {
            if (string.IsNullOrEmpty(userAccount.MfaHardResetCancelCode))
            {
                _logger.LogInformation($"cancel MFA hard reset failed: no cancel code exists for account in database (username: {userAccount.Username}");
                return false;
            }

            if (!string.Equals(cancelCode, userAccount.MfaHardResetCancelCode))
            {
                _logger.LogInformation($"cancel MFA hard reset failed: user-submitted cancel code does not match cancel code in database (username: {userAccount.Username}, submitted code: {cancelCode}");
                return false;
            }

            return true;
        }

        #endregion
    }
}
