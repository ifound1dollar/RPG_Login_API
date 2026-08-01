using RPG_Login_API.Data;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;

namespace RPG_Login_API.Services
{
    public class ResetPasswordService : IResetPasswordService
    {
        private readonly IDatabaseService _databaseService;
        private readonly IEmailService _emailService;
        private readonly ITokenService _tokenService;
        private readonly IUtilityService _utilityService;
        private readonly ILogger _logger;

        public ResetPasswordService(IDatabaseService databaseService, IEmailService emailService, ITokenService tokenService,
            IUtilityService utilityService, ILogger<ResetPasswordService> logger)
        {
            _databaseService = databaseService;
            _emailService = emailService;
            _tokenService = tokenService;
            _utilityService = utilityService;

            _logger = logger;
        }



        public async Task ForgotPasswordAsync(string usernameOrEmail)
        {
            // NOTE: We do not return a status code for security reasons (codes can be sent anonymously, and we cannot
            //  provide information to an unauthorized user whether an account exists and was sent a code successfully).

            usernameOrEmail = usernameOrEmail.Trim();

            // FIND USER | Try to find user in database. Return null if we cannot find by username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(usernameOrEmail);
                if (userAccount == null)
                {
                    _logger.LogInformation($"forgot password attempt failed: user not found in database (username/email: {usernameOrEmail})");
                    return;
                }
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "forgot password attempt")))
            {
                return;
            }

            // TRY TO SEND CODE TO EMAIL | Do not await because sending code can take a while.
            _ = _emailService.SendCodeToEmailAsync(userAccount.PrimaryEmail, ConfirmationCodeData.CodeContext.PasswordReset);
        }

        public async Task<(int, object?)> InitiateResetPasswordAsync(string usernameOrEmail, string confirmationCode)
        {
            // NOTE: We return a generic error message because this endpoint allows anonymous calling. We cannot allow
            //  unauthorized users to look up whether an account username/email exists by returning specific information.

            usernameOrEmail = usernameOrEmail.Trim();

            // FIND USER | Try to find user in database. We check for valid username/email in controller, so should always find an account.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(usernameOrEmail);
                if (userAccount == null)
                {
                    _logger.LogInformation($"initiate reset password failed: user not found in database (username/email: {usernameOrEmail})");
                    return (401, "Invalid or expired confirmation code.");
                }
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "initiate reset password")))
            {
                return (401, "Invalid or expired confirmation code.");
            }

            // VALIDATE USER-SUBMITTED CONFIRMATION CODE | Call email code service method to validate, which logs internally.
            if (!_emailService.ValidateSubmittedCode(userAccount.PrimaryEmail, confirmationCode, ConfirmationCodeData.CodeContext.PasswordReset))
            {
                return (401, "Invalid or expired confirmation code.");
            }

            // SUCCESS: GENERATE RESPONSE | On successful request, consume confirmation code and generate short-duration reset token.
            var response = new PasswordResetTokenResponseModel()
            {
                Username = userAccount.Username,
                PasswordResetToken = _tokenService.GenerateAccessToken(userAccount.Username, TokenService.Roles.ResetPassword, durationMinutes: 5)
            };

            _logger.LogInformation($"initiate reset password successful (username: {userAccount.Username})");
            return (200, response);
        }

        public async Task<(int, object?)> SubmitResetPasswordAsync(string username, string newPassword)
        {
            newPassword = newPassword.Trim();

            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "submit reset password");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "submit reset password")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // Ensure submitted password is not found in list of 100,000 most-used-passwords.
            if (_utilityService.IsPasswordInsecure(newPassword, username, "submit reset password"))
            {
                return (422, "Password does not meet minimum security standards, please submit a more secure password.");
            }

            // VERIFY NEW PASSWORD DOES NOT MATCH PREVIOUS
            if (!EnsureNewPasswordIsDifferent(newPassword, userAccount))
            {
                return (409, "New password cannot be the same as old password.");
            }

            // SUCCESS: GENERATE NEW PASSWORD HASH AND UPDATE DOCUMENT | Update various fields in account document now that password is reset.
            userAccount.PasswordHash = HashUtility.GenerateNewPasswordHash(newPassword);
            userAccount.DoesPasswordNeedReset = false;                  // Always reset to false regardless of whether reset was forced.
            userAccount.IsEmailVerified = true;                         // Reset requires email anyway, so implicitly verify email.
            userAccount.LastPasswordChangedTime = DateTime.UtcNow;
            userAccount.RefreshTokenHash = string.Empty;                // Reset just in case anyone was logged in at time of change.
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // NOTIFY ACCOUNT EMAIL OF PASSWORD CHANGE | Do not await.
            _ = _emailService.NotifyUserOnAccountSettingsChanged(userAccount.PrimaryEmail, userAccount.Username,
                IEmailService.NotificationContext.PasswordChanged);

            _logger.LogInformation($"submit reset password successful (username: {username})");
            return (200, "Reset password successful, please log in again.");
        }



        #region Private: Local utility methods

        private bool EnsureNewPasswordIsDifferent(string newPassword, UserAccountModel userAccount)
        {
            if (HashUtility.ComparePasswordToHash(newPassword, userAccount.PasswordHash))
            {
                _logger.LogInformation($"password reset failed: new password is the same as existing password (username: {userAccount.Username})");
                return false;
            }
            return true;
        }

        #endregion
    }
}
