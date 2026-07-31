using RPG_Login_API.Data;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;

namespace RPG_Login_API.Services
{
    public class AccountService : IAccountService
    {
        private readonly IDatabaseService _databaseService;
        private readonly IEmailService _emailService;
        private readonly IUtilityService _utilityService;
        private readonly ILogger _logger;

        public AccountService(IDatabaseService databaseService, IEmailService emailService, IUtilityService utilityService,
            ILogger<AccountService> logger)
        {
            _databaseService = databaseService;
            _emailService = emailService;
            _utilityService = utilityService;

            _logger = logger;
        }



        public async Task<(int, object?)> ChangeUsernameAsync(string existingUsername, string currentPassword, string newUsername)
        {
            newUsername = newUsername.Trim();

            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(existingUsername, "change username");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "change username")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // VALIDATE SUBMITTED PASSWORD | Only allow change if user entered their current password.
            if (!_utilityService.ComparePasswordForAccount(currentPassword, userAccount.PasswordHash, userAccount.Username, "change username"))
            {
                return (401, "Incorrect account password, please try again.");
            }

            // ENSURE NON-PROFANE USERNAME | Deny any particularly profane username using ProfanityDetector library.
            if (_utilityService.IsUsernameProfane(newUsername, "change username"))
            {
                return (422, "That username is not allowed, please try a different username.");
            }

            // VERIFY THAT USERNAME IS NOT ALREADY IN USE | Deny change if username is already in use by a legitimate account.
            if (!(await _utilityService.IsUsernameAvailableAsync(newUsername, "change username")))
            {
                return (409, "Username already in use, please try a different username.");
            }

            // ENSURE USER IS ALLOWED TO CHANGE USERNAME | Deny change if username was changed less than 30 days ago.
            if (!IsUserAllowedToChangeUsername(userAccount))
            {
                return (493, "Cannot change username within 30 days of previous change.");
            }

            // VERIFY THAT NEW USERNAME IS NOT SAME AS PREVIOUS
            if (!EnsureNewUsernameIsDifferent(newUsername, userAccount))
            {
                return (409, "New username cannot be the same as old username.");
            }

            // SUCCESS: RE-LOGIN USER | Now that account state has changed, re-login user to generate new tokens with new username.
            var response = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: false);
            response.Username = newUsername;        // Manually update username in response.

            // UPDATE DOCUMENT AND DATABASE | Update username and last username changed time in document, then update database.
            userAccount.Username = newUsername;
            userAccount.LastUsernameChangedTime = DateTime.UtcNow;
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(existingUsername, userAccount);     // Query by old username.

            // NOTIFY ACCOUNT EMAIL OF USERNAME CHANGE | Do not await.
            _ = _emailService.NotifyUserOnAccountSettingsChanged(userAccount.PrimaryEmail, IEmailService.NotificationContext.UsernameChanged);

            _logger.LogInformation($"change username successful (old username: {existingUsername} | new username: {newUsername})");
            return (200, response);
        }

        public async Task<(int, object?)> ChangePasswordAsync(string username, string currentPassword, string newPassword)
        {
            newPassword = newPassword.Trim();

            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "change password");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "change password")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // VALIDATE SUBMITTED PASSWORD | Only allow change if user entered their current password.
            if (!_utilityService.ComparePasswordForAccount(currentPassword, userAccount.PasswordHash, userAccount.Username, "change password"))
            {
                return (401, "Incorrect (current) account password, please try again.");
            }

            // Ensure submitted password is not found in list of 100,000 most-used-passwords.
            if (_utilityService.IsPasswordInsecure(newPassword, username, "change password"))
            {
                return (422, "Password does not meet minimum security standards, please submit a more secure password.");
            }

            // VERIFY NEW PASSWORD DOES NOT MATCH PREVIOUS
            if (!EnsureNewPasswordIsDifferent(newPassword, userAccount))
            {
                return (409, "New password cannot be the same as old password.");
            }

            // SUCCESS: RE-LOGIN USER | Now that account state has changed, re-login user to generate new tokens with new username.
            var response = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: false);

            // GENERATE NEW PASSWORD HASH AND UPDATE DOCUMENT | Update various fields in account document now that password is reset.
            userAccount.PasswordHash = HashUtility.GenerateNewPasswordHash(newPassword);
            userAccount.DoesPasswordNeedReset = false;                  // Always reset to false regardless of whether reset was forced.
            userAccount.IsEmailVerified = true;                         // Reset requires email anyway, so implicitly verify email.
            userAccount.LastPasswordChangedTime = DateTime.UtcNow;
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // NOTIFY ACCOUNT EMAIL OF PASSWORD CHANGE | Do not await.
            _ = _emailService.NotifyUserOnAccountSettingsChanged(userAccount.PrimaryEmail, IEmailService.NotificationContext.PasswordChanged);

            _logger.LogInformation($"change password successful (username: {username})");
            return (200, response);
        }

        public async Task<(int, object?)> SubmitChangedEmailAsync(string username, string currentPassword, string newEmail)
        {
            newEmail = newEmail.Trim();

            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "submit changed email");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "submit changed email")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // VALIDATE SUBMITTED PASSWORD | Only allow change if user entered their current password.
            if (!_utilityService.ComparePasswordForAccount(currentPassword, userAccount.PasswordHash, userAccount.Username, "submit changed email"))
            {
                return (401, "Incorrect account password, please try again.");
            }

            // VERIFY NEW EMAIL IS NOT THE SAME AS PREVIOUS
            if (!EnsureNewEmailIsDifferent(newEmail, userAccount, "submit changed email"))
            {
                return (409, "New email cannot be the same as old email.");
            }

            // VERIFY THAT EMAIL IS NOT ALREADY IN USE | Deny change with GENERIC ERROR MESSAGE if email is in use by another account.
            if (!(await _utilityService.IsEmailAvailableAsync(newEmail, username, "submit changed email")))
            {
                return (500, "An unexpected error occured during new email submission, please try again.");     // GENERIC FOR SECURITY
            }

            // SUCCESS: ADD PENDING NEW EMAIL TO DOCUMENT | Update pending new email field, but do NOT set last changed time or logout yet.
            userAccount.PendingNewPrimaryEmail = newEmail;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // SEND CONFIRMATION CODE TO NEW EMAIL | Do not await, because sending email can take a while.
            _ = _emailService.SendCodeToEmailAsync(newEmail, ConfirmationCodeData.CodeContext.PrimaryEmailVerification);

            _logger.LogInformation($"submit changed email successful (username: {username} | current email: {userAccount.PrimaryEmail} | new email: {newEmail})");
            return (200, "Submit new email for change successful.");
        }

        public async Task<(int, object?)> ResendChangedEmailVerificationCodeAsync(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "resend changed email verification code");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "resend changed email verification code")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // RESEND EMAIL VERIFICATION CODE | Generate and send a new code, target email depending on context.
            (int code, string message) = await _emailService.SendCodeToEmailAsync(userAccount.PendingNewPrimaryEmail,
                ConfirmationCodeData.CodeContext.PrimaryEmailVerification);

            // We actually utilize the 'send code' response because this endpoint is only accessible to validated users.
            return (code, message);
        }

        public async Task<(int, object?)> VerifyChangedEmailAsync(string username, string confirmationCode)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "verify changed email");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "verify changed email")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // VALIDATE USER-SUBMITTED CONFIRMATION CODE | Call email code service method to validate, which logs internally.
            if (!_emailService.ValidateSubmittedCode(userAccount.PendingNewPrimaryEmail, confirmationCode, ConfirmationCodeData.CodeContext.PrimaryEmailVerification))
            {
                return (401, "Invalid or expired confirmation code.");
            }

            // DOUBLE-CHECK EMAIL IS UNIQUE | Ensure new email is still unique before updating database.
            if (!(await _utilityService.IsEmailAvailableAsync(userAccount.PendingNewPrimaryEmail, username, "verify changed email")))
            {
                // Clear pending field (is not available).
                userAccount.PendingNewPrimaryEmail = string.Empty;
                await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

                return (500, "An unexpected error occured during email change verification, please try again.");    // GENERIC FOR SECURITY
            }

            // SUCCESS: GENERATE ACCESS RESPONSE | On successful primary email manual change, re-generate both refresh and access token (like login).
            var response = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: false);
            response.PrimaryEmail = userAccount.PendingNewPrimaryEmail;                         // Manually update primary email in response.

            // NOTIFY OLD EMAIL OF CHANGE | This must be done before overwriting active (old) primary email.
            _ = _emailService.NotifyUserOnAccountSettingsChanged(userAccount.PrimaryEmail, IEmailService.NotificationContext.PrimaryEmailChanged);

            // UPDATE DATABASE | After token generation, update account document.
            userAccount.PrimaryEmail = userAccount.PendingNewPrimaryEmail;
            userAccount.PendingNewPrimaryEmail = string.Empty;      // Clear pending new email upon verification; verified email is now main email.
            userAccount.LastEmailChangedTime = DateTime.UtcNow;     // Consider verification to be 'changed time'.
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // NOTIFY NEW EMAIL OF PRIMARY EMAIL CHANGE | Do not await.
            _ = _emailService.NotifyUserOnAccountSettingsChanged(userAccount.PrimaryEmail, IEmailService.NotificationContext.PrimaryEmailChanged);

            _logger.LogInformation($"verify changed email successful (username: {username}, verified email: {userAccount.PrimaryEmail})");
            return (200, response);
        }

        public async Task<(int, object?)> SubmitSecondaryEmailAsync(string username, string currentPassword, string secondaryEmail)
        {
            secondaryEmail = secondaryEmail.Trim();

            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "submit secondary email");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "submit secondary email")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // VERIFY NEW EMAIL IS NOT THE SAME AS PREVIOUS
            if (!EnsureNewEmailIsDifferent(secondaryEmail, userAccount, "submit secondary email"))
            {
                return (409, "New secondary email cannot be the same as old secondary email.");
            }

            // VERIFY THAT EMAIL IS NOT ALREADY IN USE | Deny change with GENERIC ERROR MESSAGE if email is in use by another account.
            if (!(await _utilityService.IsEmailAvailableAsync(secondaryEmail, username, "submit secondary email")))
            {
                return (500, "An unexpected error occured during new email submission, please try again.");     // GENERIC FOR SECURITY
            }

            // SUCCESS: ADD PENDING NEW EMAIL TO DOCUMENT | Update pending new email field, but do NOT set last changed time or logout yet.
            userAccount.PendingNewSecondaryEmail = secondaryEmail;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // SEND CONFIRMATION CODE TO NEW EMAIL | Do not await, because sending email can take a while.
            _ = _emailService.SendCodeToEmailAsync(secondaryEmail, ConfirmationCodeData.CodeContext.SecondaryEmailVerification);

            _logger.LogInformation($"submit secondary email successful (username: {username} | current secondary email: {userAccount.SecondaryEmail}" +
                $"| submitted secondary email: {secondaryEmail})");
            return (200, "Submit secondary email successful.");
        }

        public async Task<(int, object?)> ResendSecondaryEmailVerificationCodeAsync(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "resend secondary email verification code");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "resend secondary email verification code")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // RESEND EMAIL VERIFICATION CODE | Generate and send a new code, target email depending on context.
            (int code, string message) = await _emailService.SendCodeToEmailAsync(userAccount.PendingNewSecondaryEmail,
                ConfirmationCodeData.CodeContext.SecondaryEmailVerification);

            // We actually utilize the 'send code' response because this endpoint is only accessible to validated users.
            return (code, message);
        }

        public async Task<(int, object?)> VerifySecondaryEmailAsync(string username, string confirmationCode)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "verify secondary email");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "verify secondary email")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // VALIDATE USER-SUBMITTED CONFIRMATION CODE | Call email code service method to validate, which logs internally.
            if (!_emailService.ValidateSubmittedCode(userAccount.PendingNewSecondaryEmail, confirmationCode, ConfirmationCodeData.CodeContext.SecondaryEmailVerification))
            {
                return (401, "Invalid or expired confirmation code.");
            }

            // DOUBLE-CHECK EMAIL IS UNIQUE | Ensure new email is still unique before updating database.
            if (!(await _utilityService.IsEmailAvailableAsync(userAccount.PendingNewSecondaryEmail, username, "verify secondary email")))
            {
                // Clear pending field (is not available).
                userAccount.PendingNewSecondaryEmail = string.Empty;
                await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

                return (500, "An unexpected error occured during secondary email verification, please try again.");     // GENERIC FOR SECURITY
            }

            // SUCCESS: GENERATE LOGIN RESPONSE | Generate full login response with newly-verified and ready-to-use secondary email.
            var response = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: false);
            response.SecondaryEmail = userAccount.PendingNewSecondaryEmail;                     // Manually update response after created.

            // UPDATE DATABASE | Move pending secondary email to secondary email, then clear pending.
            userAccount.SecondaryEmail = userAccount.PendingNewSecondaryEmail;
            userAccount.PendingNewSecondaryEmail = string.Empty;
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // NOTIFY BOTH PRIMARY AND NEW SECONDARY EMAIL OF CHANGE | Do not await.
            _ = _emailService.NotifyUserOnAccountSettingsChanged(userAccount.PrimaryEmail, IEmailService.NotificationContext.SecondaryEmailChanged);
            _ = _emailService.NotifyUserOnAccountSettingsChanged(userAccount.SecondaryEmail, IEmailService.NotificationContext.SecondaryEmailChanged);

            _logger.LogInformation($"verify secondary email successful (username: {username}, verified secondary email: {userAccount.SecondaryEmail})");
            return (200, response);
        }


        #region Private: Local utility methods

        public bool IsUserAllowedToChangeUsername(UserAccountModel userAccount)
        {
            if (DateTime.UtcNow - userAccount.LastUsernameChangedTime < TimeSpan.FromDays(30))
            {
                _logger.LogInformation($"change username failed: cannot change username less than 30 days since last change (existing username: {userAccount.Username})");
                return false;
            }
            return true;
        }

        public bool IsUserAllowedToChangePassword(UserAccountModel userAccount)
        {
            // Ignore time check if server is enforcing password reset (otherwise account could be unintentionally locked).
            if (!userAccount.DoesPasswordNeedReset && DateTime.UtcNow - userAccount.LastPasswordChangedTime < TimeSpan.FromDays(1))
            {
                _logger.LogInformation($"change password failed: cannot change password less than 24 hours since last change (username: {userAccount.Username})");
                return false;
            }
            return true;
        }

        public bool IsUserAllowedToChangeEmail(UserAccountModel userAccount)
        {
            if (DateTime.UtcNow - userAccount.LastEmailChangedTime < TimeSpan.FromDays(30))
            {
                _logger.LogInformation($"submit changed email failed: cannot change email less than 30 days since last change (username: {userAccount.Username})");
                return false;
            }
            return true;
        }



        private bool EnsureNewUsernameIsDifferent(string newUsername, UserAccountModel userAccount)
        {
            if (string.Equals(userAccount.Username, newUsername))
            {
                _logger.LogInformation($"change username failed: new username is the same as existing username (existing username: {userAccount.Username})");
                return false;
            }
            return true;
        }

        private bool EnsureNewPasswordIsDifferent(string newPassword, UserAccountModel userAccount)
        {
            if (HashUtility.ComparePasswordToHash(newPassword, userAccount.PasswordHash))
            {
                _logger.LogInformation($"change password failed: new password is the same as existing password (username: {userAccount.Username})");
                return false;
            }
            return true;
        }

        private bool EnsureNewEmailIsDifferent(string newEmail, UserAccountModel userAccount, string context)
        {
            if (string.Equals(newEmail, userAccount.PrimaryEmail))
            {
                _logger.LogInformation($"{context} failed: new email cannot be the same as old email (username: {userAccount.Username}" +
                    $" | existing email: {userAccount.PrimaryEmail} | new email: {newEmail})");
                return false;
            }
            return true;
        }

        #endregion
    }
}
