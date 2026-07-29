using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;
using System.Collections.Concurrent;

namespace RPG_Login_API.Services
{
    public class LoginService : ILoginService
    {
        // Stores an array of failed login attempt timestamps for each user, used for account security purposes.
        private readonly ConcurrentDictionary<string, List<DateTime>> _failedLoginAttempts = [];

        private readonly IDatabaseService _databaseService;
        private readonly ITokenService _tokenService;
        private readonly IMfaCodeService _mfaCodeService;
        private readonly IEmailService _emailService;
        private readonly IUtilityService _utilityService;
        private readonly ILogger _logger;

        public LoginService(IDatabaseService databaseService, ITokenService tokenService, IMfaCodeService mfaCodeService,
            IEmailService emailService, IUtilityService utilityService, ILogger<LoginService> logger)
        {
            _databaseService = databaseService;
            _tokenService = tokenService;
            _mfaCodeService = mfaCodeService;
            _emailService = emailService;
            _utilityService = utilityService;

            _logger = logger;
        }



        public async Task<(int, object?)> LoginFromRefreshAsync(string refreshTokenString)
        {
            // PARSE TOKEN | Try to retrieve username and token object from the passed-in token string.
            if (!_tokenService.TryReadRefreshToken(refreshTokenString, out var username))
            {
                return (400, "Malformed refresh token in refresh login request.");
            }

            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "refresh login");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "refresh login")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // VALIDATE TOKEN | Validate token against stored refresh token AND check expiration and GUID match.
            if (!(await _utilityService.EnsureRefreshTokenIsValidAsync(refreshTokenString, userAccount)))
            {
                return (401, "Invalid or expired refresh token.");
            }

            // SUCCESS: GENERATE RESPONSE AND UPDATE DATABASE | Generate response model update document in database with new refresh token.
            AccessResponseModel response = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: false);

            // IMPORTANT: Write new refresh token to database (should always be valid, otherwise writes empty string).
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"refresh login successful (username: {response.Username}) with login code {response.LoginStatusCode}");
            return (200, response);
        }

        public async Task<(int, object?)> LoginAsync(string usernameOrEmail, string password)
        {
            // IMPORTANT: We check for a matching account here but do NOT return until password hash comparison to prevent
            //  timing attacks (performing a password hash comparison regardless of whether the account was found will
            //  cause this method to always return at the same time whether the account exists or the password is incorrect).

            usernameOrEmail = usernameOrEmail.Trim();

            // FIND USER | Try to find user in database. Return null if we cannot find by username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            userAccount ??= await _databaseService.GetOneByEmailAsync(usernameOrEmail); // If null, tries by email.

            // PASSWORD HASH COMPARISON | Compare password using HashUtility class, first checking for valid user account.
            // FAKE HASH COMPARISON | For security reasons, do fake hash even if account does not exist.
            if (userAccount == null)
            {
                HashUtility.DoFakeHashComparison(password);
                _logger.LogInformation($"login failed: user not found in database (username/email: {usernameOrEmail})");
                return (401, "Invalid username/email or password, please try again.");
            }
            
            // REAL PASSWORD COMPARISON | Actually compare passwords, appending failed login attempt if failure.
            if (!_utilityService.ComparePasswordForAccount(password, userAccount.PasswordHash, userAccount.Username, "login"))
            {
                AppendFailedLoginAttemptToTracker(userAccount.Username);
                return (401, "Invalid username/email or password, please try again.");
            }

            // PREVENT LOGIN IF ACCOUNT HAS TOO MANY FAILED LOGIN ATTEMPTS IN THE LAST FEW MINUTES
            if (DoesAccountHaveTooManyFailedLoginAttempts(userAccount.Username))
            {
                return (401, "Invalid username/email or password, please try again.");
            }

            // CORRECT CREDENTIALS, BUT ENSURE ACCOUNT NOT LOCKED
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "login")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // UNLOCK ACCOUNT IF WAS LOCKED FOR MFA RESET (BUT NO LONGER IS LOCKED) AND CLEAR FAILED LOGIN ATTEMPTS
            await UnlockAccountAfterLockedTimeEnded(userAccount);
            ClearFailedLoginAttemptsOnSuccess(userAccount.Username);

            // SUCCESS: GENERATE LOGIN RESPONSE | Generate response for initial login step, but no refresh token.
            AccessResponseModel response = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: true);

            _logger.LogInformation($"initial login step successful (username: {response.Username}) with login code {response.LoginStatusCode}");
            return (200, response);
        }

        public async Task<(int, object?)> SubmitMfaCodeForLoginAsync(string username, string mfaCode)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "submit MFA code for login");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "submit MFA code for login")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // Validate submitted code, differentiating between active and pending code based on submitted role.
            if (!_mfaCodeService.ValidateMfaCode(userAccount, mfaCode, isForActive: true))
            {
                return (401, "Incorrect multi-factor authentication code.");
            }

            // SUCCESS: Generate full-access login response, then update database with the newly-generated refresh token.
            AccessResponseModel response = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: false);
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"login completed successfully with MFA (username: {username}) with login code {response.LoginStatusCode}");
            return (200, response);
        }

        public async Task<(int, object?)> LogoutAsync(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "logout");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // UPDATE DATABASE | Remove stored refresh token and update in launcher status and time.
            userAccount.RefreshTokenHash = string.Empty;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"logout successful (username: {username})");
            return (200, "Logout successful.");
        }



        #region Private: Local utility methods

        /// <summary>
        /// Appends the current timestamp (DateTime.UtcNow) to the failed login attempt tracker for this account.
        ///  This does not check any other elements or delete expired attempts outside the sliding window.
        /// </summary>
        /// <param name="username"> The user account which just had a failed login. </param>
        private void AppendFailedLoginAttemptToTracker(string username)
        {
            // If an entry already exists, append a now timestamp to the list.
            if (_failedLoginAttempts.TryGetValue(username, out var list))
            {
                list.Add(DateTime.UtcNow);
                return;
            }

            // Else create a new dictionary entry for this user and with now as the only item in the list.
            _failedLoginAttempts[username] = [DateTime.UtcNow];
        }

        /// <summary>
        /// Checks whether the given account has too many failed login attempts within the last five minutes. In
        ///  addition to checking the number of attempts using a sliding window, also removes any old attempts
        ///  that are not within the window.
        /// </summary>
        /// <param name="username"> The user account being checked for failed login attempt count. </param>
        /// <returns> True if the account has too many failed login attempts within the last five minutes, else false. </returns>
        private bool DoesAccountHaveTooManyFailedLoginAttempts(string username)
        {
            if (_failedLoginAttempts.TryGetValue(username, out var list))
            {
                // Iterate over all items in the list, incrementing tracker if within the last 5 minutes.
                int count = 0;
                DateTime now = DateTime.UtcNow;
                for (int i = 0; i < list.Count; i++)
                {
                    if (now - list[i] < TimeSpan.FromMinutes(5)) count++;
                }

                // Remove all elements in the list from more than five minutes ago (using actual count vs. our count).
                if (list.Count > count)
                {
                    list.RemoveRange(0, list.Count - count);

                    // If now empty, remove the key entirely.
                    if (list.Count == 0) _failedLoginAttempts.Remove(username, out _);
                }

                // Finally, if our count is >= 3, return true.
                if (count >= 3)
                {
                    _logger.LogInformation($"login failed: account is temporarily locked because of too many failed login attempts");
                    return true;
                }
            }

            // Return false if there is no entry for the passed-in username.
            return false;
        }

        /// <summary>
        /// Checks whether the account was previously locked for MFA hard reset, fully unlocking it if so.
        ///  Clears the current MFA setup and all hard reset fields in the database, awaiting the update
        ///  then returning. Does nothing if there is no MFA hard reset cancel code in the database.
        /// </summary>
        /// <param name="userAccount"> The user account that will be unlocked, if applicable. </param>
        private async Task UnlockAccountAfterLockedTimeEnded(UserAccountModel userAccount)
        {
            // Do nothing if no MFA cancel code exists (was not locked in the first place).
            if (string.IsNullOrEmpty(userAccount.MfaHardResetCancelCode)) return;

            // Remove the current MFA setup and all hard reset data.
            userAccount.ActiveMfaKey = string.Empty;
            userAccount.PendingMfaKey = string.Empty;
            userAccount.MfaRecoveryCodeHash = string.Empty;
            userAccount.MfaHardResetInitiatedTime = DateTime.MinValue;
            userAccount.MfaHardResetLockedUntilTime = DateTime.MinValue;
            userAccount.MfaHardResetCancelCode = string.Empty;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // Notify both emails that the account's MFA setup has been hard reset.
            _ = _emailService.SendMfaHardResetCompletedNotifToEmailAsync(userAccount.PrimaryEmail);
            if (!string.IsNullOrEmpty(userAccount.SecondaryEmail))
            {
                _ = _emailService.SendMfaHardResetCompletedNotifToEmailAsync(userAccount.SecondaryEmail);
            }
        }

        /// <summary>
        /// Clears all stored failed login attempts for the given account on successful login.
        /// </summary>
        /// <param name="username"> The user account which just successfully logged in with username/email and password. </param>
        private void ClearFailedLoginAttemptsOnSuccess(string username)
        {
            // Remove the entire dictionary entry on successful login.
            _failedLoginAttempts.Remove(username, out _);
        }

        #endregion

    }
}
