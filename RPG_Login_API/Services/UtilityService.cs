using RPG_Login_API.Data;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.Responses;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;

namespace RPG_Login_API.Services
{
    public class UtilityService : IUtilityService
    {
        private readonly IDatabaseService _databaseService;
        private readonly ITokenService _tokenService;
        private readonly IEmailService _emailService;
        private readonly ILogger _logger;

        private readonly ProfanityFilter.ProfanityFilter _profanityFilter;
        private readonly HashSet<string> _bannedPasswords;

        public UtilityService(IDatabaseService databaseService, ITokenService tokenService, IEmailService emailCodeService,
            ILogger<UtilityService> logger)
        {
            _databaseService = databaseService;
            _tokenService = tokenService;
            _emailService = emailCodeService;

            _logger = logger;

            // Load a list of 100000 most commonly used passwords, used to prevent unsafe passwords.
            string filePath = Path.Combine(Directory.GetCurrentDirectory(), "Utility", "100k-most-used-passwords-NCSC.txt");
            _bannedPasswords = new HashSet<string>(File.ReadAllLines(filePath), StringComparer.Ordinal);

            // Load custom (minimal) profanity filter list, for use when users submit a new username.
            filePath = Path.Combine(Directory.GetCurrentDirectory(), "Utility", "minimal-profanity-filter-list.txt");
            _profanityFilter = new ProfanityFilter.ProfanityFilter(File.ReadAllLines(filePath).ToList());
        }



        public async Task<UserAccountModel?> TryRetrieveAccountByUsernameAsync(string username, string context)
        {
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"{context} failed: could not find account in database for provided username (username: {username})");
                return null;
            }
            return userAccount;
        }

        public async Task<UserAccountModel?> TryRetrieveAccountByEmailAsync(string accountEmail, string context)
        {
            var userAccount = await _databaseService.GetOneByEmailAsync(accountEmail);
            if (userAccount == null)
            {
                _logger.LogInformation($"{context} failed: could not find account in database for provided email (email: {accountEmail})");
                return null;
            }
            return userAccount;
        }

        public async Task<bool> EnsureAccountIsNotLockedAsync(UserAccountModel userAccount, string context)
        {
            // Simply compare the 'account locked until' timestamp against the current time.
            DateTime now = DateTime.UtcNow;
            if (userAccount.TimeTrackers.AccountLockedUntil > now || userAccount.MfaHardResetLockedUntilTime > now)
            {
                // Ensure no refresh token remains if locked.
                if (userAccount.RefreshTokenHash != string.Empty)
                {
                    userAccount.RefreshTokenHash = string.Empty;
                    await _databaseService.ReplaceOneByIdAsync(userAccount.Id, userAccount);    // Do not check return value.
                }

                _logger.LogInformation($"{context} failed: account is locked until {userAccount.TimeTrackers.AccountLockedUntil.Date.ToString()} (username: {userAccount.Username})");
                return false;
            }

            return true;
        }

        public AccessResponseModel GenerateAccessResponse(UserAccountModel userAccount, bool isInitialLoginStep)
        {
            // Generate login response based on account state.
            int loginCode; string role; string refreshToken = string.Empty;
            if (!userAccount.IsEmailVerified)
            {
                // If email not verified, code is 1 and a confirmation email must be sent.
                loginCode = 10;
                role = TokenUtility.Roles.EmailNotVerified;
                _ = _emailService.SendCodeToEmailAsync(userAccount.PrimaryEmail, ConfirmationCodeData.CodeContext.PrimaryEmailVerification);
            }
            else if (userAccount.DoesPasswordNeedReset)
            {
                // If password must be reset for security reasons, code is 2 and confirmation email must be sent.
                loginCode = 20;
                role = TokenUtility.Roles.ResetPassword;
                _ = _emailService.SendCodeToEmailAsync(userAccount.PrimaryEmail, ConfirmationCodeData.CodeContext.PasswordReset);
            }
            else if (string.IsNullOrEmpty(userAccount.ActiveMfaKey))
            {
                // If no MFA key, then MFA is not yet enabled for this account.
                loginCode = 30;
                role = TokenUtility.Roles.MfaNotEnabled;
            }
            else
            {
                // Else account state is good (fully set up), so check whether we are awaiting MFA submission (pending login).
                if (isInitialLoginStep)
                {
                    loginCode = 1;
                    role = TokenUtility.Roles.AwaitingMfa;
                }
                else
                {
                    loginCode = 0;
                    role = TokenUtility.Roles.FullAccess;
                    refreshToken = _tokenService.GenerateRefreshToken(userAccount.Username, durationDays: 30);
                }
            }

            // Finally, create AccessResponseModel with our code and role (also potentially refresh token) created above.
            return new AccessResponseModel()
            {
                Username = userAccount.Username,
                PrimaryEmail = userAccount.PrimaryEmail,
                SecondaryEmail = userAccount.SecondaryEmail,    // May be empty.
                LoginStatusCode = loginCode,
                RefreshToken = refreshToken,
                AccessToken = _tokenService.GenerateAccessToken(userAccount.Username, role, durationMinutes: 15),
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
            };
        }

        public async Task<bool> IsUsernameAvailableAsync(string username, string context)
        {
            var existingAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (existingAccount != null)
            {
                // If username is in use but account email was never verified and was created >30 days ago, delete it (zombie).
                if (!existingAccount.IsEmailVerified && DateTime.UtcNow - existingAccount.TimeTrackers.AccountCreatedTime > TimeSpan.FromDays(30))
                {
                    await _databaseService.DeleteOneByIdAsync(existingAccount.Id);
                    return true;                // Deleted zombie, so username IS available.
                }

                _logger.LogInformation($"{context} failed: username already in use (username: {username})");
                return false;                   // Else was not zombie, so username is NOT available.
            }

            // Else if existing account is null, then does not exist so is available.
            return true;
        }

        public async Task<bool> IsEmailAvailableAsync(string email, string username, string context)
        {
            // First, check whether the email is in use as the primary email for an account.
            var existingAccount = await _databaseService.GetOneByEmailAsync(email);
            if (existingAccount != null)
            {
                // If email is in use but account email was never verified and was created >30 days ago, delete it (zombie).
                if (!existingAccount.IsEmailVerified && DateTime.UtcNow - existingAccount.TimeTrackers.AccountCreatedTime > TimeSpan.FromDays(30))
                {
                    await _databaseService.DeleteOneByIdAsync(existingAccount.Id);
                    return true;                // Deleted zombie, so email IS available.
                }

                _logger.LogInformation($"{context} failed: email already in use (username: {username}, desired email: {email})");
                return false;                   // Else was not zombie, so email is NOT available.
            }

            // Check for secondary email (only checks for fully set, not pending).
            if (await _databaseService.IsSecondaryEmailInUseAsync(email))
            {
                _logger.LogInformation($"{context} failed: email already in use (username: {username}, desired email: {email})");
                return false;                   // Secondary email can only be set if the account email is fully verified (not zombie).
            }

            // Else is not in use as primary (non-zombie) OR secondary.
            return true;
        }

        public async Task<bool> EnsureRefreshTokenIsValidAsync(string refreshToken, UserAccountModel userAccount)
        {
            bool tokenIsValid = _tokenService.ValidateToken(refreshToken, userAccount.RefreshTokenHash);
            if (!tokenIsValid)
            {
                // This means the token in the database is invalid, so remove it.
                userAccount.RefreshTokenHash = string.Empty;
                await _databaseService.ReplaceOneByIdAsync(userAccount.Id, userAccount);    // Do not check success state.

                _logger.LogInformation($"refresh login failed: user-provided token does not match stored token or is expired (username: {userAccount.Username})");
                return false;
            }

            return true;
        }

        public bool IsUsernameProfane(string username, string context)
        {
            if (_profanityFilter.DetectAllProfanities(username).Count > 0)
            {
                _logger.LogInformation($"{context} failed: username contains profanity blocked by filter (username: {username})");
                return true;
            }
            return false;
        }

        public bool IsPasswordInsecure(string password, string username, string context)
        {
            if (_bannedPasswords.Contains(password))
            {
                _logger.LogInformation($"{context} failed: password found in list of 100,000 insecure passwords (username: {username})");
                return true;
            }
            return false;
        }

        public bool ComparePasswordForAccount(string password, string compareToHash, string username, string context)
        {
            if (!HashUtility.ComparePasswordToHash(password, compareToHash))
            {
                _logger.LogInformation($"{context} failed: user-provided password does not match account's stored password (username: {username})");
                return false;
            }
            return true;
        }

        
    }
}
