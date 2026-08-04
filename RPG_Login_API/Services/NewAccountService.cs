using RPG_Login_API.Data;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.Responses;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;

namespace RPG_Login_API.Services
{
    public class NewAccountService : INewAccountService
    {
        private readonly IDatabaseService _databaseService;
        private readonly IEmailService _emailService;
        private readonly IUtilityService _utilityService;
        private readonly ILogger _logger;

        public NewAccountService(IDatabaseService databaseService, IEmailService emailCodeService,
            IUtilityService utilityService, ILogger<NewAccountService> logger)
        {
            _databaseService = databaseService;
            _emailService = emailCodeService;
            _utilityService = utilityService;

            _logger = logger;
        }



        public async Task<(int, object?)> RegisterAsync(string username, string email, string password)
        {
            // TRIM WHITESPACE FROM BEGINNING AND END OF USERNAME, EMAIL, AND PASSWORD
            username = username.Trim();
            email = email.Trim();
            password = password.Trim();

            // ENSURE USERNAME AND EMAIL NOT ALREADY IN USE | Query database for any existing account with matching username or email.
            bool isAvailable = await _utilityService.IsUsernameAvailableAsync(username, "registration");
            if (!isAvailable)
            {
                return (409, "That username is unavailable, please try a different username.");
            }
            isAvailable = await _utilityService.IsEmailAvailableAsync(email, "NEW USER", "registration");
            if (!isAvailable)
            {
                return (500, "An unexpected error occurred during registration, please try again.");    // GENERIC FOR SECURITY
            }

            // ENSURE NON-PROFANE USERNAME | Deny any particularly profane username using ProfanityDetector library.
            if (_utilityService.IsUsernameProfane(username, "registration"))
            {
                return (422, "That username is not allowed, please try a different username.");
            }

            // Ensure submitted password is not found in list of 100,000 most-used-passwords.
            if (_utilityService.IsPasswordInsecure(password, "NEW USER", "registration"))
            {
                return (422, "Password does not meet minimum security standards, please submit a more secure password.");
            }

            // CREATE NEW ACCOUNT MODEL | Username and email are unique (verified in controller), so create a new user document.
            UserAccountModel userAccount = new()
            {
                Username = username,
                PrimaryEmail = email,
                PasswordHash = HashUtility.GenerateNewPasswordHash(password),
                RefreshTokenHash = string.Empty,                    // New account is not fully logged in, so no refresh token.
                AccountCreatedTime = DateTime.UtcNow,
                LastPasswordChangedTime = DateTime.UtcNow,
                LastUsernameChangedTime = DateTime.UtcNow,
            };

            // INSERT INTO DATABASE VIA API CALL | Try to insert, returning 500 error if failure.
            if (!await _databaseService.InsertOneAsync(userAccount))
            {
                return (500, "An unexpected database error occurred during the request.");
            }

            // GENERATE RESPONSE | Finally, after account creation, generate response and return. Always has email not verified login code.
            AccessResponseModel response = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: true);

            _logger.LogInformation($"new user registration successful (username: {username} | email: {email})");
            return (201, response);
        }

        public async Task<(int, object?)> ResendEmailVerificationCodeAsync(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "resend email verification code");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "resend email verification code")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // RESEND EMAIL VERIFICATION CODE | Generate and send a new code to primary email.
            (int code, string message) = await _emailService.SendCodeToEmailAsync(userAccount.PrimaryEmail, ConfirmationCodeData.CodeContext.PrimaryEmailVerification);

            // We actually utilize the 'send code' response because this endpoint is only accessible to validated users.
            _logger.LogInformation($"resend email verification code successful (username: {username})");
            return (code, message);
        }

        public async Task<(int, object?)> VerifyEmailForNewAccountAsync(string username, string confirmationCode)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "new account email verification");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "new account email verification")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // VALIDATE USER-SUBMITTED CONFIRMATION CODE | Call email code service method to validate, which logs internally.
            if (!_emailService.ValidateSubmittedCode(userAccount.PrimaryEmail, confirmationCode, ConfirmationCodeData.CodeContext.PrimaryEmailVerification))
            {
                return (401, "Invalid or expired confirmation code.");
            }

            // SUCCESS: GENERATE LOGIN RESPONSE | On successful new account email verification, generate login response (not full login yet).
            var response = _utilityService.GenerateAccessResponse(userAccount, isInitialLoginStep: true);    // New account = initial login step

            // UPDATE DATABASE | Update user account in database with newly-set 'email verified' flag.
            userAccount.IsEmailVerified = true;
            userAccount.LastEmailChangedTime = DateTime.UtcNow;     // Consider verification to be 'changed time'.
            if (!await _databaseService.ReplaceOneByIdAsync(userAccount.Id, userAccount))
            {
                return (500, "An unexpected database error occurred during the request.");
            }

            _logger.LogInformation($"new account email verification successful (username: {username}, verified email: {userAccount.PrimaryEmail})");
            return (200, response);
        }
    }
}
