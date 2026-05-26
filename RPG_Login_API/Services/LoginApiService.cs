using Microsoft.AspNetCore.Identity.Data;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using Org.BouncyCastle.Asn1.Ocsp;
using RPG_Login_API.Configuration;
using RPG_Login_API.Data;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace RPG_Login_API.Services
{
    /// <summary>
    /// The LoginApiService is responsible for performing API endpoint logic and is used directly by the
    ///  controller. This class depends on the DatabaseService and the TokenService. Can be scoped or singleton.
    /// </summary>
    public class LoginApiService : ILoginApiService
    {
        // Stores an array of failed login attempt timestamps for each user, used for account security purposes.
        private readonly ConcurrentDictionary<string, List<DateTime>> _failedLoginAttempts = [];

        private readonly IDatabaseService _databaseService;
        private readonly ITokenService _tokenService;
        private readonly IEmailCodeService _emailCodeService;
        private readonly ILogger _logger;

        public LoginApiService(IDatabaseService databaseService, ITokenService tokenService, IEmailCodeService emailCodeService,
            ILogger<LoginApiService> logger)
        {
            _databaseService = databaseService;
            _tokenService = tokenService;
            _emailCodeService = emailCodeService;

            _logger = logger;
        }





        #region (Interface) Public: User Account Access API Logic

        public async Task<(int, string, LoginResponseModel?)> UserLoginFromRefreshAsync(string refreshTokenString)
        {
            // PARSE TOKEN | Try to retrieve username and token object from the passed-in token string.
            if (!_tokenService.TryReadUsernameFromTokenString(refreshTokenString, out var username))
            {
                _logger.LogInformation($"Refresh login failed: malformed (unreadable) refresh token in request");
                return (400, "Malformed refresh token in refresh login request.", null);
            }

            // FIND USER | Try to find user in database. Return null if we cannot find by username.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Refresh login failed: account for username stored in refresh token not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.", null);
            }

            // COMPARE TOKEN | Now that we have found a valid user, compare the stored refresh token with this refresh token.
            if (!HashUtility.CompareRefreshTokenToHash(refreshTokenString, userAccount.RefreshTokenHash))
            {
                _logger.LogInformation($"Refresh login failed: user-provided token does not match token in database (username: {username})");
                return (401, "Invalid or expired refresh token.", null);
            }

            // ACTUALLY VALIDATE TOKEN | If token matches stored token in database, validate it (checks expiration and client GUID).
            if (!_tokenService.ValidateToken(refreshTokenString))
            {
                // This means the token in the database is invalid, so remove it.
                userAccount.RefreshTokenHash = string.Empty;
                await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

                _logger.LogInformation($"Refresh login failed: token is expired or found mismatched client GUID (username: {username})");
                return (401, "Invalid or expired refresh token.", null);
            }

            // DISALLOW MULTIPLE LOGINS | If account is already logged into launcher, ensure it is not a zombie, then deny login.
            if (userAccount.InLauncherStatus && (DateTime.UtcNow - userAccount.LastInLauncherTime < TimeSpan.FromSeconds(75)))
            {
                // IMPORTANT: We do not invalidate the account's stored refresh token because the account that IS currently
                //  logged in will have its associated refresh token stored. The device doing the duplicate login attempt
                //  will remove its refresh token client-side, which is already invalid in the database.
                _logger.LogInformation($"Refresh login failed: user already logged in on another device");
                return (403, "Account already logged into launcher on another device, please try again later.", null);
            }

            // GENERATE RESPONSE | Finally, token is confirmed fully valid so determine login response based on account state.
            LoginResponseModel response;
            if (!userAccount.IsEmailVerified || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                int statusCode = (!userAccount.IsEmailVerified) ? 1 : 2;                    // 1 if unconfirmed, else 2 for password reset
                string role = (!userAccount.IsEmailVerified) ? TokenService.Roles.EmailNotVerified : TokenService.Roles.ResetPassword;
                response = new LoginResponseModel()
                {
                    Username = userAccount.Username,
                    Email = userAccount.Email,
                    LoginStatusCode = statusCode,
                    RefreshToken = _tokenService.GenerateRefreshToken(userAccount.Username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(userAccount.Username, role, durationMinutes: 15),
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
                };

                // Unconfirmed or reset required will need a new confirmation code. Do not await send because it can take a while.
                _ = _emailCodeService.SendCodeToEmailAsync(userAccount.Email, ConfirmationCodeData.CodeContext.EmailVerification);
            }
            else
            {
                // Else account state is good, so return full login with refresh token AND access token.
                response = new LoginResponseModel()
                {
                    Username = userAccount.Username,
                    Email = userAccount.Email,
                    LoginStatusCode = 0,
                    RefreshToken = _tokenService.GenerateRefreshToken(userAccount.Username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(userAccount.Username, TokenService.Roles.FullAccess, durationMinutes: 15),
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
                };
                userAccount.InLauncherStatus = true;
                userAccount.LastInLauncherTime = DateTime.UtcNow;
            }

            // UPDATE DATABASE | After token generation, update document in database with newly-generated HASHED refresh token.
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"User refresh login successful (username: {response.Username}) with login code {response.LoginStatusCode}");
            return (200, "Refresh login successful.", response);
        }

        public async Task<(int, string, LoginResponseModel?)> UserLoginAsync(string usernameOrEmail, string password)
        {
            // IMPORTANT: We check for a matching account here but do NOT return until password hash comparison to prevent
            //  timing attacks (performing a password hash comparison regardless of whether the account was found will
            //  cause this method to always return at the same time whether the account exists or the password is incorrect).

            // FIND USER | Try to find user in database. Return null if we cannot find by username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(usernameOrEmail);
            }

            // PASSWORD HASH COMPARISON | Compare password using HashUtility class, first checking for valid user account.
            if (userAccount == null)
            {
                // If failed to find account, perform FAKE hash comparison to return at the same time.
                HashUtility.DoFakeHashComparison(password);

                _logger.LogInformation($"Login failed: user not found in database (username/email: {usernameOrEmail})");
                return (401, "Invalid username/email or password, please try again.", null);
            }
            if (!HashUtility.ComparePasswordToHash(password, userAccount.PasswordHash))
            {
                // Else account DOES exist, so do legitimate password hash comparison and return if mismatch.
                AppendFailedLoginAttemptToTracker(userAccount.Username);

                _logger.LogInformation($"Login failed: user-provided password does not match account's stored password (username: {userAccount.Username})");
                return (401, "Invalid username/email or password, please try again.", null);
            }

            // CHECK IF ACCOUNT LOCKED | Block the successful login if the account is temporarily locked because of failed attempts.
            if (DoesAccountHaveTooManyFailedLoginAttempts(userAccount.Username))
            {
                _logger.LogInformation($"Login failed: account is temporarily locked because of too many failed login attempts");
                return (401, "Invalid username/email or password, please try again.", null);
            }

            // VALID BUT DISALLOW MULTIPLE LOGINS | If account is already logged into launcher, ensure it is not a zombie, then deny login.
            if (userAccount.InLauncherStatus && (DateTime.UtcNow - userAccount.LastInLauncherTime < TimeSpan.FromSeconds(75)))
            {
                _logger.LogInformation($"Login failed: user already logged in on another device");
                return (403, "Account already logged into launcher on another device, please try again later.", null);
            }

            // SUCCESS: GENERATE RESPONSE | Determine how we will process login based on account state.
            ClearFailedLoginAttemptsOnSuccess(userAccount.Username);
            LoginResponseModel response;
            if (!userAccount.IsEmailVerified || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                int statusCode = (!userAccount.IsEmailVerified) ? 1 : 2;                    // 1 if unconfirmed, else 2 for password reset
                string role = (!userAccount.IsEmailVerified) ? TokenService.Roles.EmailNotVerified : TokenService.Roles.ResetPassword;
                response = new LoginResponseModel()
                {
                    Username = userAccount.Username,
                    Email = userAccount.Email,
                    LoginStatusCode = statusCode,
                    RefreshToken = _tokenService.GenerateRefreshToken(userAccount.Username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(userAccount.Username, role, durationMinutes: 15),
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
                };

                // Unconfirmed or reset required will need a new confirmation code. Do not await send because it can take a while.
                _ = _emailCodeService.SendCodeToEmailAsync(userAccount.Email, ConfirmationCodeData.CodeContext.EmailVerification);
            }
            else
            {
                // Else account state is good, so return full login with refresh token AND access token. Also update access tokens map.
                response = new LoginResponseModel()
                {
                    Username = userAccount.Username,
                    Email = userAccount.Email,
                    LoginStatusCode = 0,
                    RefreshToken = _tokenService.GenerateRefreshToken(userAccount.Username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(userAccount.Username, TokenService.Roles.FullAccess, durationMinutes: 15),
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
                };
                userAccount.InLauncherStatus = true;
                userAccount.LastInLauncherTime = DateTime.UtcNow;
            }

            // UPDATE DATABASE | After token generation, update document in database with newly-generated refresh token.
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"User login successful (username: {response.Username}) with login code {response.LoginStatusCode}");
            return (200, "Login successful.", response);
        }

        public async Task<(int, string, LoginResponseModel?)> UserRegisterAsync(string username, string email, string password)
        {
            // ENSURE USERNAME AND EMAIL NOT ALREADY IN USE | Query database for any existing account with matching username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount != null)
            {
                // If username is in use but account email was never verified and was created >30 days ago, delete it (zombie).
                if (!userAccount.IsEmailVerified && DateTime.UtcNow - userAccount.AccountCreatedTime > TimeSpan.FromDays(30))
                {
                    await _databaseService.DeleteOneByUsernameAsync(userAccount.Username);
                }
                // Else username is actually in use, so return failure.
                else
                {
                    _logger.LogInformation($"Registration failed: username already in use (username: {username})");
                    return (409, "Username already in use, please try a different username.", null);
                }
            }
            userAccount = await _databaseService.GetOneByEmailAsync(username);
            if (userAccount != null)
            {
                // Same logic as username check above.
                if (!userAccount.IsEmailVerified && DateTime.UtcNow - userAccount.AccountCreatedTime > TimeSpan.FromDays(30))
                {
                    await _databaseService.DeleteOneByEmailAsync(userAccount.Email);
                }
                else
                {
                    // Return a GENERIC error message.
                    _logger.LogInformation($"Registration failed: email already in use (email: {email})");
                    return (500, "An unexpected error occurred during registration, please try again.", null);
                }
            }

            // CREATE NEW ACCOUNT MODEL | Username and email are unique (verified in controller), so create a new user document.
            string refreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30);
            userAccount = new()
            {
                Username = username,
                Email = email,
                PasswordHash = HashUtility.GenerateNewPasswordHash(password),
                RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(refreshToken),   // Store hashed token in database.
                AccountCreatedTime = DateTime.UtcNow,
                LastPasswordChangedTime = DateTime.UtcNow,
                LastUsernameChangedTime = DateTime.UtcNow,
                // ObjectId is auto generated, and other values are left default. In launcher status and time remain unset.
            };
            await _databaseService.InsertOneAsync(userAccount);

            // GENERATE RESPONSE | Finally, after account creation, generate response and return.
            var response = new LoginResponseModel()
            {
                Username = username,
                Email = email,
                LoginStatusCode = 1,        // New accounts must always confirm email (code 1).
                RefreshToken = refreshToken,
                AccessToken = _tokenService.GenerateAccessToken(userAccount.Username, TokenService.Roles.EmailNotVerified, durationMinutes: 15),
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
            };

            // GENERATE EMAIL VERIFICATION CODE | Generate and send email verification code to user's email immediately. Do not await.
            _ = _emailCodeService.SendCodeToEmailAsync(userAccount.Email, ConfirmationCodeData.CodeContext.EmailVerification);

            _logger.LogInformation($"New user registration successful (username: {username} | email: {email})");
            return (201, "Account registration successful.", response);
        }

        public async Task<(int, string)> UserLogoutAsync(string username)
        {
            // NOTE: If the user is in-game when they log out, the game application will remain logged in, but they will need
            //  to re-login when they want to launch the game again.

            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Logout failed: account for username stored in access token not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.");
            }

            // UPDATE DATABASE | Remove stored refresh token and update in launcher status and time.
            userAccount.InLauncherStatus = false;
            userAccount.LastInLauncherTime = DateTime.UtcNow;
            userAccount.RefreshTokenHash = string.Empty;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"User logout successful (username: {username})");
            return (200, "Logout successful.");
        }

        public async Task<(int, string)> UserResendEmailVerificationCode(string username, bool isForNewAccount)
        {
            // FIND USER | Try to find user in database. We check for valid username in controller, so should always find an account.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Resend email verification code failed: account for username stored in access token not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.");
            }

            // RESEND EMAIL VERIFICATION CODE | Generate and send a new code, target email depending on context.
            string targetEmail = (isForNewAccount) ? userAccount.Email : userAccount.PendingNewEmail;
            (int code, string message) = await _emailCodeService.SendCodeToEmailAsync(targetEmail, ConfirmationCodeData.CodeContext.EmailVerification);

            // We actually utilize the 'send code' response because this endpoint is only accessible to validated users.
            return (code, message);
        }

        public async Task<(int, string, LoginResponseModel?)> UserVerifyAccountEmailAsync(string username, string confirmationCode, bool isForNewAccount)
        {
            // FIND USER | Try to find user in database. We check for valid username in controller, so should always find an account.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Email verification failed: account for username stored in access token not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.", null);
            }

            // VALIDATE USER-SUBMITTED CONFIRMATION CODE | Call email code service method to validate, which logs internally.
            string targetEmail = (isForNewAccount) ? userAccount.Email : userAccount.PendingNewEmail;
            if (!_emailCodeService.ValidateSubmittedCode(targetEmail, confirmationCode, ConfirmationCodeData.CodeContext.EmailVerification))
            {
                return (401, "Invalid or expired confirmation code.", null);
            }

            // SUCCESS: GENERATE LOGIN RESPONSE | On successful email verification, re-generate both refresh and access token (like login).
            var response = new LoginResponseModel()
            {
                Username = userAccount.Username,
                Email = targetEmail,
                LoginStatusCode = 0,        // Always full success status after successful verification.
                RefreshToken = _tokenService.GenerateRefreshToken(userAccount.Username, durationDays: 30),
                AccessToken = _tokenService.GenerateAccessToken(userAccount.Username, TokenService.Roles.FullAccess, durationMinutes: 15),
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
            };

            // UPDATE DATABASE | After token generation, update account document.
            userAccount.Email = targetEmail;                    // Target email will be existing email OR pending new email, depending on context.
            userAccount.PendingNewEmail = string.Empty;         // Clear pending new email upon verification; verified email is now main email.
            userAccount.IsEmailVerified = true;
            userAccount.LastEmailChangedTime = DateTime.UtcNow; // Consider verification to be 'changed time'.
            userAccount.InLauncherStatus = true;
            userAccount.LastInLauncherTime = DateTime.UtcNow;
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"User email verification successful (username: {username}, verified email: {targetEmail})");
            return (200, "Account email verification successful.", response);
        }

        public async Task UserForgotPasswordAsync(string usernameOrEmail)
        {
            // NOTE: We do not return a status code for security reasons (codes can be sent anonymously, and we cannot
            //  provide information to an unauthorized user whether an account exists and was sent a code successfully).

            // FIND USER | Try to find user in database. Return null if we cannot find by username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(usernameOrEmail);
                if (userAccount == null)
                {
                    _logger.LogInformation($"Forgot password attempt failed: user not found in database (username/email: {usernameOrEmail})");
                    return;
                }
            }

            // TRY TO SEND CODE TO EMAIL | Do not await because sending code can take a while.
            _ = _emailCodeService.SendCodeToEmailAsync(userAccount.Email, ConfirmationCodeData.CodeContext.PasswordReset);
        }

        public async Task<(int, string, PasswordResetTokenResponseModel?)> UserInitiatePasswordResetAsync(string usernameOrEmail, string confirmationCode)
        {
            // NOTE: We return a generic error message because this endpoint allows anonymous calling. We cannot allow
            //  unauthorized users to look up whether an account username/email exists by returning specific information.

            // FIND USER | Try to find user in database. We check for valid username/email in controller, so should always find an account.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(usernameOrEmail);
                if (userAccount == null)
                {
                    _logger.LogInformation($"Initiate password reset failed: user not found in database (username/email: {usernameOrEmail})");
                    return (401, "Invalid or expired confirmation code.", null);
                }
            }

            // VALIDATE USER-SUBMITTED CONFIRMATION CODE | Call email code service method to validate, which logs internally.
            if (!_emailCodeService.ValidateSubmittedCode(userAccount.Email, confirmationCode, ConfirmationCodeData.CodeContext.PasswordReset))
            {
                return (401, "Invalid or expired confirmation code.", null);
            }

            // SUCCESS: GENERATE RESPONSE | On successful request, consume confirmation code and generate short-duration reset token.
            var response = new PasswordResetTokenResponseModel()
            {
                Username = userAccount.Username,
                PasswordResetToken = _tokenService.GenerateAccessToken(userAccount.Username, TokenService.Roles.ResetPassword, durationMinutes: 5)
            };

            _logger.LogInformation($"User initiate password reset successful (username: {userAccount.Username})");
            return (200, "Initiate password reset successful.", response);
        }

        public async Task<(int, string)> UserSubmitNewPasswordAsync(string username, string newPassword)
        {
            // FIND USER | Try to find user in database. Return false if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Password reset failed: account for username stored in reset token not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE USER IS ALLOWED TO CHANGE PASSWORD | If trying to change less than 24 hours since last change, deny change.
            //  Also ignore time check if server is enforcing password reset (otherwise account could be bricked).
            if (!userAccount.DoesPasswordNeedReset && DateTime.UtcNow - userAccount.LastPasswordChangedTime < TimeSpan.FromDays(1))
            {
                _logger.LogInformation($"Password reset failed: cannot change password less than 24 hours since last change (username: {username})");
                return (493, "Cannot change password within 24 hours of previous change.");
            }

            // VALID USER: VERIFY NEW PASSWORD DOES NOT MATCH PREVIOUS
            if (HashUtility.ComparePasswordToHash(newPassword, userAccount.PasswordHash))
            {
                _logger.LogInformation($"Password reset failed: new password cannot be the same as old password (username: {username})");
                return (409, "New password cannot be the same as old password.");
            }
            
            // GENERATE NEW PASSWORD HASH AND UPDATE DOCUMENT | Update various fields in account document now that password is reset.
            userAccount.PasswordHash = HashUtility.GenerateNewPasswordHash(newPassword);
            userAccount.DoesPasswordNeedReset = false;      // Always reset to false regardless of whether reset was forced.
            userAccount.IsEmailVerified = true;             // Reset requires email anyway, so implicitly verify email.
            userAccount.LastPasswordChangedTime = DateTime.UtcNow;

            // LOG OUT USER AND ACTUALLY UPDATE DATABASE | Invalidate user's refresh token, then update database.
            userAccount.RefreshTokenHash = string.Empty;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation($"User password reset successful (username: {username})");
            return (200, "Password reset successful.");
        }

        public async Task<(int, string, LoginResponseModel?)> UserChangeUsernameAsync(string existingUsername, string newUsername)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(existingUsername);
            if (userAccount == null)
            {
                _logger.LogInformation($"Username change failed: account for username stored in access token not found in database (username: {existingUsername})");
                return (404, "Failed to find user account for the provided username.", null);
            }

            // VERIFY THAT USERNAME IS NOT ALREADY IN USE | Deny change if username is already in use by a legitimate account.
            var existingAccount = await _databaseService.GetOneByUsernameAsync(newUsername);
            if (existingAccount != null)
            {
                // If username is in use but account email was never verified and was created >30 days ago, delete it (zombie).
                if (!userAccount.IsEmailVerified && DateTime.UtcNow - userAccount.AccountCreatedTime > TimeSpan.FromDays(30))
                {
                    await _databaseService.DeleteOneByUsernameAsync(userAccount.Username);
                }
                // Else username is actually in use, so return failure.
                else
                {
                    _logger.LogInformation($"Username change failed: username already in use (username: {newUsername})");
                    return (409, "Username already in use, please try a different username.", null);
                }
            }

            // ENSURE USER IS ALLOWED TO CHANGE USERNAME | Deny change if username was changed less than 30 days ago.
            if (DateTime.UtcNow - userAccount.LastUsernameChangedTime < TimeSpan.FromDays(30))
            {
                _logger.LogInformation($"Username change failed: cannot change username less than 30 days since last change (existing username: {existingUsername})");
                return (493, "Cannot change username within 30 days of previous change.", null);
            }

            // VERIFY THAT NEW USERNAME IS NOT SAME AS PREVIOUS
            if (string.Equals(userAccount.Username, newUsername))
            {
                _logger.LogInformation("Username change failed: user-submitted new username is the same as existing account username");
                return (409, "New username cannot be the same as old username.", null);
            }

            // RE-LOGIN USER | Now that account state has changed, re-login user to generate new tokens with new username.
            var response = new LoginResponseModel()
            {
                Username = newUsername,
                Email = userAccount.Email,
                LoginStatusCode = 0,        // This endpoint can only be accessed by a full-access token, so make full access again.
                RefreshToken = _tokenService.GenerateRefreshToken(newUsername, durationDays: 30),
                AccessToken = _tokenService.GenerateAccessToken(newUsername, TokenService.Roles.FullAccess, durationMinutes: 15),
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
            };

            // UPDATE DOCUMENT AND DATABASE | Update username and last username changed time in document, then update database.
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            userAccount.InLauncherStatus = true;
            userAccount.LastInLauncherTime = DateTime.UtcNow;
            userAccount.Username = newUsername;
            userAccount.LastUsernameChangedTime = DateTime.UtcNow;
            await _databaseService.UpdateOneByUsernameAsync(existingUsername, userAccount);     // Query by old username.

            _logger.LogInformation($"User successfully changed username (old username: {existingUsername} | new username: {newUsername})");
            return (200, "Username change successful", response);
        }

        public async Task<(int, string)> UserRequestEmailChangeAsync(string username)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Request email change failed: account for username stored in access token not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.");
            }

            // TRY TO SEND CODE TO EMAIL | Send a confirmation code to the account's existing email.
            (int code, string message) = await _emailCodeService.SendCodeToEmailAsync(userAccount.Email, ConfirmationCodeData.CodeContext.ChangeEmail);

            // We actually utilize the 'send code' response because this endpoint is only accessible to validated users.
            return (code, message);
        }

        public async Task<(int, string, EmailChangeTokenResponseModel?)> UserInitiateEmailChangeAsync(string username, string confirmationCode)
        {
            // FIND USER | Try to find user in database. We check for valid username in controller, so should always find an account.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Initiate email change failed: user not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.", null);
            }

            // VALIDATE USER-SUBMITTED CONFIRMATION CODE | Call email code service method to validate, which logs internally.
            if (!_emailCodeService.ValidateSubmittedCode(userAccount.Email, confirmationCode, ConfirmationCodeData.CodeContext.ChangeEmail))
            {
                return (401, "Invalid or expired confirmation code.", null);
            }

            // ENSURE USER IS ALLOWED TO CHANGE EMAIL | Deny change if email was changed less than 30 days ago.
            if (DateTime.UtcNow - userAccount.LastEmailChangedTime < TimeSpan.FromDays(30))
            {
                _logger.LogInformation($"Initiate email change failed: cannot change email less than 30 days since last change (username: {username})");
                return (493, "Cannot change email within 30 days of previous change.", null);
            }

            // SUCCESS: GENERATE RESPONSE | On successful request, consume confirmation code and generate short-duration email change token.
            var response = new EmailChangeTokenResponseModel()
            {
                Username = userAccount.Username,
                EmailChangeToken = _tokenService.GenerateAccessToken(userAccount.Username, TokenService.Roles.ChangeEmail, durationMinutes: 5)
            };

            _logger.LogInformation($"User initiate email change successful (username: {username})");
            return (200, "Initiate email change successful.", response);
        }

        public async Task<(int, string)> UserSubmitNewEmailAsync(string username, string newEmail)
        {
            // FIND USER | Try to find user in database. Return false if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Submit new email failed: account for username stored in email change token not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.");
            }

            // VERIFY NEW EMAIL IS NOT THE SAME AS PREVIOUS
            if (newEmail == userAccount.Email)
            {
                _logger.LogInformation($"Submit new email failed: new email cannot be the same as old email (username: {username}" +
                    $" | existing email: {userAccount.Email} | new email: {newEmail})");
                return (409, "New email cannot be the same as old email.");
            }

            // VERIFY THAT EMAIL IS NOT ALREADY IN USE | Deny change with GENERIC ERROR MESSAGE if email is in use by another account.
            var existingAccount = await _databaseService.GetOneByEmailAsync(newEmail);
            if (existingAccount != null)
            {
                // If email is in use but account email was never verified and was created >30 days ago, delete it (zombie).
                if (!userAccount.IsEmailVerified && DateTime.UtcNow - userAccount.AccountCreatedTime > TimeSpan.FromDays(30))
                {
                    await _databaseService.DeleteOneByEmailAsync(userAccount.Email);
                }
                else
                {
                    // Return a GENERIC error message.
                    _logger.LogInformation($"Submit new email failed: email already in use (username: {username}" +
                        $" | existing email: {userAccount.Email} | new email: {newEmail})");
                    return (500, "An unexpected error occured during new email submission, please try again.");
                }
            }

            // SUCCESS: ADD PENDING NEW EMAIL TO DOCUMENT | Update pending new email field, but do NOT set last changed time or logout yet.
            userAccount.PendingNewEmail = newEmail;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            // SEND CONFIRMATION CODE TO NEW EMAIL | Do not await, because sending email can take a while.
            _ = _emailCodeService.SendCodeToEmailAsync(newEmail, ConfirmationCodeData.CodeContext.EmailVerification);

            _logger.LogInformation($"User submit new email successful (username: {username} | current email: {userAccount.Email} | new email: {newEmail})");
            return (200, "Submit new email successful.");
        }

        #endregion

        #region Public: User account online status tracking

        public async Task<(int, string)> UserPingInLauncherAsync(string username)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Ping in launcher failed: account for username stored in access token not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.");
            }

            // Update in launcher status and time for this account in the database.
            userAccount.InLauncherStatus = true;
            userAccount.LastInLauncherTime = DateTime.UtcNow;
            await _databaseService.UpdateOneByUsernameAsync(username, userAccount);

            _logger.LogInformation($"User ping in launcher successful (username: {username})");
            return (204, "");
        }

        public async Task<(int, string)> UserNotifyLauncherExitAsync(string username)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation($"Notify launcher exit failed: account for username stored in access token not found in database (username: {username})");
                return (404, "Failed to find user account for the provided username.");
            }

            // Update in launcher status and set time of exit to last in launcher time.
            userAccount.InLauncherStatus = false;
            userAccount.LastInLauncherTime = DateTime.UtcNow;
            await _databaseService.UpdateOneByUsernameAsync(username, userAccount);

            _logger.LogInformation($"User notify launcher exit successful (username: {username})");
            return (204, "");
        }

        #endregion

        #region Private: Utility

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
                return count >= 3;
            }

            // Return false if there is no entry for the passed-in username.
            return false;
        }

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
            _failedLoginAttempts[username] = [ DateTime.UtcNow ];
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
