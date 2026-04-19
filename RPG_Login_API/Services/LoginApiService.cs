using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
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
        // Stores temporary confirmation codes with expiration, use a concurrent dictionary for async safety.
        private readonly ConcurrentDictionary<string, ConfirmationCodeData> _confirmationCodes = [];



        private readonly IDatabaseService _databaseService;
        private readonly ITokenService _tokenService;
        private readonly ILogger _logger;

        public LoginApiService(IDatabaseService databaseService, ITokenService tokenService, ILogger<LoginApiService> logger)
        {
            _databaseService = databaseService;
            _tokenService = tokenService;

            _logger = logger;
        }





        #region (Interface) Public: User Account Access API Logic

        public async Task<LoginResponseModel> UserLoginFromRefreshAsync(string refreshTokenString)
        {
            // PARSE TOKEN | Try to retrieve username and token object from the passed-in token string.
            if (!_tokenService.TryReadUsernameFromTokenString(refreshTokenString, out var username))
            {
                throw new BadHttpRequestException($"Client refresh login failed: malformed (unreadable) refresh token in request");
            }

            // FIND USER | Try to find user in database. Return null if we cannot find by username.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                throw new KeyNotFoundException($"Client refresh login failed: account for username stored in refresh token not found in database (username: {username})");
            }

            // COMPARE TOKEN | Now that we have found a valid user, compare the stored refresh token with this refresh token.
            if (!HashUtility.CompareRefreshTokenToHash(refreshTokenString, userAccount.RefreshTokenHash))
            {
                throw new UnauthorizedAccessException($"Client refresh login failed: user-provided token does not match token in database (username: {username})");
            }

            // ACTUALLY VALIDATE TOKEN | If token matches stored token in database, validate it (checks expiration and client GUID).
            if (!_tokenService.ValidateToken(refreshTokenString))
            {
                // This means the token in the database is invalid, so remove it.
                userAccount.RefreshTokenHash = string.Empty;
                await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

                throw new UnauthorizedAccessException($"Client refresh login failed: token is expired or found mismatched client GUID (username: {username})");
            }

            // GENERATE RESPONSE | Finally, token is confirmed fully valid so determine login response based on account state.
            LoginResponseModel response;
            if (!userAccount.IsEmailVerified || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                int statusCode = (!userAccount.IsEmailVerified) ? 1 : 2;   // 1 if unconfirmed, else 2 for password reset
                response = new LoginResponseModel()
                {
                    Username = userAccount.Username,
                    LoginStatusCode = statusCode,
                    RefreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(username, statusCode, durationMinutes: 15),
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
                };

                // Unconfirmed or reset required will need a new confirmation code.
                GenerateAndSendConfirmationCode(userAccount.Username);
            }
            else
            {
                // Else account state is good, so return full login with refresh token AND access token.
                response = new LoginResponseModel()
                {
                    Username = userAccount.Username,
                    LoginStatusCode = 0,
                    RefreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(username, 0, durationMinutes: 15),
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
                };
            }

            // UPDATE DATABASE | After token generation, update document in database with newly-generated HASHED refresh token.
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            userAccount.LastLoginTime = DateTime.UtcNow;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            return response;
        }

        public async Task<LoginResponseModel> UserLoginAsync(string usernameOrEmail, string password)
        {
            // TODO: ADD FAILED LOGIN IN-MEMORY TRACKER DICTIONARY, AND ASSOCIATED LOGIC HERE

            // FIND USER | Try to find user in database. Return null if we cannot find by username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(usernameOrEmail);
                if (userAccount == null)
                {
                    throw new KeyNotFoundException($"Client login failed: user not found in database (username/email: {usernameOrEmail})");
                }
            }

            // COMPARE PASSWORD | If user found, compare password using PasswordUtility class. Return null if password mismatch.
            if (!HashUtility.ComparePasswordToHash(password, userAccount.PasswordHash))
            {
                throw new UnauthorizedAccessException($"Client login failed: user-provided password does not match account's stored password (username: {userAccount.Username})");
            }

            // SUCCESS: GENERATE RESPONSE | Determine how we will process login based on account state.
            LoginResponseModel response;
            if (!userAccount.IsEmailVerified || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                int statusCode = (!userAccount.IsEmailVerified) ? 1 : 2;   // 1 if unconfirmed, else 2 for password reset
                response = new LoginResponseModel()
                {
                    Username = userAccount.Username,
                    LoginStatusCode = statusCode,
                    RefreshToken = _tokenService.GenerateRefreshToken(usernameOrEmail, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(usernameOrEmail, statusCode, durationMinutes: 15),
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
                };

                // Unconfirmed or reset required will need a new confirmation code.
                GenerateAndSendConfirmationCode(userAccount.Username);
            }
            else
            {
                // Else account state is good, so return full login with refresh token AND access token. Also update access tokens map.
                response = new LoginResponseModel()
                {
                    Username = userAccount.Username,
                    LoginStatusCode = 0,
                    RefreshToken = _tokenService.GenerateRefreshToken(usernameOrEmail, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(usernameOrEmail, 0, durationMinutes: 15),
                    AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
                };
            }

            // UPDATE DATABASE | After token generation, update document in database with newly-generated refresh token.
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            userAccount.LastLoginTime = DateTime.UtcNow;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            return response;
        }

        public async Task<LoginResponseModel> UserRegisterAsync(string username, string email, string password)
        {
            // ENSURE USERNAME AND EMAIL NOT ALREADY IN USE | Query database for any existing account with matching username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount != null)
            {
                throw new ArgumentException($"Client registration failed: user-provided username already in use (username: {username})");
            }
            userAccount = await _databaseService.GetOneByEmailAsync(username);
            if (userAccount != null)
            {
                throw new ArgumentException($"Client registration failed: user-provided email already in use (email: {email})");
            }

            // CREATE NEW ACCOUNT MODEL | Username and email are unique (verified in controller), so create a new user document.
            string refreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30);
            UserAccountModel userAccountModel = new()
            {
                Username = username,
                Email = email,
                AccountCreatedTime = DateTime.UtcNow,
                PasswordHash = HashUtility.GenerateNewPasswordHash(password),
                RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(refreshToken),   // Store hashed token in database.
                LastLoginTime = DateTime.UtcNow,
                LastPasswordChangedTime = DateTime.UtcNow,
                LastUsernameChangedTime = DateTime.UtcNow,
                // ObjectId is auto generated, and other values are left default.
            };
            await _databaseService.InsertOneAsync(userAccountModel);

            // GENERATE RESPONSE | Finally, after account creation, generate response and return.
            var response = new LoginResponseModel()
            {
                Username = username,
                LoginStatusCode = 1,        // New accounts must always confirm email (code 1).
                RefreshToken = refreshToken,
                AccessToken = _tokenService.GenerateAccessToken(username, 1, durationMinutes: 15),
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
            };

            // GENERATE EMAIL VERIFICATION CODE | Generate and send email verification code to user's email immediately.
            GenerateAndSendConfirmationCode(userAccountModel.Username);

            return response;
        }

        public async Task UserLogoutAsync(string username)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                throw new KeyNotFoundException($"Client logout failed: account for username stored in access token not found in database (username: {username})");
            }

            // UPDATE DATABASE | Remove the stored refresh token from the user account document, then update database.
            userAccount.RefreshTokenHash = string.Empty;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);
            
        }

        public async Task UserSendConfirmationCodeAsync(string usernameOrEmail)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(usernameOrEmail);
                if (userAccount == null)
                {
                    throw new KeyNotFoundException($"Client confirmation code request failed: user not found in database (username/email: {usernameOrEmail})");
                }
            }

            // PREVENT NEW CODE SPAM | Ensure there is not an existing confirmation code for this account created less than 60 seconds ago.
            if (_confirmationCodes.TryGetValue(usernameOrEmail, out var codeData))
            {
                // If existing code was created less than 60 seconds ago, log error and return.
                if ((DateTime.UtcNow - codeData.Created) < TimeSpan.FromMinutes(1))
                {
                    throw new InvalidOperationException($"Client confirmation code request failed: cannot generate new code within 60 seconds of previous (username/email: {usernameOrEmail})");
                }
            }

            // CREATE CODE AND STORE LOCALLY | Generate a random alphanumeric code and add to container of confirmation codes.
            GenerateAndSendConfirmationCode(userAccount.Username);
            
        }

        public async Task<LoginResponseModel> UserVerifyAccountEmailAsync(string username, string confirmationCode)
        {
            // FIND USER | Try to find user in database. We check for valid username in controller, so should always find an account.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                throw new KeyNotFoundException($"Client email verification failed: account for username stored in access token not found in database (username: {username})");
            }

            // CHECK FOR AND VALIDATE EXISTING CODE | Try to find stored code in dictionary, returning null if does not exist or expired.
            if (!_confirmationCodes.TryGetValue(username, out var codeData))
            {
                throw new UnauthorizedAccessException($"Client email verification failed: no local confirmation code found for this user (username: {username})");
            }
            if (codeData.Expiration < DateTime.UtcNow)
            {
                // Remove expired code data, discarding out variable because it is not needed.
                _confirmationCodes.Remove(username, out _);

                throw new UnauthorizedAccessException($"Client email verification failed: expired user-provided confirmation code (username: {username})");
            }

            // COMPARE CONFIRMATION CODES | Compare user-provided code with stored code, returning null if mismatch.
            if (codeData.Code != confirmationCode)
            {
                // Increment code counter, which is used to invalidate the code after 3 failed code submit attempts.
                codeData.AttemptCounter++;
                if (codeData.AttemptCounter >= 3)
                {
                    // If counter now >= 3, invalidate code by removing from local container.
                    _confirmationCodes.Remove(username, out _);
                }

                throw new UnauthorizedAccessException($"Client email verification failed: invalid confirmation code submitted by user (username: {username})");
            }

            // SUCCESS: GENERATE LOGIN RESPONSE | On successful email verification, re-generate both refresh and access token (like login).
            _confirmationCodes.Remove(username, out _);     // Consume code.
            var response = new LoginResponseModel()
            {
                Username = username,
                LoginStatusCode = 0,        // Always full success status after successful verification.
                RefreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30),
                AccessToken = _tokenService.GenerateAccessToken(username, 1, durationMinutes: 15),
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
            };

            // UPDATE DATABASE | After token generation, update document in database with newly-generated refresh token.
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            userAccount.IsEmailVerified = true;
            userAccount.LastLoginTime = DateTime.UtcNow;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            return response;
        }

        public async Task<PasswordResetTokenResponseModel> UserRequestPasswordResetAsync(string usernameOrEmail, string confirmationCode)
        {
            // FIND USER | Try to find user in database. We check for valid username/email in controller, so should always find an account.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(usernameOrEmail);
                if (userAccount == null)
                {
                    throw new KeyNotFoundException($"Client request password reset failed: user not found in database (username/email: {usernameOrEmail})");
                }
            }

            // CHECK FOR AND VALIDATE EXISTING CODE | Try to find stored code in dictionary, returning null if does not exist or expired.
            if (!_confirmationCodes.TryGetValue(userAccount.Username, out var codeData))
            {
                throw new UnauthorizedAccessException($"Client request password reset failed: no local confirmation code found for this user (username: {userAccount.Username})");
            }
            if (codeData.Expiration < DateTime.UtcNow)
            {
                // Remove expired code data, discarding out variable because it is not needed.
                _confirmationCodes.Remove(userAccount.Username, out _);

                throw new UnauthorizedAccessException($"Client request password reset failed: expired user-provided confirmation code (username: {userAccount.Username})");
            }

            // COMPARE CONFIRMATION CODES | Compare user-provided code with stored code, returning null if mismatch.
            if (codeData.Code != confirmationCode)
            {
                // Increment code counter, which is used to invalidate the code after 3 failed code submit attempts.
                codeData.AttemptCounter++;
                if (codeData.AttemptCounter >= 3)
                {
                    // If counter now >= 3, invalidate code by removing from local container.
                    _confirmationCodes.Remove(userAccount.Username, out _);
                }

                throw new UnauthorizedAccessException($"Client request password reset failed: invalid confirmation code submitted by user (username: {userAccount.Username})");
            }

            // SUCCESS: GENERATE RESPONSE | On successful request, consume confirmation code and generate short-duration reset token.
            _confirmationCodes.Remove(userAccount.Username, out _);
            var response = new PasswordResetTokenResponseModel()
            {
                Username = userAccount.Username,
                ResetToken = _tokenService.GenerateAccessToken(userAccount.Username, 2, durationMinutes: 5)
            };

            return response;
        }

        public async Task UserResetPasswordAsync(string username, string newPassword)
        {
            // FIND USER | Try to find user in database. Return false if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                throw new KeyNotFoundException($"Client password reset failed: account for username stored in reset token not found in database (username: {username})");
            }

            // ENSURE USER IS ALLOWED TO CHANGE PASSWORD | If trying to change less than 24 hours since last change, deny change.
            if (!userAccount.DoesPasswordNeedReset && DateTime.UtcNow - userAccount.LastPasswordChangedTime < TimeSpan.FromDays(1))
            {
                // Only check time if password reset is NOT enforced; if enforced, always allow reset.

                throw new InvalidOperationException($"Client password reset failed: cannot change password less than 24 hours since last change (username: {username})");
            }

            // VALID USER: VERIFY NEW PASSWORD DOES NOT MATCH PREVIOUS
            if (HashUtility.ComparePasswordToHash(newPassword, userAccount.PasswordHash))
            {
                throw new ArgumentException($"Client password reset failed: new password cannot be the same as old password (username: {username})");
            }
            
            // GENERATE NEW PASSWORD HASH AND UPDATE DOCUMENT | Update various fields in account document now that password is reset.
            userAccount.PasswordHash = HashUtility.GenerateNewPasswordHash(newPassword);
            userAccount.DoesPasswordNeedReset = false;      // Always reset to false regardless of whether reset was forced.
            userAccount.IsEmailVerified = true;             // Reset requires email anyway, so implicitly verify email.
            userAccount.LastPasswordChangedTime = DateTime.UtcNow;

            // LOG OUT USER AND ACTUALLY UPDATE DATABASE | Invalidate user's refresh token, then update database.
            userAccount.RefreshTokenHash = string.Empty;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);

        }

        public async Task<LoginResponseModel> UserChangeUsernameAsync(string existingUsername, string newUsername)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(existingUsername);
            if (userAccount == null)
            {
                throw new KeyNotFoundException($"Client username change failed: account for username stored in access token not found in database (username: {existingUsername})");
            }

            // ENSURE USER IS ALLOWED TO CHANGE USERNAME | Deny change if username was changed less than 30 days ago.
            if (DateTime.UtcNow - userAccount.LastUsernameChangedTime < TimeSpan.FromDays(30))
            {
                throw new InvalidOperationException($"Client username change failed: cannot change username less than 30 days since last change (existing username: {existingUsername})");
            }

            // RE-LOGIN USER | Now that account state has changed, re-login user to generate new tokens with new username.
            var response = new LoginResponseModel()
            {
                Username = newUsername,
                LoginStatusCode = 0,        // This endpoint can only be accessed by a full-access token, so make full access again.
                RefreshToken = _tokenService.GenerateRefreshToken(newUsername, durationDays: 30),
                AccessToken = _tokenService.GenerateAccessToken(newUsername, 0, durationMinutes: 15),
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15)
            };

            // UPDATE DOCUMENT AND DATABASE | Update username and last username changed time in document, then update database.
            userAccount.RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            userAccount.LastLoginTime = DateTime.UtcNow;
            userAccount.Username = newUsername;
            userAccount.LastUsernameChangedTime = DateTime.UtcNow;
            await _databaseService.UpdateOneByUsernameAsync(existingUsername, userAccount);     // Query by old username.

            return response;
        }

        #endregion

        #region Private: Utility

        private void GenerateAndSendConfirmationCode(string username)
        {
            // TODO: REPLACE TEMPORARY IMPLEMENTATION HERE WITH LEGITIMATE RANDOM CODE AND ACTUALLY SEND TO EMAIL, USING CUSTOM SERVICE
            string code = "00000000";
            _confirmationCodes[username] = new ConfirmationCodeData(code, durationMinutes: 5);  // Replace if existing.
            // SEND TO EMAIL
        }

        #endregion

    }
}
