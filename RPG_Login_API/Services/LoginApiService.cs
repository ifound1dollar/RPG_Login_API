using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using RPG_Login_API.Configuration;
using RPG_Login_API.Data;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;
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
        // TODO: ENSURE THERE ARE NO THREAD SAFETY CONCERNS WITH THESE CONTAINERS (we only await DatabaseService)
        private readonly Dictionary<string, DateTime> _tokenGuidBlacklist = [];     // Stores invalidated access tokens with expiration
        private readonly Dictionary<string, ConfirmationCodeData> _confirmationCodes = [];  // Stores temporary confirmation codes with expiration



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

        public async Task<LoginResponseModel?> UserLoginFromRefreshAsync(string refreshTokenString)
        {
            LoginResponseModel response;

            // PARSE TOKEN | Try to retrieve username and token object from the passed-in token string.
            if (!_tokenService.TryReadUsernameFromTokenString(refreshTokenString, out var username)) return null;

            // FIND USER | Try to find user in database. Return null if we cannot find by username.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation("Token user not found in database (username: {username})", username);
                return null;
            }

            // COMPARE TOKEN | Now that we have found a valid user, compare the stored refresh token with this refresh token.
            if (!HashUtility.CompareRefreshTokenToHash(refreshTokenString, userAccount.RefreshTokenHash))
            {
                _logger.LogInformation("Passed-in token does not match token in database (username: {username})", username);
                return null;
            }

            // ACTUALLY VALIDATE TOKEN | If token matches stored token in database, validate it (primarily checks expiration).
            if (!_tokenService.ValidateToken(refreshTokenString))
            {
                _logger.LogInformation("Refresh token failed validation, may be expired (username: {username})", username);

                // This means the token in the database is invalid, so remove it.
                userAccount.RefreshTokenHash = string.Empty;
                await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);
                return null;
            }

            // GENERATE RESPONSE | Finally, token is confirmed fully valid so determine login response based on account state.
            if (!userAccount.IsEmailVerified || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                int statusCode = (!userAccount.IsEmailVerified) ? 1 : 2;   // 1 if unconfirmed, else 2 for password reset
                response = new LoginResponseModel()
                {
                    LoginStatusCode = statusCode,      
                    RefreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(username, statusCode, durationMinutes: 15)
                };
            }
            else
            {
                // Else account state is good, so return full login with refresh token AND access token. Also update access tokens map.
                response = new LoginResponseModel()
                {
                    LoginStatusCode = 0,
                    RefreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(username, 0, durationMinutes: 15)
                };
            }

            // UPDATE DATABASE | After token generation, update document in database with newly-generated HASHED refresh token.
            string hashedToken = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            userAccount.RefreshTokenHash = hashedToken;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);



            // FINALLY, log success and return login response model.
            _logger.LogInformation("User refresh login successful (username: {username}) with login code {responseCode}",
                username, response.LoginStatusCode);
            return response;
        }

        public async Task<LoginResponseModel?> UserLoginAsync(string username, string password)
        {
            // TODO: ADD FAILED LOGIN IN-MEMORY TRACKER DICTIONARY, AND ASSOCIATED LOGIC HERE

            LoginResponseModel response;

            // FIND USER | Try to find user in database. Return null if we cannot find by username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(username);
                if (userAccount == null)
                {
                    _logger.LogInformation("Username/email not found in database (input: {username})", username);
                    return null;
                }
            }

            // COMPARE PASSWORD | If user found, compare password using PasswordUtility class. Return null if password mismatch.
            if (!HashUtility.ComparePasswordToHash(password, userAccount.PasswordHash))
            {
                _logger.LogInformation("User-submitted password does not match account's stored password (username: {username})", username);
                return null;
            }

            // GENERATE RESPONSE | Determine how we will process login based on account state.
            if (!userAccount.IsEmailVerified || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                int statusCode = (!userAccount.IsEmailVerified) ? 1 : 2;   // 1 if unconfirmed, else 2 for password reset
                response = new LoginResponseModel()
                {
                    LoginStatusCode = statusCode,
                    RefreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(username, statusCode, durationMinutes: 15)
                };
            }
            else
            {
                // Else account state is good, so return full login with refresh token AND access token. Also update access tokens map.
                response = new LoginResponseModel()
                {
                    LoginStatusCode = 0,
                    RefreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30),
                    AccessToken = _tokenService.GenerateAccessToken(username, 0, durationMinutes: 15)
                };
            }

            // UPDATE DATABASE | After token generation, update document in database with newly-generated refresh token.
            string hashedToken = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            userAccount.RefreshTokenHash = hashedToken;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);



            // FINALLY, log success and return login response model.
            _logger.LogInformation("User login successful (username: {username}) with login code {responseCode}",
                username, response.LoginStatusCode);
            return response;
        }

        public async Task<LoginResponseModel?> UserRegisterAsync(string username, string email, string password)
        {
            // ENSURE UNIQUE USERNAME/EMAIL | Query database for any accounts with matching username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount != null)
            {
                _logger.LogInformation("User-submitted username already in use (username: {username})", username);
                return null;
            }
            userAccount = await _databaseService.GetOneByEmailAsync(username);
            if (userAccount != null)
            {
                _logger.LogInformation("User-submitted email already in use (email: {email})", email);
                return null;
            }

            // CREATE NEW ACCOUNT MODEL | Username and email are unique, so create a new user document.
            string refreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30);
            UserAccountModel userAccountModel = new()
            {
                Username = username,
                Email = email,
                PasswordHash = HashUtility.GenerateNewPasswordHash(password),
                RefreshTokenHash = HashUtility.GenerateNewRefreshTokenHash(refreshToken)    // Store hashed token in database.
                // ObjectId is auto generated, and other values are left default.
            };
            await _databaseService.InsertOneAsync(userAccountModel);

            // GENERATE RESPONSE | Finally, after account creation, generate response and return.
            var response = new LoginResponseModel()
            {
                LoginStatusCode = 1,        // New accounts must always confirm email (code 1).
                RefreshToken = refreshToken,
                AccessToken = _tokenService.GenerateAccessToken(username, 1, durationMinutes: 15)
            };



            // FINALLY, log success and return login response model.
            _logger.LogInformation("New user registration successful (username: {username}, email: {email})", username, email);
            return response;
        }

        public async Task UserLogoutAsync(string username, string tokenGuid)
        {
            // Access token validation is performed in controller. We know the caller is the valid user for this account.

            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation("Token user not found in database (username: {username})", username);
                return;
            }

            // BLACKLIST OLD ACCESS TOKEN | Add old token's GUID to blacklist, which expires at token default duration (max).
            _tokenGuidBlacklist.Add(tokenGuid, DateTime.UtcNow.AddMinutes(15));

            // UPDATE DATABASE | Remove the stored refresh token from the user account document, then update database.
            userAccount.RefreshTokenHash = string.Empty;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);



            // FINALLY, log success and implicitly return.
            _logger.LogInformation("User successfully logged out (username: {username})", username);
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
                    _logger.LogInformation("Username/email not found in database (input: {username})", usernameOrEmail);
                    return;
                }
            }

            // PREVENT NEW CODE SPAM | Ensure there is not an existing confirmation code for this account created less than 60 seconds ago.
            if (_confirmationCodes.TryGetValue(usernameOrEmail, out var codeData))
            {
                // If existing code was created less than 60 seconds ago, log error and return.
                if ((DateTime.UtcNow - codeData.Created) < TimeSpan.FromMinutes(1))
                {
                    _logger.LogInformation("Cannot generate new confirmation code for account within 60 seconds of previous.");
                    return;
                }
            }

            // CREATE CODE AND STORE LOCALLY | Generate a random alphanumeric code and add to container of confirmation codes.

            // TODO: REPLACE TEMPORARY IMPLEMENTATION HERE WITH LEGITIMATE RANDOM CODE AND ACTUALLY SEND TO EMAIL, USING CUSTOM SERVICE
            string code = "000000";
            _confirmationCodes[userAccount.Username] = new ConfirmationCodeData(code, durationMinutes: 5);  // Replace if existing.
            // SEND TO EMAIL



            // FINALLY, log success and implicitly return.
            _logger.LogInformation("User successfully requested a confirmation code (username: {username})", userAccount.Username);
        }

        public async Task<LoginResponseModel?> UserVerifyAccountEmailAsync(string username, string confirmationCode)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation("Token user not found in database (username: {username})", username);
                return null;
            }

            // CHECK FOR AND VALIDATE EXISTING CODE | Try to find stored code in dictionary, returning null if does not exist or expired.
            if (!_confirmationCodes.TryGetValue(username, out var codeData))
            {
                _logger.LogInformation("User tried to verify account email without an existing local confirmation code (username: {username}",
                    username);
                return null;
            }
            if (codeData.Expiration < DateTime.UtcNow)
            {
                _logger.LogInformation("User tried to verify account email with an expired confirmation code (username: {username})",
                    username);
                _confirmationCodes.Remove(username);    // Remove expired code data.
                return null;
            }

            // COMPARE CONFIRMATION CODES | Compare user-provided code with stored code, returning null if mismatch.
            if (codeData.Code != confirmationCode)
            {
                // Increment code counter, which is used to invalidate the code after 3 failed code submit attempts.
                codeData.AttemptCounter++;
                if (codeData.AttemptCounter >= 3)
                {
                    // If counter now >= 3, invalidate code by removing from local container.
                    _confirmationCodes.Remove(userAccount.Username);
                }
                return null;
            }

            // SUCCESS: GENERATE RESPONSE | On successful email verification, re-generate both refresh and access token (like login).
            _confirmationCodes.Remove(username);    // Consume code.
            var response = new LoginResponseModel()
            {
                LoginStatusCode = 0,        // Always full success status after successful verification.
                RefreshToken = _tokenService.GenerateRefreshToken(username, durationDays: 30),
                AccessToken = _tokenService.GenerateAccessToken(username, 1, durationMinutes: 15)
            };

            // UPDATE DATABASE | After token generation, update document in database with newly-generated refresh token.
            string hashedToken = HashUtility.GenerateNewRefreshTokenHash(response.RefreshToken);
            userAccount.RefreshTokenHash = hashedToken;
            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);



            // FINALLY, log success and return login response model.
            _logger.LogInformation("User email verification successful (username: {username})", username);
            return response;
        }

        public async Task<PasswordResetTokenResponseModel?> UserRequestPasswordResetAsync(string usernameOrEmail, string confirmationCode)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username or email.
            var userAccount = await _databaseService.GetOneByUsernameAsync(usernameOrEmail);
            if (userAccount == null)
            {
                userAccount = await _databaseService.GetOneByEmailAsync(usernameOrEmail);
                if (userAccount == null)
                {
                    _logger.LogInformation("Username/email not found in database (input: {username})", usernameOrEmail);
                    return null;
                }
            }

            // CHECK FOR AND VALIDATE EXISTING CODE | Try to find stored code in dictionary, returning null if does not exist or expired.
            if (!_confirmationCodes.TryGetValue(userAccount.Username, out var codeData))
            {
                _logger.LogInformation("User requested password reset without an existing local confirmation code (username: {username}",
                    userAccount.Username);
                return null;
            }
            if (codeData.Expiration < DateTime.UtcNow)
            {
                _logger.LogInformation("User requested password reset with an expired confirmation code (username: {username})",
                    userAccount.Username);
                _confirmationCodes.Remove(userAccount.Username);    // Remove expired code data.
                return null;
            }

            // COMPARE CONFIRMATION CODES | Compare user-provided code with stored code, returning null if mismatch.
            if (codeData.Code != confirmationCode)
            {
                // Increment code counter, which is used to invalidate the code after 3 failed code submit attempts.
                codeData.AttemptCounter++;
                if (codeData.AttemptCounter >= 3)
                {
                    // If counter now >= 3, invalidate code by removing from local container.
                    _confirmationCodes.Remove(userAccount.Username);
                }
                return null;
            }

            // SUCCESS: GENERATE RESPONSE | On successful request, consume confirmation code and generate short-duration reset token.
            _confirmationCodes.Remove(userAccount.Username);    // Consume code.
            var response = new PasswordResetTokenResponseModel()
            {
                ResetToken = _tokenService.GenerateAccessToken(userAccount.Username, 2, durationMinutes: 5)
            };

            // FINALLY, log success and return password reset token response model.
            _logger.LogInformation("User request password reset successful (username: {username})", userAccount.Username);
            return response;
        }

        public async Task<ResetPasswordResponseModel?> UserResetPasswordAsync(string username, string tokenGuid, string newPassword)
        {
            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await _databaseService.GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation("Token user not found in database (username: {username})", username);
                return null;
            }

            // VALID USER: VERIFY NEW PASSWORD DOES NOT MATCH PREVIOUS
            if (HashUtility.ComparePasswordToHash(newPassword, userAccount.PasswordHash))
            {
                _logger.LogInformation("User tried to reset password to same as old password (username: {username})", username);
                return null;
            }
            
            // GENERATE NEW PASSWORD HASH AND RESPONSE
            string passwordHash = HashUtility.GenerateNewPasswordHash(newPassword);
            var response = new ResetPasswordResponseModel()
            {
                Success = true
            };

            // UPDATE DATABASE AND LOG OUT USER | Update password fields in user account document, then invalidate both tokens.
            userAccount.PasswordHash = passwordHash;
            userAccount.DoesPasswordNeedReset = false;      // Always reset to false regardless of whether reset was forced.
            userAccount.RefreshTokenHash = string.Empty;
            _tokenGuidBlacklist.Add(tokenGuid, DateTime.UtcNow.AddMinutes(5));  // Make blacklist expire at maximum duration to be safe.

            await _databaseService.UpdateOneByUsernameAsync(userAccount.Username, userAccount);



            // FINALLY, log success and return reset password response model.
            _logger.LogInformation("User reset password successful (username: {username})", username);
            return response;
        }


        #endregion

    }
}
