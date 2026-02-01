using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using RPG_Login_API.Configuration;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;
using RPG_Login_API.Utility;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace RPG_Login_API.Services
{
    public class LoginApiService
    {
        // Private in-memory containers for volatile data (ex. access tokens, login attempt tracking).
        private readonly Dictionary<string, DateTime> _tokenGuidBlacklist = [];     // Stores invalidated access tokens with expiration



        private readonly IMongoCollection<UserAccountModel> userAccountsCollection;
        private readonly ILogger _logger;
        private readonly TokenService _tokenService;

        public LoginApiService(IOptions<DatabaseSettings> settings, ILogger<LoginApiService> logger, TokenService tokenService)
        {
            // TODO: MAKE DATABASE SERVICE ITS OWN CLASS, AND PASS INTO CONSTRUCTOR HERE VIA DEPENDENCY INJECTION

            // Create a new MongoClient instance from the connecting string defined in secrets.json.
            // Data pulled from secrets.json is stored in a DatabaseSettings singleton on app build in Program.cs.
            MongoClient client = new(settings.Value.ConnectionString);

            // Retrieve the database defined in secrets.json.
            IMongoDatabase database = client.GetDatabase(settings.Value.DatabaseName);

            // Finally, instantiate the collection using the name defined in secrets.json.
            userAccountsCollection = database.GetCollection<UserAccountModel>(settings.Value.UserAccountsCollectionName);

            _logger = logger;
            _tokenService = tokenService;
        }

        /// <summary>
        /// This method calls a basic MongoDB function using the database connection, which fails if
        ///  the connection is unsuccessful. Returns true if successful, false if failure.
        /// </summary>
        /// <returns> True if the database connection is valid, false otherwise. </returns>
        public bool CheckConnectionStatus()
        {
            try
            {
                userAccountsCollection.Database.Client.ListDatabaseNames();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return false;
            }
        }





        #region Public: User Account Access API Logic

        public async Task<LoginResponseModel?> UserLoginFromRefreshAsync(string refreshTokenString)
        {
            LoginResponseModel response;

            // PARSE TOKEN | Try to retrieve username and token object from the passed-in token string.
            if (!_tokenService.TryReadUsernameFromTokenString(refreshTokenString, out var username)) return null;

            // FIND USER | Try to find user in database. Return null if we cannot find by username.
            var userAccount = await GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation("Token user not found in database (username: {username})", username);
                return null;
            }

            // COMPARE TOKEN | Now that we have found a valid user, compare the stored refresh token with this refresh token.
            if (!_tokenService.CompareTokens(refreshTokenString, userAccount.RefreshToken))
            {
                _logger.LogInformation("Passed-in token does not match token in database (username: {username})", username);
                return null;
            }

            // ACTUALLY VALIDATE TOKEN | If token matches stored token in database, validate it (primarily checks expiration).
            if (!_tokenService.ValidateToken(refreshTokenString))
            {
                _logger.LogInformation("Refresh token failed validation, may be expired (username: {username})", username);
                return null;
            }

            // GENERATE RESPONSE | Finally, token is confirmed fully valid so determine login response based on account state.
            if (!userAccount.IsEmailConfirmed || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                int statusCode = (!userAccount.IsEmailConfirmed) ? 1 : 2;   // 1 if unconfirmed, else 2 for password reset
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
            // TODO: STORE REFRESH TOKEN AS HASH INSTEAD OF RAW, FOR SECURITY REASONS
            userAccount.RefreshToken = response.RefreshToken;
            await UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation("User refresh login successful (username: {username}) with login code {responseCode}",
                username, response.LoginStatusCode);
            return response;
        }

        public async Task<LoginResponseModel?> UserLoginAsync(string username, string password)
        {
            // TODO: ADD FAILED LOGIN IN-MEMORY TRACKER DICTIONARY, AND ASSOCIATED LOGIC HERE

            LoginResponseModel response;

            // FIND USER | Try to find user in database. Return null if we cannot find by username or email.
            var userAccount = await GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                userAccount = await GetOneByEmailAsync(username);
                if (userAccount == null)
                {
                    _logger.LogInformation("Username/email not found in database (input: {username})", username);
                    return null;
                }
            }

            // COMPARE PASSWORD | If user found, compare password using PasswordUtility class. Return null if password mismatch.
            if (!PasswordUtility.ComparePasswordToHash(password, userAccount.PasswordHash))
            {
                _logger.LogInformation("User-submitted password does not match account's stored password (username: {username})", username);
                return null;
            }

            // GENERATE RESPONSE | Determine how we will process login based on account state.
            if (!userAccount.IsEmailConfirmed || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                int statusCode = (!userAccount.IsEmailConfirmed) ? 1 : 2;   // 1 if unconfirmed, else 2 for password reset
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
            // TODO: STORE REFRESH TOKEN AS HASH INSTEAD OF RAW, FOR SECURITY REASONS
            userAccount.RefreshToken = response.RefreshToken;
            await UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation("User login successful (username: {username}) with login code {responseCode}",
                username, response.LoginStatusCode);
            return response;
        }

        public async Task<LoginResponseModel?> UserRegisterAsync(string username, string email, string password)
        {
            // ENSURE UNIQUE USERNAME/EMAIL | Query database for any accounts with matching username or email.
            var userAccount = await GetOneByUsernameAsync(username);
            if (userAccount != null)
            {
                _logger.LogInformation("User-submitted username already in use (username: {username})", username);
                return null;
            }
            userAccount = await GetOneByEmailAsync(username);
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
                PasswordHash = PasswordUtility.GenerateNewPasswordHash(password),
                RefreshToken = refreshToken
                // ObjectId is auto generated, and other values are left default.
            };
            await InsertOneAsync(userAccountModel);

            // GENERATE RESPONSE | Finally, after account creation, generate response and return.
            var response = new LoginResponseModel()
            {
                LoginStatusCode = 1,        // New accounts must always confirm email (code 1).
                RefreshToken = refreshToken
            };

            _logger.LogInformation("New user registration successful (username: {username}, email: {email})", username, email);
            return response;
        }

        public async Task UserLogoutAsync(string username, string tokenGuid)
        {
            // Access token validation is performed in controller. We know the caller is the valid user for this account.

            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                _logger.LogInformation("Token user not found in database (username: {username})", username);
                return;
            }

            // BLACKLIST OLD ACCESS TOKEN | Add old token's GUID to blacklist, which expires at token default duration (max).
            _tokenGuidBlacklist.Add(tokenGuid, DateTime.UtcNow.AddMinutes(15));

            // UPDATE DATABASE | Remove the stored refresh token from the user account document, then update database.
            userAccount.RefreshToken = string.Empty;
            await UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            _logger.LogInformation("User successfully logged out (username: {username})", username);
        }

        #endregion

        #region Private: MongoDB CRUD Methods

        private async Task<List<UserAccountModel>> GetAllAsync()
        {
            // Find with universally true comparator because we want to accept all found items.
            return await userAccountsCollection.Find(_ => true).ToListAsync();
        }

        private async Task<UserAccountModel> GetOneByIdAsync(string id)
        {
            // Run simple comparison on item ID (ObjectId in MongoDB).
            return await userAccountsCollection.Find(item => item.Id == id).FirstOrDefaultAsync();
        }

        private async Task<UserAccountModel> GetOneByUsernameAsync(string username)
        {
            // Run simple comparison on account username.
            return await userAccountsCollection.Find(item => item.Username == username).FirstOrDefaultAsync();
        }

        private async Task<UserAccountModel> GetOneByEmailAsync(string email)
        {
            // Run simple comparison on account email. Will be index in MongoDB.
            return await userAccountsCollection.Find(item => item.Email == email).FirstOrDefaultAsync();
        }



        private async Task InsertOneAsync(UserAccountModel model)
        {
            await userAccountsCollection.InsertOneAsync(model);
        }



        private async Task UpdateOneByIdAsync(string id, UserAccountModel model)
        {
            // Replaces the existing document entirely, searching by ID (ObjectId).
            await userAccountsCollection.ReplaceOneAsync((item => item.Id == id), model);
        }

        private async Task UpdateOneByUsernameAsync(string username, UserAccountModel model)
        {
            // Replaces the existing document entirely, searching by username.
            await userAccountsCollection.ReplaceOneAsync((item => item.Username == username), model);
        }

        private async Task UpdateOneByEmailAsync(string email, UserAccountModel model)
        {
            // Replaces the existing document entirely, searching by email.
            await userAccountsCollection.ReplaceOneAsync((item => item.Email == email), model);
        }



        private async Task DeleteOneByIdAsync(string id)
        {
            await userAccountsCollection.DeleteOneAsync(item => item.Id == id);
        }

        private async Task DeleteOneByUsernameAsync(string username)
        {
            await userAccountsCollection.DeleteOneAsync(item => item.Username == username);
        }

        private async Task DeleteOneByEmailAsync(string email)
        {
            await userAccountsCollection.DeleteOneAsync(item => item.Email == email);
        }

        #endregion
    }
}
