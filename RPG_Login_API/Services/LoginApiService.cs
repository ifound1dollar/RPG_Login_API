using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using RPG_Login_API.Data;
using RPG_Login_API.Database;
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
        private readonly Dictionary<string, AccessTokenData> _accessTokens = [];    // Maps username:tokenData



        private readonly IMongoCollection<UserAccountModel> userAccountsCollection;

        public LoginApiService(IOptions<DatabaseSettings> settings)
        {
            // Create a new MongoClient instance from the connecting string defined in secrets.json.
            // Data pulled from secrets.json is stored in a DatabaseSettings singleton on app build in Program.cs.
            MongoClient client = new(settings.Value.ConnectionString);

            // Retrieve the database defined in secrets.json.
            IMongoDatabase database = client.GetDatabase(settings.Value.DatabaseName);

            // Finally, instantiate the collection using the name defined in secrets.json.
            userAccountsCollection = database.GetCollection<UserAccountModel>(settings.Value.UserAccountsCollectionName);
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
                LogUtility.LogError("Startup", ex.Message);
                return false;
            }
        }





        #region Public: User Account Access API Logic

        public async Task<LoginResponseModel?> UserLoginFromRefreshAsync(string refreshTokenString)
        {
            LoginResponseModel response;

            // PARSE TOKEN | Try to retrieve username and token object from the passed-in token string.
            if (!TokenUtility.TryReadUsernameFromTokenString(refreshTokenString, out var username)) return null;

            // FIND USER | Try to find user in database. Return null if we cannot find by username.
            var userAccount = await GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                LogUtility.LogError("LoginFromRefresh", $"Token user not found in database (username: {username})");
                return null;
            }

            // COMPARE TOKEN | Now that we have found a valid user, compare the stored refresh token with this refresh token.
            if (!TokenUtility.CompareTokens(refreshTokenString, userAccount.RefreshToken))
            {
                LogUtility.LogError("LoginFromRefresh", $"Passed-in token does not match token in database (username: {username})");
                return null;
            }

            // ACTUALLY VALIDATE TOKEN | If token matches stored token in database, validate it (primarily checks expiration).
            if (!TokenUtility.ValidateToken(refreshTokenString))
            {
                LogUtility.LogError("LoginFromRefresh", $"Refresh token failed validation, may be expired (username: {username})");
                return null;
            }

            // GENERATE RESPONSE | Finally, token is confirmed fully valid so determine login response based on account state.
            if (!userAccount.IsEmailConfirmed || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                response = new LoginResponseModel()
                {
                    LoginStatusCode = (!userAccount.IsEmailConfirmed) ? 1 : 2,      // 1 if unconfirmed, else 2 for password reset
                    RefreshToken = TokenUtility.GenerateRefreshToken(username, durationDays: 30),
                };
            }
            else
            {
                // Else account state is good, so return full login with refresh token AND access token. Also update access tokens map.
                response = new LoginResponseModel()
                {
                    LoginStatusCode = 0,
                    RefreshToken = TokenUtility.GenerateRefreshToken(username, durationDays: 30),
                    AccessToken = TokenUtility.GenerateAccessToken(username, durationMinutes: 15)
                };
                _accessTokens[username] = new AccessTokenData(username, response.AccessToken, durationMinutes: 15);
            }

            // UPDATE DATABASE | After token generation, update document in database with newly-generated refresh token.
            // TODO: STORE REFRESH TOKEN AS HASH INSTEAD OF RAW, FOR SECURITY REASONS
            userAccount.RefreshToken = response.RefreshToken;
            await UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            LogUtility.LogMessage("LoginFromRefresh", $"User refresh login successful (username: {username}) with login code {response.LoginStatusCode}");
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
                    LogUtility.LogError("Login", $"Username/email not found in database (input: {username})");
                    return null;
                }
            }

            // COMPARE PASSWORD | If user found, compare password using PasswordUtility class. Return null if password mismatch.
            if (!PasswordUtility.ComparePasswordToHash(password, userAccount.PasswordHash))
            {
                LogUtility.LogError("Login", $"User-submitted password does not match account's stored password (username: {username})");
                return null;
            }

            // GENERATE RESPONSE | Determine how we will process login based on account state.
            if (!userAccount.IsEmailConfirmed || userAccount.DoesPasswordNeedReset)
            {
                // If unconfirmed or password needs reset, do not allow the user to access the API. Only return a refresh token.
                response = new LoginResponseModel()
                {
                    LoginStatusCode = (!userAccount.IsEmailConfirmed) ? 1 : 2,      // 1 if unconfirmed, else 2 for password reset
                    RefreshToken = TokenUtility.GenerateRefreshToken(username, durationDays: 30),
                };
            }
            else
            {
                // Else account state is good, so return full login with refresh token AND access token. Also update access tokens map.
                response = new LoginResponseModel()
                {
                    LoginStatusCode = 0,
                    RefreshToken = TokenUtility.GenerateRefreshToken(username, durationDays: 30),
                    AccessToken = TokenUtility.GenerateAccessToken(username, durationMinutes: 15)
                };
                _accessTokens[username] = new AccessTokenData(username, response.AccessToken, durationMinutes: 15);
            }

            // UPDATE DATABASE | After token generation, update document in database with newly-generated refresh token.
            // TODO: STORE REFRESH TOKEN AS HASH INSTEAD OF RAW, FOR SECURITY REASONS
            userAccount.RefreshToken = response.RefreshToken;
            await UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            LogUtility.LogMessage("Login", $"User login successful (username: {username}) with login code {response.LoginStatusCode}");
            return response;
        }

        public async Task<LoginResponseModel?> UserRegisterAsync(string username, string email, string password)
        {
            // ENSURE UNIQUE USERNAME/EMAIL | Query database for any accounts with matching username or email.
            var userAccount = await GetOneByUsernameAsync(username);
            if (userAccount != null)
            {
                LogUtility.LogError("Register", $"User-submitted username already in use (username: {username})");
                return null;
            }
            userAccount = await GetOneByEmailAsync(username);
            if (userAccount != null)
            {
                LogUtility.LogError("Register", $"User-submitted email already in use (email: {email})");
                return null;
            }

            // CREATE NEW ACCOUNT MODEL | Username and email are unique, so create a new user document.
            string refreshToken = TokenUtility.GenerateRefreshToken(username, durationDays: 30);
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

            LogUtility.LogMessage("Register", $"New user registration successful (username: {username}, email: {email})");
            return response;
        }

        public async Task UserLogoutAsync(string refreshTokenString)
        {
            // PARSE TOKEN | Try to retrieve username and token object from the passed-in token string.
            if (!TokenUtility.TryReadUsernameFromTokenString(refreshTokenString, out var username)) return;

            // FIND USER | Try to find user in database. Return null if we cannot find by username (should never happen).
            var userAccount = await GetOneByUsernameAsync(username);
            if (userAccount == null)
            {
                LogUtility.LogError("Logout", $"Token user not found in database (username: {username})");
                return;
            }

            // COMPARE TOKEN | Only allow logout from the currently-logged-in user (matching refresh token).
            if (!TokenUtility.CompareTokens(refreshTokenString, userAccount.RefreshToken))
            {
                LogUtility.LogError("Logout", $"User-submitted token does not match token in database, denying logout (username: {username}");
                return;
            }

            // NOTE: We do not need to check token expiration, as we are logging out anyway.

            // REMOVE ACCESS TOKEN | Try to find an access token for this user, removing if found.
            _accessTokens.Remove(username);

            // UPDATE DATABASE | Remove the stored refresh token from the user account document, then update database.
            userAccount.RefreshToken = string.Empty;
            await UpdateOneByUsernameAsync(userAccount.Username, userAccount);

            LogUtility.LogMessage("Logout", $"User successfully logged out (username: {username})");
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
