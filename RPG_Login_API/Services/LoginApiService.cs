using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using RPG_Login_API.Database;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.UserResponses;
using RPG_Login_API.Utility;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RPG_Login_API.Services
{
    public class LoginApiService
    {
        // Secret JWT token key is stored outside of the project directory, and is set in-memory here on app initialization.
        private static byte[] jwtKey = [];
        public static void SetJwtKey(byte[] key) { jwtKey = key; }



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
                Console.Error.WriteLine(ex.Message + " Exiting.");
                return false;
            }
        }





        #region Public: User Account Access API Logic

        public async Task<LoginResponseModel?> UserLoginAsync(string username, string password)
        {
            // Add same logic as API imitator, but instead reading from the database and returning a response model.

            // NOTE: When creating our JWT Token, set the Role claim to "user" temporarily. This is not stored in
            //  the database, and for now we will assume everyone accessing this API is a user (no admin for now).
            // We will add an 'admin' role (which can manage user accounts) at some point in the future.

            return new LoginResponseModel()
            {
                LoginStatusCode = 0,
                RefreshToken = "REFRESHTOKEN",
                AccessToken = "ACCESSTOKEN"
            };
        }

        // BELOW IS JUST AN EXAMPLE REPRESENTATION

        //public async Task<LoginSuccessResponseModel?> Authenticate(string username, string password)
        //{
        //    // Try to find user in database.
        //    var loginModel = await apiUserLoginCollection.Find(item => item.Username == username).FirstOrDefaultAsync();
        //    if (loginModel == null) return null;

        //    // If user found, compare password using PasswordUtility class.
        //    if (!PasswordUtility.Compare(password, loginModel.PasswordHash)) return null;

        //    // Since a valid account was found, generate a valid JWT token for this user.
        //    var tokenHandler = new JwtSecurityTokenHandler();
        //    var tokenDescriptor = new SecurityTokenDescriptor()
        //    {
        //        Subject = new ClaimsIdentity(
        //        [
        //            new Claim(ClaimTypes.Name, username),               // We are using username, not email.
        //            new Claim(ClaimTypes.Role, loginModel.Authority)    // Store authority from MongoDB in token.
        //        ]),
        //        Expires = DateTime.UtcNow.AddDays(1),       // One day lifetime.
        //        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(jwtKey), SecurityAlgorithms.HmacSha256Signature)
        //    };

        //    // Actually generate the token from the handler and descriptor, then convert to custom response object and return it.
        //    var token = tokenHandler.CreateToken(tokenDescriptor);
        //    return new LoginSuccessResponseModel()
        //    {
        //        Token = tokenHandler.WriteToken(token),
        //        Authority = loginModel.Authority
        //    };
        //}

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



        private async Task DeleteOneByIdAsync(string id)
        {
            await userAccountsCollection.DeleteOneAsync(item => item.Id == id);
        }

        private async Task DeleteOneByUsernameAsync(string username)
        {
            await userAccountsCollection.DeleteOneAsync(item => item.Username == username);
        }

        #endregion
    }
}
