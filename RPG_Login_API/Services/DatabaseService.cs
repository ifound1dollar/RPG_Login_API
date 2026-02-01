using Microsoft.Extensions.Options;
using MongoDB.Driver;
using RPG_Login_API.Configuration;
using RPG_Login_API.Models.MongoDB;

namespace RPG_Login_API.Services
{
    /// <summary>
    /// The DatabaseService is responsible for connecting to the database and actually performing CRUD
    ///  operations on it. Should be registered as a singleton service.
    /// </summary>
    public class DatabaseService
    {
        private readonly IMongoCollection<UserAccountModel> _userAccountsCollection;
        private readonly ILogger _logger;

        public DatabaseService(IOptions<DatabaseSettings> settings, ILogger<DatabaseService> logger)
        {
            // Create a new MongoClient instance from the connecting string defined in secrets.json.
            // Data pulled from secrets.json is stored in a DatabaseSettings singleton on app build in Program.cs.
            MongoClient client = new(settings.Value.ConnectionString);

            // Retrieve the database defined in secrets.json.
            IMongoDatabase database = client.GetDatabase(settings.Value.DatabaseName);

            // Finally, instantiate the collection using the name defined in secrets.json.
            _userAccountsCollection = database.GetCollection<UserAccountModel>(settings.Value.UserAccountsCollectionName);

            _logger = logger;
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
                _userAccountsCollection.Database.Client.ListDatabaseNames();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return false;
            }
        }





        #region Public: MongoDB CRUD Methods

        public async Task<List<UserAccountModel>> GetAllAsync()
        {
            // Find with universally true comparator because we want to accept all found items.
            return await _userAccountsCollection.Find(_ => true).ToListAsync();
        }

        public async Task<UserAccountModel> GetOneByIdAsync(string id)
        {
            // Run simple comparison on item ID (ObjectId in MongoDB).
            return await _userAccountsCollection.Find(item => item.Id == id).FirstOrDefaultAsync();
        }

        public async Task<UserAccountModel> GetOneByUsernameAsync(string username)
        {
            // Run simple comparison on account username.
            return await _userAccountsCollection.Find(item => item.Username == username).FirstOrDefaultAsync();
        }

        public async Task<UserAccountModel> GetOneByEmailAsync(string email)
        {
            // Run simple comparison on account email. Will be index in MongoDB.
            return await _userAccountsCollection.Find(item => item.Email == email).FirstOrDefaultAsync();
        }



        public async Task InsertOneAsync(UserAccountModel model)
        {
            await _userAccountsCollection.InsertOneAsync(model);
        }



        public async Task UpdateOneByIdAsync(string id, UserAccountModel model)
        {
            // Replaces the existing document entirely, searching by ID (ObjectId).
            await _userAccountsCollection.ReplaceOneAsync((item => item.Id == id), model);
        }

        public async Task UpdateOneByUsernameAsync(string username, UserAccountModel model)
        {
            // Replaces the existing document entirely, searching by username.
            await _userAccountsCollection.ReplaceOneAsync((item => item.Username == username), model);
        }

        public async Task UpdateOneByEmailAsync(string email, UserAccountModel model)
        {
            // Replaces the existing document entirely, searching by email.
            await _userAccountsCollection.ReplaceOneAsync((item => item.Email == email), model);
        }



        public async Task DeleteOneByIdAsync(string id)
        {
            await _userAccountsCollection.DeleteOneAsync(item => item.Id == id);
        }

        public async Task DeleteOneByUsernameAsync(string username)
        {
            await _userAccountsCollection.DeleteOneAsync(item => item.Username == username);
        }

        public async Task DeleteOneByEmailAsync(string email)
        {
            await _userAccountsCollection.DeleteOneAsync(item => item.Email == email);
        }

        #endregion

    }
}
