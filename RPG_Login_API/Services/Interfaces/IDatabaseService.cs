using RPG_Login_API.Models.MongoDB;

namespace RPG_Login_API.Services.Interfaces
{
    /// <summary>
    /// This interface is used by the DatabaseService to support Dependency Injection in a way that allows
    ///  for mocking during testing. Declares all public methods necessary for service functionality (CRUD).
    /// </summary>
    public interface IDatabaseService
    {
        public bool CheckConnectionStatus();

        // GET
        public Task<List<UserAccountModel>> GetAllAsync();
        public Task<UserAccountModel> GetOneByIdAsync(string id);
        public Task<UserAccountModel> GetOneByUsernameAsync(string username);
        public Task<UserAccountModel> GetOneByEmailAsync(string email);

        // POST
        public Task InsertOneAsync(UserAccountModel model);

        // PUT
        public Task UpdateOneByIdAsync(string id, UserAccountModel model);
        public Task UpdateOneByUsernameAsync(string username, UserAccountModel model);
        public Task UpdateOneByEmailAsync(string email, UserAccountModel model);

        // DELETE
        public Task DeleteOneByIdAsync(string id);
        public Task DeleteOneByUsernameAsync(string username);
        public Task DeleteOneByEmailAsync(string email);
    }
}
