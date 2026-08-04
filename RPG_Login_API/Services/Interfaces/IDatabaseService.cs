using RPG_Login_API.Models.MongoDB;
using System.Text.Json.Nodes;

namespace RPG_Login_API.Services.Interfaces
{
    /// <summary>
    /// This interface is used by the DatabaseService to support Dependency Injection in a way that allows
    ///  for mocking during testing. Declares all public methods necessary for service functionality (CRUD).
    /// </summary>
    public interface IDatabaseService
    {
        public Task<bool> CheckConnectionStatus();

        // GET
        public Task<List<UserAccountModel>?> GetAllAsync();
        public Task<UserAccountModel?> GetOneByIdAsync(string id);
        public Task<UserAccountModel?> GetOneByUsernameAsync(string username);
        public Task<UserAccountModel?> GetOneByEmailAsync(string email);

        // POST
        public Task<bool> InsertOneAsync(UserAccountModel model);

        // PATCH
        public Task<bool> UpdateOneByIdAsync<T>(string id, T patchData);
        public Task<bool> UpdateOneByUsernameAsync<T>(string username, T patchData);
        public Task<bool> UpdateOneByEmailAsync<T>(string email, T patchData);

        // PUT
        public Task<bool> ReplaceOneByIdAsync(string id, UserAccountModel model);
        public Task<bool> ReplaceOneByUsernameAsync(string username, UserAccountModel model);
        public Task<bool> ReplaceOneByEmailAsync(string email, UserAccountModel model);

        // DELETE
        public Task<bool> DeleteOneByIdAsync(string id);
        public Task<bool> DeleteOneByUsernameAsync(string username);
        public Task<bool> DeleteOneByEmailAsync(string email);

        // INFO
        public Task<bool> IsSecondaryEmailInUseAsync(string secondaryEmail);
    }
}
