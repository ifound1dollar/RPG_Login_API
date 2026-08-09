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
        public Task<bool> UpdateOneByIdAsync(string id, UserAccountPatch patchData);

        // PUT
        public Task<bool> ReplaceOneByIdAsync(string id, UserAccountModel model);

        // DELETE
        public Task<bool> DeleteOneByIdAsync(string id);

        // INFO
        public Task<bool> IsSecondaryEmailInUseAsync(string secondaryEmail);
    }
}
