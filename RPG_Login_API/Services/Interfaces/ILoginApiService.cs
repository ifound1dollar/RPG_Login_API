using RPG_Login_API.Models.UserResponses;

namespace RPG_Login_API.Services.Interfaces
{
    /// <summary>
    /// This interface is used by the LoginApiService to support Dependency Injection in a way that allows
    ///  for mocking during testing. Declares all public methods necessary for service functionality.
    /// </summary>
    public interface ILoginApiService
    {

        public Task<LoginResponseModel?> UserLoginFromRefreshAsync(string refreshTokenString);
        public Task<LoginResponseModel?> UserLoginAsync(string username, string password);
        public Task<LoginResponseModel?> UserRegisterAsync(string username, string email, string password);
        public Task UserLogoutAsync(string username, string tokenGuid);
    }
}
