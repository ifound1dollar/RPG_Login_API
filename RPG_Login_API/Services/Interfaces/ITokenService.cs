using System.Diagnostics.CodeAnalysis;

namespace RPG_Login_API.Services.Interfaces
{
    /// <summary>
    /// This interface is used by the TokenService to support Dependency Injection in a way that allows
    ///  for mocking during testing. Declares all public methods necessary for service functionality.
    /// </summary>
    public interface ITokenService
    {
        public string GenerateRefreshToken(string username, double durationDays = 30);
        public string GenerateAccessToken(string username, int stateCode, double durationMinutes = 15);

        public bool TryReadUsernameFromTokenString(string tokenString, [NotNullWhen(true)] out string? username);
        public bool ValidateToken(string token);
    }
}
