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
        public string GenerateAccessToken(string username, string role, double durationMinutes = 15);

        public bool TryReadRefreshToken(string tokenString, [NotNullWhen(true)] out string? username);
        public bool ValidateToken(string submittedToken, string storedTokenHash, string guid = "");

        /// <summary>
        /// Generates a unique JWT connect token for the provided user, which is used to validate players
        ///  connecting to the client service.
        /// </summary>
        /// <param name="username"> The user to generate the connect token for. </param>
        /// <param name="durationMinutes"> The duration of the token's validity, in minutes. </param>
        /// <returns> The generated JWT connect token in string form. </returns>
        public string GenerateGameConnectToken(string username, double durationMinutes = 60);
    }
}
