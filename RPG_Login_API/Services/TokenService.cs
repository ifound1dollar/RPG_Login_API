using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RPG_Login_API.Configuration;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RPG_Login_API.Services
{
    /// <summary>
    /// The TokenService is responsible for performing JWT token operations (create, parse, etc.) for the entire
    ///  application. Receives a TokenSettings configuration which allows it to store in-memory the private
    ///  JWT token key for use during validation and token creation. Should be registered as a singleton service.
    /// </summary>
    public class TokenService : ITokenService
    {
        public class Roles
        {
            public const string EmailNotVerified = "email_not_verified";
            public const string MfaNotEnabled = "mfa_not_enabled";
            public const string ResetPassword = "reset_password";
            public const string ChangeEmail = "change_email";
            public const string AwaitingMfa = "awaiting_mfa";
            public const string FullAccess = "full_access";

            public const string Any = EmailNotVerified + "," + MfaNotEnabled + "," + ResetPassword + ","
                + ChangeEmail + "," + AwaitingMfa + "," + FullAccess;
        }

        private readonly byte[] _jwtKey;
        private readonly TokenValidationParameters _validationParameters;
        private readonly JwtSecurityTokenHandler _handler;
        private readonly ILogger _logger;

        public TokenService(IOptions<TokenSettings> settings, ILogger<TokenService> logger)
        {
            _jwtKey = Encoding.UTF8.GetBytes(settings.Value.JwtKey);
            _handler = new();
            _logger = logger;

            // IMPORTANT: These validation parameters must match the parameters in Program.cs.
            _validationParameters = new()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(_jwtKey),
                RoleClaimType = ClaimTypes.Role     // Configure the [Authorize] behavior in Controllers to use Roles.
            };
        }



        #region (Interface) Public: Token Generation

        public string GenerateRefreshToken(string username, bool isFullAccess, double durationDays = 30)
        {
            string role = (isFullAccess) ? TokenService.Roles.FullAccess : TokenService.Roles.AwaitingMfa;

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                
                Subject = new ClaimsIdentity(
                [
                    new Claim(JwtRegisteredClaimNames.UniqueName, username),    // We are using username, not email.
                    new Claim(ClaimTypes.Role, role)                            // Allows MFA skip on refresh login if full access.
                ]),
                Expires = DateTime.UtcNow.AddDays(durationDays),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_jwtKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = _handler.CreateToken(tokenDescriptor);
            return _handler.WriteToken(token);
        }

        public string GenerateAccessToken(string username, string role, double durationMinutes = 15)
        {
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(
                [
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),  // Create GUID for this token.
                    new Claim(JwtRegisteredClaimNames.UniqueName, username),            // We are using username, not email.
                    new Claim(ClaimTypes.Role, role)                                    // Store user permission in token.
                ]),
                Expires = DateTime.UtcNow.AddMinutes(durationMinutes),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_jwtKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = _handler.CreateToken(tokenDescriptor);
            return _handler.WriteToken(token);
        }

        #endregion

        #region (Interface) Public: Token Reading, Comparison, Validation

        public bool TryReadRefreshToken(string tokenString, [NotNullWhen(true)] out string? username, out bool isFullAccess)
        {
            username = null;
            isFullAccess = false;
            if (!TryReadJwtToken(_handler, tokenString, out var token)) return false;

            // Assign username with valid string or null, returning true if valid and false if null.
            return TryReadJwtTokenData(token, out username, out isFullAccess);
        }

        public bool ValidateToken(string token, string guid = "")
        {
            // https://stackoverflow.com/questions/50204844/how-to-validate-a-jwt-token
            // May need to check this resource for validation testing. Might need to set ValidIssuer or ValidAudience
            //  in parameters, and Issuer and Audience in token creation.

            try
            {
                ClaimsPrincipal principal = _handler.ValidateToken(token, _validationParameters, out var validatedToken);

                // If no exception thrown above, then token is valid, so check expiration.
                if (DateTime.UtcNow >= validatedToken.ValidTo) return false;

                // If a GUID has been passed in, compare with the GUID stored in the token.
                if (guid != string.Empty)
                {
                    return CompareTokenGuid(token, guid, _handler);     // Method returns false if mismatch.
                }

                // If no GUID passed in, then we need only compare expiration, which is already valid so return true.
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return false;
            }

        }

        #endregion



        #region Private Static: Token String Parsing

        private static bool TryReadJwtToken(JwtSecurityTokenHandler handler, string jwtToken, [NotNullWhen(true)] out JwtSecurityToken? token)
        {
            // First, try to read token string into SecurityToken.
            token = (handler.CanReadToken(jwtToken)) ? handler.ReadJwtToken(jwtToken) : null;
            return token != null;   // Returns true if token is valid, else false if null.
        }

        private static bool TryReadJwtTokenData(JwtSecurityToken token, [NotNullWhen(true)] out string? username, out bool isFullAccess)
        {
            // Retrieve username from token. IMPORTANT: ClaimType.Name MAPS TO UniqueName.
            isFullAccess = false;
            username = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.UniqueName)?.Value;
            string? role = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            if (role != null && role == TokenService.Roles.FullAccess)
            {
                isFullAccess = true;
            }
            return (username != null && role != null);  // True if both are non-null.
        }

        private static bool CompareTokenGuid(string token, string passedInGuid, JwtSecurityTokenHandler handler)
        {
            // Try to read JWT token and extract stored GUID, then compare to passed-in GUID.
            if (TryReadJwtToken(handler, token, out var jwtToken))
            {
                string? storedGuid = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
                if (storedGuid != null)
                {
                    return passedInGuid == storedGuid;
                }
            }

            // If we do not explicitly return above, then no match could be found (or malformed token), so return false.
            return false;
        }

        #endregion

    }
}
