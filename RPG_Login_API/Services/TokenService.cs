using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RPG_Login_API.Configuration;
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
    public class TokenService
    {
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



        #region Public: Token Generation

        public string GenerateRefreshToken(string username, double durationDays = 30)
        {
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(
                [
                    new Claim(JwtRegisteredClaimNames.UniqueName, username),    // We are using username, not email.
                    new Claim(ClaimTypes.Role, "refresh")                       // Use this to loosely determine token purpose.
                ]),
                Expires = DateTime.UtcNow.AddDays(durationDays),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_jwtKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = _handler.CreateToken(tokenDescriptor);
            return _handler.WriteToken(token);
        }

        public string GenerateAccessToken(string username, int stateCode, double durationMinutes = 15)
        {
            string role;
            switch (stateCode)
            {
                case 1:
                    {
                        role = "not_confirmed";
                        break;
                    }
                case 2:
                    {
                        role = "reset_password";
                        break;
                    }
                default:
                    {
                        role = "full_access";
                        break;
                    }
            }

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

        #region Public: Token Reading, Comparison, Validation

        public bool TryReadUsernameFromTokenString(string tokenString, [NotNullWhen(true)] out string? username)
        {
            username = null;

            if (!TryReadJwtToken(tokenString, out var token)) return false;
            username = ReadUsernameFromJwtToken(token);

            return username != null;
        }

        public bool ValidateToken(string token)
        {
            // https://stackoverflow.com/questions/50204844/how-to-validate-a-jwt-token
            // May need to check this resource for validation testing. Might need to set ValidIssuer or ValidAudience
            //  in parameters, and Issuer and Audience in token creation.

            try
            {
                ClaimsPrincipal principal = _handler.ValidateToken(token, _validationParameters, out var validatedToken);

                // If no exception thrown above, then token is valid, so check expiration.
                return (DateTime.UtcNow < validatedToken.ValidTo);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return false;
            }

        }


        #endregion

        #region Private: Token String Parsing

        private bool TryReadJwtToken(string jwtToken, [NotNullWhen(true)] out JwtSecurityToken? token)
        {
            // First, try to read token string into SecurityToken.
            token = (_handler.CanReadToken(jwtToken)) ? _handler.ReadJwtToken(jwtToken) : null;
            return token != null;   // Returns true if token is valid, else false if null.
        }

        private string? ReadUsernameFromJwtToken(JwtSecurityToken token)
        {
            // Retrieve username from token. IMPORTANT: ClaimType.Name MAPS TO UniqueName.
            var username = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.UniqueName)?.Value;

            return username;    // May be null.
        }

        #endregion

    }
}
