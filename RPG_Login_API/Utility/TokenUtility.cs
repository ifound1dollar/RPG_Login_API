using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RPG_Login_API.Utility
{
    public static class TokenUtility
    {
        // Secret JWT token key is stored outside of the project directory, and is set in-memory here on app initialization.
        private static byte[] _jwtKey = [];
        private static TokenValidationParameters _validationParameters = new();
        public static void SetRequiredData(byte[] jwtKey, TokenValidationParameters parameters)
        {
            _jwtKey = jwtKey;
            _validationParameters = parameters;
        }

        private static readonly JwtSecurityTokenHandler _handler = new();



        #region Public: Token Generation

        public static string GenerateRefreshToken(string username, double durationDays = 30)
        {
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.Name, username),       // We are using username, not email.
                    new Claim(ClaimTypes.Role, "user")          // Store user permission in token.
                ]),
                Expires = DateTime.UtcNow.AddDays(durationDays),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_jwtKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = _handler.CreateToken(tokenDescriptor);
            return _handler.WriteToken(token);
        }

        public static string GenerateAccessToken(string username, double durationMinutes = 15)
        {
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.Name, username),       // We are using username, not email.
                    new Claim(ClaimTypes.Role, "user")          // Store user permission in token.
                ]),
                Expires = DateTime.UtcNow.AddMinutes(durationMinutes),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_jwtKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = _handler.CreateToken(tokenDescriptor);
            return _handler.WriteToken(token);
        }

        #endregion

        #region Public: Token Parsing / Reading

        private static bool TryReadJwtToken(string jwtToken, [NotNullWhen(true)] out JwtSecurityToken? token)
        {
            // First, try to read token string into SecurityToken.
            token = (_handler.CanReadToken(jwtToken)) ? _handler.ReadJwtToken(jwtToken) : null;
            return token != null;   // Returns true if token is valid, else false if null.
        }

        private static string? ReadUsernameFromJwtToken(JwtSecurityToken token)
        {
            // Retrieve username from token. IMPORTANT: ClaimType.Name MAPS TO UniqueName.
            var username = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.UniqueName)?.Value;

            return username;    // May be null.
        }

        public static bool TryReadUsernameFromTokenString(string tokenString, [NotNullWhen(true)] out string? username)
        {
            username = null;

            if (!TryReadJwtToken(tokenString, out var token)) return false;
            username = ReadUsernameFromJwtToken(token);

            return username != null;
        }

        #endregion

        #region Public: Token Comparison and Validation

        public static bool CompareTokens(string token1, string token2)
        {
            return token1.Equals(token2); 
        }

        public static bool ValidateToken(string token)
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
                LogUtility.LogError("TokenUtility", ex.Message);
                return false;
            }
            
        }

        #endregion
    }
}
