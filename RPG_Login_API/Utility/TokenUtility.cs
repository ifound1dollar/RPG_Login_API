using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RPG_Login_API.Utility
{
    public static class TokenUtility
    {
        private static readonly JwtSecurityTokenHandler _handler = new();



        #region Public: Token Generation

        public static string GenerateRefreshToken(string username, byte[] jwtKey, double durationDays = 30)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.Name, username),       // We are using username, not email.
                    new Claim(ClaimTypes.Role, "user")          // Store user permission in token.
                ]),
                Expires = DateTime.UtcNow.AddDays(durationDays),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(jwtKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static string GenerateAccessToken(string username, byte[] jwtKey, double durationMinutes = 15)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.Name, username),       // We are using username, not email.
                    new Claim(ClaimTypes.Role, "user")          // Store user permission in token.
                ]),
                Expires = DateTime.UtcNow.AddMinutes(durationMinutes),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(jwtKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        #endregion

        #region Public: Token Parsing / Reading

        private static bool TryReadJwtToken(string jwtToken, [NotNullWhen(true)] out JwtSecurityToken? token)
        {
            token = (_handler.CanReadToken(jwtToken)) ? _handler.ReadJwtToken(jwtToken) : null;
            return token != null;   // Returns true if token is valid, else false if null.
        }

        private static string? ReadUsernameFromJwtToken(JwtSecurityToken token)
        {
            // Retrieve username from token. IMPORTANT: ClaimType.Name MAPS TO UniqueName.
            var username = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.UniqueName)?.Value;

            return username;    // May be null.
        }

        public static bool TryParseTokenString(string tokenString, [NotNullWhen(true)] out string? username, [NotNullWhen(true)] out JwtSecurityToken? token)
        {
            username = null;
            token = null;

            if (!TryReadJwtToken(tokenString, out token)) return false;
            username = ReadUsernameFromJwtToken(token);

            return username != null;
        }

        #endregion

        #region Public: Token Comparison and Validation

        public static bool CompareTokens(string token1, string token2)
        {
            return token1.Equals(token2); 
        }

        public static bool IsTokenExpired(JwtSecurityToken token)
        {
            // Token expiration time should always use UTC on creation.
            return (DateTime.UtcNow > token.ValidTo);
        }

        #endregion
    }
}
