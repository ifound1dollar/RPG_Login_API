using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace RPG_Login_API.Configuration
{
    public class TokenSettings
    {
        public string JwtKey { get; set; } = null!;
    }
}
