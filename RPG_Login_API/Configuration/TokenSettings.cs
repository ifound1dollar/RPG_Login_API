using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace RPG_Login_API.Configuration
{
    /// <summary>
    /// Represents JWT token configuration data like secret JWT token key in object form. Should be
    ///  populated from JSON configuration data, accessed within Program.cs.
    /// </summary>
    public class TokenSettings
    {
        public string JwtKey { get; set; } = null!;
    }
}
