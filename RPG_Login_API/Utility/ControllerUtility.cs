using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RPG_Login_API.Utility
{
    public static class ControllerUtility
    {
        public static bool TryReadAccessTokenData(ClaimsPrincipal user, [NotNullWhen(true)] out string? username,
            [NotNullWhen(true)] out string? role, [NotNullWhen(true)] out string? guid)
        {
            username = user.Identity?.Name;                                 // UniqueName maps directly to Identity.Name.
            role = user.FindFirst(ClaimTypes.Role)?.Value;                  // Use the same ClaimTypes.Role as during creation.
            guid = user.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;      // We use Jti for GUID on token creation.

            // Returns true when username and GUID are valid, false otherwise.
            return (username != null && guid != null);
        }
    }
}
