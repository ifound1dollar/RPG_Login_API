namespace RPG_Login_API.Configuration
{
    public class MfaServiceSettings
    {
        public string Issuer { get; set; } = string.Empty;
        public string SymmetricKey { get; set; } = string.Empty;
    }
}
