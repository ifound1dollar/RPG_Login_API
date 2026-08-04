namespace RPG_Login_API.Models.MongoDB
{
    public class ApiUserAccessResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public DateTime AccessTokenExpiration { get; set; }
    }
}
