namespace RPG_Login_API.Models.UserResponses
{
    public class LoginResponseModel
    {
        public string Username { get; set; } = string.Empty;
        public string PrimaryEmail { get; set; } = string.Empty;
        public string SecondaryEmail { get; set; } = string.Empty;
        public int LoginStatusCode { get; set; } = -1;
        public string RefreshToken { get; set; } = string.Empty;
        public string AccessToken { get; set; } = string.Empty;
        public DateTime AccessTokenExpiration { get; set; }
    }
}
