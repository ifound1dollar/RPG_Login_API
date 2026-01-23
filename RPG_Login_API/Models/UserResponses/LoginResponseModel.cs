namespace RPG_Login_API.Models.UserResponses
{
    public class LoginResponseModel
    {
        public int LoginStatusCode { get; set; } = -1;      // 0 for full success, 1 for unconfirmed email, 2 for password needs reset
        public string RefreshToken { get; set; } = string.Empty;
        public string AccessToken { get; set; } = string.Empty;
    }
}
