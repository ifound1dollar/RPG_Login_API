namespace RPG_Login_API.Models.UserRequests
{
    public class RefreshLoginRequestModel
    {
        public string RefreshToken { get; set; } = string.Empty;
        public string ClientGuid { get; set; } = string.Empty;
    }
}
