namespace RPG_Login_API.Models.Responses
{
    public class ConnectTokenResponseModel
    {
        public string ConnectToken { get; set; } = string.Empty;
        public DateTime ConnectTokenExpiration { get; set; }
    }
}
