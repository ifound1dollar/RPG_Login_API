namespace RPG_Login_API.Models.UserResponses
{
    public class EmailChangeTokenResponseModel
    {
        public string Username { get; set; } = string.Empty;
        public string EmailChangeToken { get; set; } = string.Empty;
    }
}
