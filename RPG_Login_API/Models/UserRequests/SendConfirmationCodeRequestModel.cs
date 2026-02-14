namespace RPG_Login_API.Models.UserRequests
{
    public class SendConfirmationCodeRequestModel
    {
        public string UsernameOrEmail { get; set; } = string.Empty;
    }
}
