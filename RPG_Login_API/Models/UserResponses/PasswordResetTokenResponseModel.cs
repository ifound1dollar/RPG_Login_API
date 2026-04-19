namespace RPG_Login_API.Models.UserResponses
{
    public class PasswordResetTokenResponseModel
    {
        public string Username { get; set; } = string.Empty;
        public string ResetToken { get; set; } = string.Empty;
    }
}
