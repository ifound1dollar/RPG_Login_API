namespace RPG_Login_API.Models.Responses
{
    public class PasswordResetTokenResponseModel
    {
        public string Username { get; set; } = string.Empty;
        public string PasswordResetToken { get; set; } = string.Empty;
    }
}
