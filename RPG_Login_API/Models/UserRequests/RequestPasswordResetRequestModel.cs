namespace RPG_Login_API.Models.UserRequests
{
    public class RequestPasswordResetRequestModel
    {
        public string UsernameOrEmail { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
    }
}
