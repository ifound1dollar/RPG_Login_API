namespace RPG_Login_API.Models.UserRequests
{
    // LOGIN AND REGISTER

    public class RefreshLoginRequestModel
    {
        public string RefreshToken { get; set; } = string.Empty;
        public string ClientGuid { get; set; } = string.Empty;
    }

    public class LoginRequestModel
    {
        public string UsernameOrEmail { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class RegisterRequestModel
    {
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }





    // CONFIRMATION CODE AND EMAIL VERIFICATION

    public class ForgotPasswordRequestModel
    {
        public string UsernameOrEmail { get; set; } = string.Empty;
    }

    public class VerifyEmailRequestModel
    {
        public string Code { get; set; } = string.Empty;
    }





    // CHANGE PASSWORD / USERNAME / EMAIL

    public class InitiatePasswordResetRequestModel
    {
        public string UsernameOrEmail { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
    }

    public class PasswordResetRequestModel
    {
        public string NewPassword { get; set; } = string.Empty;
    }

    public class ChangeUsernameRequestModel
    {
        public string NewUsername { get; set; } = string.Empty;
    }

    public class InitiateEmailChangeRequestModel
    {
        public string Code { get; set; } = string.Empty;
    }

    public class SubmitNewEmailRequestModel
    {
        public string NewEmail { get; set; } = string.Empty;
    }

    public class VerifyNewEmailRequestModel
    {
        public string Code { get; set; } = string.Empty;
    }
}
