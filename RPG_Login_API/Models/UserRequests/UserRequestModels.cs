using System.ComponentModel.DataAnnotations;

namespace RPG_Login_API.Models.UserRequests
{
    // LOGIN AND REGISTER

    public class RefreshLoginRequestModel
    {
        [Required(ErrorMessage = "Refresh token is required.")]
        public string RefreshToken { get; set; } = string.Empty;

        [Required(ErrorMessage = "Client GUID must be manually sent in request body.")]
        public string ClientGuid { get; set; } = string.Empty;
    }

    public class LoginRequestModel
    {
        [Required(ErrorMessage = "A non-empty username or email is required.")]
        public string UsernameOrEmail { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; } = string.Empty;
    }

    public class RegisterRequestModel
    {
        [Required(ErrorMessage = "Username is required.")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required.")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required.")]
        public string Password { get; set; } = string.Empty;
    }





    // CONFIRMATION CODE AND EMAIL VERIFICATION

    public class ForgotPasswordRequestModel
    {
        [Required(ErrorMessage = "A non-empty username or email is required.")]
        public string UsernameOrEmail { get; set; } = string.Empty;
    }

    public class VerifyEmailRequestModel
    {
        [Required(ErrorMessage = "A confirmation code is required.")]
        public string Code { get; set; } = string.Empty;
    }





    // CHANGE PASSWORD / USERNAME / EMAIL

    public class InitiatePasswordResetRequestModel
    {
        [Required(ErrorMessage = "A non-empty username or email is required.")]
        public string UsernameOrEmail { get; set; } = string.Empty;

        [Required(ErrorMessage = "A confirmation code is required.")]
        public string Code { get; set; } = string.Empty;
    }

    public class PasswordResetRequestModel
    {
        [Required(ErrorMessage = "A new password is required.")]
        public string NewPassword { get; set; } = string.Empty;
    }

    public class ChangeUsernameRequestModel
    {
        [Required(ErrorMessage = "A new username is required.")]
        public string NewUsername { get; set; } = string.Empty;
    }

    public class InitiateEmailChangeRequestModel
    {
        [Required(ErrorMessage = "A confirmation code is required.")]
        public string Code { get; set; } = string.Empty;
    }

    public class SubmitNewEmailRequestModel
    {
        [Required(ErrorMessage = "A new email is required.")]
        public string NewEmail { get; set; } = string.Empty;
    }
}
