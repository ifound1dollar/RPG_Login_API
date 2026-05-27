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
        [RegularExpression(@"^[a-zA-Z0-9_]{5,20}$", ErrorMessage = "Username must be 5-20 characters and can only include uppercase and lowercase letters, digits, and underscores.")]
        public string Username { get; set; } = string.Empty;

        [RegularExpression(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", ErrorMessage = "Email must be a valid email address.")]
        public string Email { get; set; } = string.Empty;

        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,64}$", ErrorMessage = "Password must be 8-64 characters and include at least one one uppercase and lowercase letter, digit, and special character.")]
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
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,64}$", ErrorMessage = "New password must be 8-64 characters and include at least one one uppercase and lowercase letter, digit, and special character.")]
        public string NewPassword { get; set; } = string.Empty;
    }

    public class ChangeUsernameRequestModel
    {
        [RegularExpression(@"^[a-zA-Z0-9_]{5,20}$", ErrorMessage = "Username must be 5-20 characters and can only include uppercase and lowercase letters, digits, and underscores.")]
        public string NewUsername { get; set; } = string.Empty;
    }

    public class InitiateEmailChangeRequestModel
    {
        [Required(ErrorMessage = "A confirmation code is required.")]
        public string Code { get; set; } = string.Empty;
    }

    public class SubmitNewEmailRequestModel
    {
        [RegularExpression(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", ErrorMessage = "New email must be a valid email address.")]
        public string NewEmail { get; set; } = string.Empty;
    }
}
