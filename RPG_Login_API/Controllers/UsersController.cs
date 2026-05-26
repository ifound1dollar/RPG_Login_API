using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Org.BouncyCastle.Asn1.Ocsp;
using RPG_Login_API.Models.UserRequests;
using RPG_Login_API.Models.UserResponses;
using RPG_Login_API.Services;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace RPG_Login_API.Controllers
{
    // PERMISSION ROLES CURRENTLY USED ARE: "email_not_verified", "mfa_not_enabled", "reset_password", "change_email", "awaiting_mfa", "full_access"

    [EnableRateLimiting("IpLimitPolicy")]   // Limit requests from any specific IP.
    [Authorize]             // Denotes that all requests BY DEFAULT require JWT token authentication (passed in the HTTP request).
                            //  The token passed to the controller must be the access token. Refresh token is handled manually.
    [Route("api/users")]    // Makes all endpoints begin with "[URL]/api/users"; endpoint methods below define suffixes.
    [ApiController]
    public class UsersController : Controller
    {
        // TODO: CONSIDER USING GLOBAL EXCEPTION HANDLING MIDDLEWARE INSTEAD OF TRY-CATCH BLOCKS IN EACH CONTROLLER METHOD

        private readonly ILoginApiService _service;
        private readonly ILogger _logger;

        private readonly HashSet<string> _bannedPasswords;

        public UsersController(ILoginApiService service, ILogger<UsersController> logger)
        {
            // Adding the LoginApiService object as a constructor parameter utilizes ASP.NET's built-in dependency
            //  injection system. The controller is effectively requesting the Service from the services container
            //  configured in Program.cs.
            _service = service;
            _logger = logger;

            // Load a list of 100000 most commonly used passwords, used to prevent unsafe passwords.
            string badPasswordsFilePath = Path.Combine(Directory.GetCurrentDirectory(), "Utility", "100k-most-used-passwords-NCSC.txt");
            _bannedPasswords = new HashSet<string>(System.IO.File.ReadAllLines(badPasswordsFilePath), StringComparer.Ordinal);
        }



        #region Public: User Account Operations

        [AllowAnonymous]                // Logging in requires allowing un-authorized users to access endpoint.
        [Route("login-refresh")]
        [HttpPost]
        public async Task<ActionResult> UserLoginFromRefreshAsync([FromBody] RefreshLoginRequestModel request)
        {
            (int code, string message, LoginResponseModel? response) = await _service.UserLoginFromRefreshAsync(request.RefreshToken);
            return (response != null) ? StatusCode(code, response) : StatusCode(code, message);
        }



        [AllowAnonymous]        // Allow un-authorized users to access this endpoint (not logged in = no token yet).
        [Route("login")]  // Appends to route defined in class declaration. Can begin with '/' to override prefix in class declaration.
        [HttpPost]
        public async Task<ActionResult> UserLoginAsync([FromBody] LoginRequestModel loginRequest)
        {
            (int code, string message, LoginResponseModel? response) = await _service.UserLoginAsync(loginRequest.UsernameOrEmail, loginRequest.Password);
            return (response != null) ? StatusCode(code, response) : StatusCode(code, message);
        }



        [AllowAnonymous]
        [Route("register")]
        [HttpPost]
        public async Task<ActionResult> UserRegisterAsync([FromBody] RegisterRequestModel registerRequest)
        {
            // Verify validity of email, username, and password with simple(?) regex. This is also checked client-side.
            string emailPattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
            if (!Regex.IsMatch(registerRequest.Email, emailPattern))
            {
                _logger.LogInformation($"Client registration failed, email failed regex check (email: {registerRequest.Email})");
                return UnprocessableEntity("Invalid email, please enter a valid email.");
            }

            string usernamePattern = @"^[a-zA-Z0-9_]{5,20}$";                                   // Username, 5-20 chars, upper lower digit underscore
            if (!Regex.IsMatch(registerRequest.Username, usernamePattern))
            {
                _logger.LogInformation($"Client registration failed, username failed regex check (username: {registerRequest.Username})");
                return UnprocessableEntity("Username must be 5-20 characters and can only include uppercase and lowercase letters, digits, and underscores.");
            }

            string passwordPattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,64}$";   // Password, 8-64 chars, 1+ upper lower digit special (all specials)
            if (!Regex.IsMatch(registerRequest.Password, passwordPattern))
            {
                _logger.LogInformation($"Client registration failed, password failed regex check (username: {registerRequest.Username})");
                return UnprocessableEntity("New password must be 8-64 characters and include at least one one uppercase and lowercase letter, digit, and special character.");
            }
            // Also ensure password is not found in list of 100000 most-used-passwords (highly insecure).
            if (_bannedPasswords.Contains(registerRequest.Password))
            {
                _logger.LogInformation($"Client registration failed, password found in list of 100000 insecure passwords (username: {registerRequest.Username})");
                return UnprocessableEntity("Password does not meet minimum security standards, please submit a more secure password.");
            }

            (int code, string message, LoginResponseModel? response) = await _service.UserRegisterAsync(registerRequest.Username, registerRequest.Email, registerRequest.Password);
            return (response != null) ? StatusCode(code, response) : StatusCode(code, message);
        }



        [Authorize(Roles = TokenService.Roles.Any)]     // Require access token, any role. Only allow authenticated user to log out.
        [Route("logout")]
        [HttpPost]
        public async Task<ActionResult> UserLogoutAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client logout failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, string message) = await _service.UserLogoutAsync(username);
            return StatusCode(code, message);
        }



        [Authorize(Roles = TokenService.Roles.EmailNotVerified + "," + TokenService.Roles.FullAccess)]  // New account verification AND manual email change resend.
        [Route("resend-email-verification-code")]
        [HttpPost]
        public async Task<ActionResult> UserResendEmailVerificationCodeAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client resend email verification code failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Call service method with context based on stored role.
            int code; string message;
            if (role == TokenService.Roles.EmailNotVerified)
            {
                // If email not verified, then is for new account.
                (code, message) = await _service.UserResendEmailVerificationCode(username, isForNewAccount: true);
            }
            else
            {
                // Else full access means is for manual email change, so will send code to pending new email.
                (code, message) = await _service.UserResendEmailVerificationCode(username, isForNewAccount: false);
            }
            return StatusCode(code, message);
        }



        [Authorize(Roles = TokenService.Roles.EmailNotVerified + "," + TokenService.Roles.ChangeEmail)] // New account verification AND manual email change verification.
        [Route("verify-email")]
        [HttpPost]
        public async Task<ActionResult> UserVerifyAccountEmail([FromBody] VerifyEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client email verification failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Call service method with context based on stored role.
            int code; string message; LoginResponseModel? response;
            if (role == TokenService.Roles.EmailNotVerified)
            {
                (code, message, response) = await _service.UserVerifyAccountEmailAsync(username, request.Code, isForNewAccount: true);
            }
            else
            {
                (code, message, response) = await _service.UserVerifyAccountEmailAsync(username, request.Code, isForNewAccount: false);
            }
            return (response != null) ? StatusCode(code, response) : StatusCode(code, message);
        }



        [AllowAnonymous]            // Anyone can request a confirmation code (necessary to allow forgot password functionality).
        [Route("forgot-password")]
        [HttpPost]
        public async Task<ActionResult> UserForgotPasswordAsync([FromBody] ForgotPasswordRequestModel request)
        {
            // NOTE: We always return 200 (OK) to prevent the confirmation code endpoint from being used as a method
            //  for malicious actors to lookup existing usernames/emails. By always returning 200 (OK), users cannot
            //  know whether an account is associated with the username/email.

            await _service.UserForgotPasswordAsync(request.UsernameOrEmail);
            return Ok();
        }



        [AllowAnonymous]        // Allow anonymous to enable forgot password functionality; request must include a confirmation code.
        [Route("initiate-password-reset")]
        [HttpPost]
        public async Task<ActionResult> UserInitiatePasswordResetAsync([FromBody] InitiatePasswordResetRequestModel request)
        {
            // NOTE: Initiating a password reset returns only an access token with the ResetPassword role. This endpoint ensures 
            //  that only valid users can receive this access token by requiring a short-duration one-time-use confirmation code
            //  alongside the passed-in account username or email.

            (int code, string message, PasswordResetTokenResponseModel? response) = await _service.UserInitiatePasswordResetAsync(request.UsernameOrEmail, request.Code);
            return (response != null) ? StatusCode(code, response) : StatusCode(code, message);
        }



        [Authorize(Roles = TokenService.Roles.ResetPassword)]       // Only allow endpoint access for reset_password token roles.
        [Route("submit-new-password")]
        [HttpPost]
        public async Task<ActionResult> UserResetPasswordAsync([FromBody] PasswordResetRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client submit new password failed, incorrectly formatted reset (access) token in request header");
                return BadRequest("Malformed password reset token in API request.");
            }

            // Verify passed-in password matches basic password regex. This is also checked client-side.
            string passwordPattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,64}$";   // Password, 8-64 chars, 1+ upper lower digit special (all specials)
            if (!Regex.IsMatch(request.NewPassword, passwordPattern))
            {
                _logger.LogInformation($"Client submit new password failed, new password failed regex check (username: {username})");
                return UnprocessableEntity("New password must be 8-64 characters and include at least one one uppercase and lowercase letter, digit, and special character.");
            }
            // Also ensure password is not found in list of 100000 most-used-passwords.
            if (_bannedPasswords.Contains(request.NewPassword))
            {
                _logger.LogInformation($"Client submit new password failed, password found in list of 100000 insecure passwords (username: {username})");
                return UnprocessableEntity("Password does not meet minimum security standards, please submit a more secure password.");
            }

            (int code, string message) = await _service.UserSubmitNewPasswordAsync(username, request.NewPassword);
            return StatusCode(code, message);
        }



        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only allow username change if user has full access.
        [Route("change-username")]
        [HttpPost]
        public async Task<ActionResult> UserChangeUsernameAsync([FromBody] ChangeUsernameRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client username change failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Verify passed-in username matches basic username regex. This is also checked client-side.
            string usernamePattern = @"^[a-zA-Z0-9_]{5,20}$";                   // Username, 5-20 chars, upper lower digit underscore
            if (!Regex.IsMatch(request.NewUsername, usernamePattern))
            {
                _logger.LogInformation($"Client username change failed, new username failed regex check (username: {username})");
                return UnprocessableEntity("New username must be 5-20 characters and can only include uppercase and lowercase letters, digits, and underscores.");
            }

            (int code, string message, LoginResponseModel? response) = await _service.UserChangeUsernameAsync(username, request.NewUsername);
            return (response != null) ? StatusCode(code, response) : StatusCode(code, message);
        }



        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only allow email change request if full access.
        [Route("request-email-change")]
        [HttpPost]
        public async Task<ActionResult> UserRequestEmailChangeAsync()
        {
            // This endpoint simply generates a confirmation code for the user stored in the access token.
            // IMPORTANT: Because this is only accessible by fully-logged-in users, we can return actual success code and message.

            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client request email change failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, string message) = await _service.UserRequestEmailChangeAsync(username);
            return StatusCode(code, message);
        }



        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only allow actually initiating email change if full access.
        [Route("initiate-email-change")]
        [HttpPost]
        public async Task<ActionResult> UserInitiateEmailChangeAsync(InitiateEmailChangeRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client initiate email change failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, string message, EmailChangeTokenResponseModel? response) = await _service.UserInitiateEmailChangeAsync(username, request.Code);
            return (response != null) ? StatusCode(code, response) : StatusCode(code, message);
        }



        [Authorize(Roles = TokenService.Roles.ChangeEmail)]
        [Route("submit-new-email")]
        [HttpPost]
        public async Task<ActionResult> UserSubmitNewEmailAsync(SubmitNewEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client submit new email failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, string message) = await _service.UserSubmitNewEmailAsync(username, request.NewEmail);
            return StatusCode(code, message);
        }

        #endregion

        #region Public: Client account state tracking

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only considered in launcher if logged in with full access.
        [Route("ping-in-launcher")]
        [HttpPost]
        public async Task<ActionResult> UserPingInLauncher()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client ping in launcher failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, string message) = await _service.UserPingInLauncherAsync(username);
            if (code == 204)
            {
                return NoContent();
            }
            else
            {
                return StatusCode(code, message);
            }
        }

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only process exit for fully-logged-in users.
        [Route("notify-launcher-exit")]
        [HttpPost]
        public async Task<ActionResult> UserNotifyLauncherExit()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client notify launcher exit failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, string message) = await _service.UserNotifyLauncherExitAsync(username);
            if (code == 204)
            {
                return NoContent();
            }
            else
            {
                return StatusCode(code, message);
            }
        }

        #endregion

        #region Private: Utility

        private bool TryReadAccessTokenData(ClaimsPrincipal user, [NotNullWhen(true)] out string? username,
            [NotNullWhen(true)] out string? role, [NotNullWhen(true)] out string? guid)
        {
            username = user.Identity?.Name;                                 // UniqueName maps directly to Identity.Name.
            role = user.FindFirst(ClaimTypes.Role)?.Value;                  // Use the same ClaimTypes.Role as during creation.
            guid = user.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;      // We use Jti for GUID on token creation.

            // Returns true when username and GUID are valid, false otherwise.
            return (username != null && guid != null);
        }

        #endregion
    }
}
