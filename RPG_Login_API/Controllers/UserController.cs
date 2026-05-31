using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using RPG_Login_API.Models.UserRequests;
using RPG_Login_API.Services;
using RPG_Login_API.Services.Interfaces;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace RPG_Login_API.Controllers
{
    // PERMISSION ROLES CURRENTLY USED ARE: "email_not_verified", "mfa_not_enabled", "reset_password", "change_email", "awaiting_mfa", "full_access"

    [EnableRateLimiting("IpLimitPolicy")]   // Limit requests from any specific IP.
    [Authorize]             // Denotes that all requests BY DEFAULT require JWT token authentication (passed in the HTTP request).
                            //  The token passed to the controller must be the access token. Refresh token is handled manually.
    [Route("api/users")]    // Makes all endpoints begin with "[URL]/api/users"; endpoint methods below define suffixes.
    [ApiController]
    public class UserController : Controller
    {
        private readonly IUserService _service;
        private readonly ILogger _logger;

        public UserController(IUserService service, ILogger<UserController> logger)
        {
            // Adding the LoginApiService object as a constructor parameter utilizes ASP.NET's built-in dependency
            //  injection system. The controller is effectively requesting the Service from the services container
            //  configured in Program.cs.
            _service = service;
            _logger = logger;
        }



        #region Public: User Account Operations

        [AllowAnonymous]                // Logging in requires allowing un-authorized users to access endpoint.
        [Route("login-refresh")]
        [HttpPost]
        public async Task<ActionResult> UserLoginFromRefreshAsync([FromBody] RefreshLoginRequestModel request)
        {
            (int code, object? response) = await _service.UserLoginFromRefreshAsync(request.RefreshToken);
            return StatusCode(code, response);
        }



        [AllowAnonymous]        // Allow un-authorized users to access this endpoint (not logged in = no token yet).
        [Route("login")]  // Appends to route defined in class declaration. Can begin with '/' to override prefix in class declaration.
        [HttpPost]
        public async Task<ActionResult> UserLoginAsync([FromBody] LoginRequestModel loginRequest)
        {
            (int code, object? response) = await _service.UserLoginAsync(loginRequest.UsernameOrEmail, loginRequest.Password);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenService.Roles.AwaitingMfa)]
        [Route("submit-mfa-code")]
        [HttpPost]
        public async Task<ActionResult> UserSubmitMfaCodeForLogin(SubmitMfaCodeRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client submit MFA code, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _service.UserSubmitMfaCodeForLoginAsync(username, request.MfaCode);
            return StatusCode(code, response);
        }



        [AllowAnonymous]
        [Route("register")]
        [HttpPost]
        public async Task<ActionResult> UserRegisterAsync([FromBody] RegisterRequestModel registerRequest)
        {
            (int code, object? response) = await _service.UserRegisterAsync(registerRequest.Username, registerRequest.Email, registerRequest.Password);
            return StatusCode(code, response);
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

            (int code, object? response) = await _service.UserLogoutAsync(username);
            return StatusCode(code, response);
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

            // Email not verified implies is for new account, else full access is for manual email change.
            bool isForNewAccount = (role == TokenService.Roles.EmailNotVerified);
            (int code, object? response) = await _service.UserResendEmailVerificationCode(username, isForNewAccount);
            return StatusCode(code, response);
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

            // Email not verified implies is for new account, else full access is for manual email change.
            bool isForNewAccount = (role == TokenService.Roles.EmailNotVerified);
            (int code, object? response) = await _service.UserVerifyAccountEmailAsync(username, request.Code, isForNewAccount);
            return StatusCode(code, response);
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

            (int code, object? response) = await _service.UserInitiatePasswordResetAsync(request.UsernameOrEmail, request.Code);
            return StatusCode(code, response);
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

            (int code, object? response) = await _service.UserSubmitNewPasswordAsync(username, request.NewPassword);
            return StatusCode(code, response);
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

            (int code, object? response) = await _service.UserChangeUsernameAsync(username, request.NewUsername);
            return StatusCode(code, response);
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

            (int code, object? response) = await _service.UserRequestEmailChangeAsync(username);
            return StatusCode(code, response);
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

            (int code, object? response) = await _service.UserInitiateEmailChangeAsync(username, request.Code);
            return StatusCode(code, response);
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

            (int code, object? response) = await _service.UserSubmitNewEmailAsync(username, request.NewEmail);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenService.Roles.MfaNotEnabled + "," + TokenService.Roles.FullAccess)]
        [Route("setup-mfa")]
        [HttpPost]
        public async Task<ActionResult> UserSetupMfa()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client setup MFA failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _service.UserSetupMfaAsync(username);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenService.Roles.MfaNotEnabled + "," + TokenService.Roles.AwaitingMfa + "," + TokenService.Roles.FullAccess)]
        [Route("verify-mfa-setup")]     // ^ MFA not enabled for initial setup, awaiting MFA for recover, full access for manual change
        [HttpPost]
        public async Task<ActionResult> UserVerifyMfaSetup(VerifyMfaSetupRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client setup MFA failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _service.UserVerifyMfaSetupAsync(username, request.MfaCode);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenService.Roles.AwaitingMfa + "," + TokenService.Roles.FullAccess)]
        [Route("recover-mfa")]
        [HttpPost]
        public async Task<ActionResult> UserRecoverMfa(RecoverMfaRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client recover MFA failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _service.UserRecoverMfaAsync(username, request.RecoveryCode);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only fully-logged-in users can regenerate recovery code.
        [Route("regenerate-mfa-recovery-code")]
        [HttpPost]
        public async Task<ActionResult> UserRegenerateMfaRecoveryCode()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("Client recover MFA failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _service.UserRegenerateMfaRecoveryCodeAsync(username);
            return StatusCode(code, response);
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

            (int code, object? response) = await _service.UserPingInLauncherAsync(username);
            return (code == 204) ? NoContent() : StatusCode(code, response);
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

            (int code, object? response) = await _service.UserNotifyLauncherExitAsync(username);
            return (code == 204) ? NoContent() : StatusCode(code, response);
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
