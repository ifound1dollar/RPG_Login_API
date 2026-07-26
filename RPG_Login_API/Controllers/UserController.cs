using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Org.BouncyCastle.Asn1.Ocsp;
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
    [Route("users")]    // Makes all endpoints begin with "[URL]/users"; endpoint methods below define suffixes.
    [ApiController]
    public class UserController : Controller
    {
        private readonly ILoginService _loginService;
        private readonly INewAccountService _newAccountService;
        private readonly IResetPasswordService _resetPasswordService;
        private readonly IAccountService _accountService;
        private readonly IMfaSetupService _mfaSetupService;
        private readonly ILauncherService _launcherService;
        private readonly ILogger _logger;

        public UserController(ILoginService loginService, INewAccountService newAccountService, IResetPasswordService resetPasswordService,
            IAccountService accountService, IMfaSetupService mfaSetupService, ILauncherService launcherService, ILogger<UserController> logger)
        {
            // Adding the services object as constructor parameters utilizes ASP.NET's built-in dependency
            //  injection system. The controller is effectively requesting the Service from the services container
            //  configured in Program.cs.
            _loginService = loginService;
            _newAccountService = newAccountService;
            _resetPasswordService = resetPasswordService;
            _accountService = accountService;
            _mfaSetupService = mfaSetupService;
            _launcherService = launcherService;

            _logger = logger;
        }



        #region Public: User Account Operations

        [AllowAnonymous]                // Logging in requires allowing un-authorized users to access endpoint.
        [Route("login-refresh")]
        [HttpPost]
        public async Task<ActionResult> UserLoginFromRefreshAsync([FromBody] RefreshLoginRequestModel request)
        {
            (int code, object? response) = await _loginService.LoginFromRefreshAsync(request.RefreshToken);
            return StatusCode(code, response);
        }



        [AllowAnonymous]        // Allow un-authorized users to access this endpoint (not logged in = no token yet).
        [Route("login")]  // Appends to route defined in class declaration. Can begin with '/' to override prefix in class declaration.
        [HttpPost]
        public async Task<ActionResult> UserLoginAsync([FromBody] LoginRequestModel loginRequest)
        {
            (int code, object? response) = await _loginService.LoginAsync(loginRequest.UsernameOrEmail, loginRequest.Password);
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
                _logger.LogInformation("submit MFA code for login failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _loginService.SubmitMfaCodeForLoginAsync(username, request.MfaCode);
            return StatusCode(code, response);
        }



        [AllowAnonymous]
        [Route("register")]
        [HttpPost]
        public async Task<ActionResult> UserRegisterAsync([FromBody] RegisterRequestModel registerRequest)
        {
            (int code, object? response) = await _newAccountService.RegisterAsync(registerRequest.Username, registerRequest.Email, registerRequest.Password);
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
                _logger.LogInformation("logout failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _loginService.LogoutAsync(username);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenService.Roles.EmailNotVerified)]    // New account verification only.
        [Route("resend-email-verification-code")]
        [HttpPost]
        public async Task<ActionResult> UserResendEmailVerificationCodeAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("resend email verification code failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Email not verified implies is for new account, else full access is for manual email change.
            (int code, object? response) = await _newAccountService.ResendEmailVerificationCodeAsync(username);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenService.Roles.EmailNotVerified)]    // New account verification only.
        [Route("verify-email")]
        [HttpPost]
        public async Task<ActionResult> UserVerifyEmailForNewAccountAsync([FromBody] VerifyEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("new account email verification failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Email not verified implies is for new account, else full access is for manual email change.
            (int code, object? response) = await _newAccountService.VerifyEmailForNewAccountAsync(username, request.Code);
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

            await _resetPasswordService.ForgotPasswordAsync(request.UsernameOrEmail);
            return Ok();
        }

        [AllowAnonymous]        // Allow anonymous to enable forgot password functionality; request must include a confirmation code.
        [Route("initiate-reset-password")]
        [HttpPost]
        public async Task<ActionResult> UserInitiateResetPasswordAsync([FromBody] InitiatePasswordResetRequestModel request)
        {
            // NOTE: Initiating a password reset returns only an access token with the ResetPassword role. This endpoint ensures 
            //  that only valid users can receive this access token by requiring a short-duration one-time-use confirmation code
            //  alongside the passed-in account username or email.

            (int code, object? response) = await _resetPasswordService.InitiateResetPasswordAsync(request.UsernameOrEmail, request.Code);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenService.Roles.ResetPassword)]       // Only allow endpoint access for reset_password token roles.
        [Route("submit-reset-password")]
        [HttpPost]
        public async Task<ActionResult> UserSubmitResetPasswordAsync([FromBody] PasswordResetRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("submit reset password failed, incorrectly formatted reset (access) token in request header");
                return BadRequest("Malformed password reset token in API request.");
            }

            (int code, object? response) = await _resetPasswordService.SubmitResetPasswordAsync(username, request.NewPassword);
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
                _logger.LogInformation("change username failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.ChangeUsernameAsync(username, request.CurrentPassword, request.NewUsername);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only allow password change if user has full access.
        [Route("change-password")]
        [HttpPost]
        public async Task<ActionResult> UserChangePasswordAsync(ChangePasswordRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("change password failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.ChangePasswordAsync(username, request.CurrentPassword, request.NewPassword);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only allow email change if user has full access.
        [Route("submit-changed-email")]
        [HttpPost]
        public async Task<ActionResult> UserSubmitChangedEmailAsync(SubmitChangedEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("submit changed email failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.SubmitChangedEmailAsync(username, request.CurrentPassword, request.NewEmail);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only allow email change if user has full access.
        [Route("resend-changed-email-verification-code")]
        [HttpPost]
        public async Task<ActionResult> UserResendChangedEmailVerificationCodeAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("resend changed email verification code failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Email not verified implies is for new account, else full access is for manual email change.
            (int code, object? response) = await _accountService.ResendChangedEmailVerificationCodeAsync(username);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only allow email change if user has full access.
        [Route("verify-changed-email")]
        [HttpPost]
        public async Task<ActionResult> UserVerifyChangedEmailAsync(VerifyEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("verify changed email failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Email not verified implies is for new account, else full access is for manual email change.
            (int code, object? response) = await _accountService.VerifyChangedEmailAsync(username, request.Code);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenService.Roles.MfaNotEnabled + "," + TokenService.Roles.FullAccess)]
        [Route("begin-mfa-setup")]
        [HttpPost]
        public async Task<ActionResult> UserBeginMfaSetup()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("begin MFA setup failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaSetupService.BeginMfaSetup(username);
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
                _logger.LogInformation("verify MFA setup failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaSetupService.VerifyMfaSetupAsync(username, request.MfaCode);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenService.Roles.AwaitingMfa)]
        [Route("recover-mfa")]
        [HttpPost]
        public async Task<ActionResult> UserRecoverMfa(RecoverMfaRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("recover MFA configuration failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaSetupService.RecoverMfaAsync(username, request.RecoveryCode);
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
                _logger.LogInformation("regenerate MFA recovery code failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaSetupService.RegenerateMfaRecoveryCodeAsync(username);
            return StatusCode(code, response);
        }

        #endregion

        #region Public: Secondary Email Setup

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only fully-logged-in users can configure secondary email.
        [Route("submit-secondary-email")]
        [HttpPost]
        public async Task<ActionResult> UserSubmitSecondaryEmailAsync(SubmitSecondaryEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("submit secondary email failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.SubmitSecondaryEmailAsync(username, request.CurrentPassword, request.SecondaryEmail);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only fully-logged-in users can configure secondary email.
        [Route("resend-secondary-verification-code")]
        [HttpPost]
        public async Task<ActionResult> UserResendSecondaryEmailVerificationCodeAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("resend secondary email verification code failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.ResendSecondaryEmailVerificationCodeAsync(username);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only fully-logged-in users can configure secondary email.
        [Route("verify-secondary-email")]
        [HttpPost]
        public async Task<ActionResult> UserVerifySecondaryEmailAsync(VerifySecondaryEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("verify secondary email failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.VerifySecondaryEmailAsync(username, request.Code);
            return StatusCode(code, response);
        }

        #endregion

        #region Public: User play game logic

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only fully-logged-in can play the game.
        [Route("play-game")]
        [HttpPost]
        public async Task<ActionResult> UserPlayGame()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("play game from launcher failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _launcherService.PlayGameFromLauncherAsync(username);
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
                _logger.LogInformation("ping in launcher failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _launcherService.PingInLauncherAsync(username);
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
                _logger.LogInformation("notify launcher exit failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _launcherService.NotifyLauncherExitAsync(username);
            return (code == 204) ? NoContent() : StatusCode(code, response);
        }

        #endregion



        #region Private Static: Utility

        private static bool TryReadAccessTokenData(ClaimsPrincipal user, [NotNullWhen(true)] out string? username,
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
