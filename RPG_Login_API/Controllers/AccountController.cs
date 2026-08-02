using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using RPG_Login_API.Models.Requests;
using RPG_Login_API.Services;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;

namespace RPG_Login_API.Controllers
{
    [EnableRateLimiting("IpLimitPolicy")]   // Limit requests from any specific IP.
    [Authorize]             // Denotes that all requests BY DEFAULT require JWT token authentication (passed in the HTTP request).
    [Route("account")]      // Makes all endpoints begin with "[URL]/account/"; endpoint methods below define suffixes.
    [ApiController]
    public class AccountController : Controller
    {
        private readonly IAccountService _accountService;
        private readonly ILogger _logger;

        public AccountController(IAccountService accountService, ILogger<AccountController> logger)
        {
            _accountService = accountService;
            _logger = logger;
        }



        #region Basic Account Settings

        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only allow username change if user has full access.
        [Route("change-username")]
        [HttpPost]
        public async Task<ActionResult> UserChangeUsernameAsync([FromBody] ChangeUsernameRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("change username failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.ChangeUsernameAsync(username, request.CurrentPassword, request.NewUsername);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only allow password change if user has full access.
        [Route("change-password")]
        [HttpPost]
        public async Task<ActionResult> UserChangePasswordAsync(ChangePasswordRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("change password failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.ChangePasswordAsync(username, request.CurrentPassword, request.NewPassword);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only allow email change if user has full access.
        [Route("submit-changed-email")]
        [HttpPost]
        public async Task<ActionResult> UserSubmitChangedEmailAsync(SubmitChangedEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("submit changed email failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.SubmitChangedEmailAsync(username, request.CurrentPassword, request.NewEmail);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only allow email change if user has full access.
        [Route("resend-changed-email-verification-code")]
        [HttpPost]
        public async Task<ActionResult> UserResendChangedEmailVerificationCodeAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("resend changed email verification code failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Email not verified implies is for new account, else full access is for manual email change.
            (int code, object? response) = await _accountService.ResendChangedEmailVerificationCodeAsync(username);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only allow email change if user has full access.
        [Route("verify-changed-email")]
        [HttpPost]
        public async Task<ActionResult> UserVerifyChangedEmailAsync(VerifyEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("verify changed email failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Email not verified implies is for new account, else full access is for manual email change.
            (int code, object? response) = await _accountService.VerifyChangedEmailAsync(username, request.Code);
            return StatusCode(code, response);
        }

        #endregion



        #region Secondary Email

        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only fully-logged-in users can configure secondary email.
        [Route("submit-secondary-email")]
        [HttpPost]
        public async Task<ActionResult> UserSubmitSecondaryEmailAsync(SubmitSecondaryEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("submit secondary email failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.SubmitSecondaryEmailAsync(username, request.CurrentPassword, request.SecondaryEmail);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only fully-logged-in users can configure secondary email.
        [Route("resend-secondary-verification-code")]
        [HttpPost]
        public async Task<ActionResult> UserResendSecondaryEmailVerificationCodeAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("resend secondary email verification code failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.ResendSecondaryEmailVerificationCodeAsync(username);
            return StatusCode(code, response);
        }

        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only fully-logged-in users can configure secondary email.
        [Route("verify-secondary-email")]
        [HttpPost]
        public async Task<ActionResult> UserVerifySecondaryEmailAsync(VerifySecondaryEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("verify secondary email failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _accountService.VerifySecondaryEmailAsync(username, request.Code);
            return StatusCode(code, response);
        }

        #endregion

    }
}
