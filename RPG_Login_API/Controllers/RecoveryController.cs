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
    [Route("recovery")]     // Makes all endpoints begin with "[URL]/recovery/"; endpoint methods below define suffixes.
    [ApiController]
    public class RecoveryController : Controller
    {
        private readonly IRecoveryService _recoveryService;
        private readonly ILogger _logger;

        public RecoveryController(IRecoveryService resetPasswordService, ILogger<RecoveryController> logger)
        {
            _recoveryService = resetPasswordService;
            _logger = logger;
        }



        [AllowAnonymous]            // Anyone can request a confirmation code (necessary to allow forgot password functionality).
        [Route("forgot-password")]
        [HttpPost]
        public async Task<ActionResult> UserForgotPasswordAsync([FromBody] ForgotPasswordRequestModel request)
        {
            // NOTE: We always return 200 (OK) to prevent the confirmation code endpoint from being used as a method
            //  for malicious actors to lookup existing usernames/emails. By always returning 200 (OK), users cannot
            //  know whether an account is associated with the username/email.

            await _recoveryService.ForgotPasswordAsync(request.UsernameOrEmail);
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

            (int code, object? response) = await _recoveryService.InitiateResetPasswordAsync(request.UsernameOrEmail, request.Code);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.ResetPassword)]       // Only allow endpoint access for reset_password token roles.
        [Route("submit-reset-password")]
        [HttpPost]
        public async Task<ActionResult> UserSubmitResetPasswordAsync([FromBody] PasswordResetRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("submit reset password failed, incorrectly formatted reset (access) token in request header");
                return BadRequest("Malformed password reset token in API request.");
            }

            (int code, object? response) = await _recoveryService.SubmitResetPasswordAsync(username, request.NewPassword);
            return StatusCode(code, response);
        }
    }
}
