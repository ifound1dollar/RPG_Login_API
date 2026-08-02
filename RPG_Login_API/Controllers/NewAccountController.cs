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
    [Route("newaccount")]   // Makes all endpoints begin with "[URL]/newaccount/"; endpoint methods below define suffixes.
    [ApiController]
    public class NewAccountController : Controller
    {
        private readonly INewAccountService _newAccountService;
        private readonly ILogger _logger;

        public NewAccountController(INewAccountService newAccountService, ILogger<NewAccountController> logger)
        {
            _newAccountService = newAccountService;
            _logger = logger;
        }



        [AllowAnonymous]
        [Route("register")]
        [HttpPost]
        public async Task<ActionResult> UserRegisterAsync([FromBody] RegisterRequestModel registerRequest)
        {
            (int code, object? response) = await _newAccountService.RegisterAsync(registerRequest.Username, registerRequest.Email, registerRequest.Password);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.EmailNotVerified)]    // New account verification only.
        [Route("resend-email-verification-code")]
        [HttpPost]
        public async Task<ActionResult> UserResendEmailVerificationCodeAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("resend email verification code failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Email not verified implies is for new account, else full access is for manual email change.
            (int code, object? response) = await _newAccountService.ResendEmailVerificationCodeAsync(username);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.EmailNotVerified)]    // New account verification only.
        [Route("verify-email")]
        [HttpPost]
        public async Task<ActionResult> UserVerifyEmailForNewAccountAsync([FromBody] VerifyEmailRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("new account email verification failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Email not verified implies is for new account, else full access is for manual email change.
            (int code, object? response) = await _newAccountService.VerifyEmailForNewAccountAsync(username, request.Code);
            return StatusCode(code, response);
        }
    }
}
