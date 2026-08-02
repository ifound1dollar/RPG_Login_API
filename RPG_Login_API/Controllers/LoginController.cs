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
    [Route("auth")]         // Makes all endpoints begin with "[URL]/auth/"; endpoint methods below define suffixes.
    [ApiController]
    public class LoginController : Controller
    {
        private readonly ILoginService _loginService;
        private readonly ILogger _logger;

        public LoginController(ILoginService loginService, ILogger<LoginController> logger)
        {
            _loginService = loginService;
            _logger = logger;
        }



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



        [Authorize(Roles = TokenUtility.Roles.AwaitingMfa)]
        [Route("submit-mfa-code")]
        [HttpPost]
        public async Task<ActionResult> UserSubmitMfaCodeForLogin(SubmitMfaCodeRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("submit MFA code for login failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _loginService.SubmitMfaCodeForLoginAsync(username, request.MfaCode);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.Any)]     // Require access token, any role. Only allow authenticated user to log out.
        [Route("logout")]
        [HttpPost]
        public async Task<ActionResult> UserLogoutAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("logout failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _loginService.LogoutAsync(username);
            return StatusCode(code, response);
        }
    }
}
