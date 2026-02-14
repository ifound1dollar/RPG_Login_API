using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using RPG_Login_API.Models.UserRequests;
using RPG_Login_API.Services;
using RPG_Login_API.Utility;
using System.IdentityModel.Tokens.Jwt;
using System.Text.RegularExpressions;

namespace RPG_Login_API.Controllers
{
    // PERMISSION ROLES CURRENTLY USED ARE: "not_confirmed", "reset_password", "full_access"

    [Authorize]         // Denotes that all requests BY DEFAULT require JWT token authentication (passed in the HTTP request).
                        //  The token passed to the controller must be the access token. Refresh tokens are handled manually.
    [Route("api")]      // Makes all endpoints begin with "[URL]/api"; endpoint methods below define suffixes.
    [ApiController]
    public class LoginApiController : Controller
    {
        // TODO: CONSIDER USING GLOBAL EXCEPTION HANDLING MIDDLEWARE INSTEAD OF TRY-CATCH BLOCKS IN EACH CONTROLLER METHOD

        private readonly LoginApiService _service;
        private readonly ILogger _logger;

        public LoginApiController(LoginApiService service, ILogger<LoginApiController> logger)
        {
            // Adding the LoginApiService object as a constructor parameter utilizes ASP.NET's built-in dependency
            //  injection system. The controller is effectively requesting the Service from the services container
            //  configured in Program.cs.
            _service = service;
            _logger = logger;
        }



        #region Public: User Account Access

        [AllowAnonymous]                // Logging in requires allowing un-authorized users to access endpoint.
        [Route("users/login-refresh")]
        [HttpPost]
        public async Task<ActionResult> UserLoginFromRefreshAsync([FromBody] RefreshLoginRequestModel request)
        {
            // Validate request body immediately.
            if (request.RefreshToken == string.Empty)
            {
                _logger.LogInformation("Client refresh login failed, missing refresh token in request body");
                return BadRequest("Failed to login with refresh token: refresh token field cannot be empty.");
            }

            try
            {
                var responseModel = await _service.UserLoginFromRefreshAsync(request.RefreshToken);
                if (responseModel == null)
                {
                    return Unauthorized("Failed to login with refresh token: invalid or expired refresh token.");
                }

                return Ok(responseModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem();
            }
        }

        [AllowAnonymous]        // Allow un-authorized users to access this endpoint (not logged in = no token yet).
        [Route("users/login")]  // Appends to route defined in class declaration. Can begin with '/' to override prefix in class declaration.
        [HttpPost]
        public async Task<ActionResult> UserLoginAsync([FromBody] LoginRequestModel loginRequest)
        {
            // Immediately reject any request with empty input fields.
            if (loginRequest.Username == string.Empty || loginRequest.Password == string.Empty)
            {
                _logger.LogInformation("Client login failed, missing username or password fields in request body");
                return BadRequest("Login failed: username and password fields must not be empty.");
            }

            try
            {
                var responseModel = await _service.UserLoginAsync(loginRequest.Username, loginRequest.Password);
                if (responseModel == null)
                {
                    return Unauthorized("Login failed: invalid username or password.");
                }

                return Ok(responseModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem();
            }
            
            // Consider adding a finally{} block that destroys the LoginRequestModel, removing raw password from memory.
        }

        [AllowAnonymous]
        [Route("users/register")]
        [HttpPost]
        public async Task<ActionResult> UserRegisterAsync([FromBody] RegisterRequestModel registerRequest)
        {
            // Verify validity of email, username, and password with simple(?) regex.
            string emailPattern = @"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$";          // Email
            string usernamePattern = @"^[a-zA-Z0-9_]{5,20}$";                                   // Username, 5-20 chars, upper lower digit underscore
            string passwordPattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$";   // Password, 8+ chars, 1+ upper lower digit symbol
            if (!Regex.IsMatch(registerRequest.Email, emailPattern) || !Regex.IsMatch(registerRequest.Username, usernamePattern)
                || !Regex.IsMatch(registerRequest.Password, passwordPattern))
            {
                _logger.LogInformation("Client registration failed (username {username}), email/username/password failed regex check",
                    registerRequest.Username);
                return BadRequest("Registration failed: invalid input for email, username, or password");
            }

            // TODO: ADD CHECK TO PREVENT GENERIC PASSWORDS (USE LIBRARY FOR THIS). RETURN 422 'UNPROCESSABLE ENTITY' IF GENERIC.
            // https://github.com/andrewlock/CommonPasswordsValidator

            try
            {
                var responseModel = await _service.UserRegisterAsync(registerRequest.Username, registerRequest.Email, registerRequest.Password);
                if (responseModel == null)
                {
                    return Conflict("Registration failed: unavailable username or email");
                }

                return Ok(responseModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem();
            }
        }

        [Authorize(Roles = TokenService.Roles.Any)]     // Require access token, any role. Only allow authenticated user to log out.
        [Route("users/logout")]
        [HttpPost]
        public async Task<ActionResult> UserLogoutAsync()
        {
            // Retrieve account username and GUID from token.
            var username = User.Identity?.Name;                                 // UniqueName maps directly to Identity.Name.
            var guid = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;      // We use Jti for GUID on token creation.
            if (username == null || guid == null)
            {
                _logger.LogInformation("Client logout failed, incorrectly formatted access token in request header");
                return BadRequest("Failed to logout: incorrectly formatted bearer token.");
            }

            try
            {
                await _service.UserLogoutAsync(username, guid);
                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem();
            }
        }

        [AllowAnonymous]            // Anyone can request a confirmation code (necessary to allow forgot password functionality).
        [Route("users/confirmation-code")]
        [HttpPost]
        public async Task<ActionResult> UserSendConfirmationCodeAsync([FromBody] SendConfirmationCodeRequestModel request)
        {
            // TODO: CALL SERVICE METHOD TO FIND ACCOUNT BY PASSED-IN EMAIL OR USERNAME, THEN SEND CONFIRMATION CODE TO EMAIL

            return Ok();
        }

        [Authorize(Roles = TokenService.Roles.EmailNotVerified)]    // Only allow endpoint access for accounts not yet verified.
        [Route("users/verify-email")]
        [HttpPost]
        public async Task<ActionResult> UserVerifyAccountEmail([FromBody] VerifyEmailRequestModel request)
        {
            // Retrieve account username and GUID from token.
            var username = User.Identity?.Name;                                 // UniqueName maps directly to Identity.Name.
            var guid = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;      // We use Jti for GUID on token creation.
            if (username == null || guid == null)
            {
                _logger.LogInformation("Client logout failed, incorrectly formatted access token in request header");
                return BadRequest("Failed to logout: incorrectly formatted bearer token.");
            }



            // TODO: CALL SERVICE METHOD TO CHECK FOR CODE WITH USERNAME MAKING REQUEST, VERIFYING EMAIL IF MATCH AND NOT EXPIRED
            // NOTE: Should invalidate the token GUID sent with this request upon successful verification (need new full-access token).
            // SHOULD WE RETURN A FULL ACCESS TOKEN? PROBABLY

            return Ok();
        }

        [AllowAnonymous]        // Allow anonymous to enable forgot password functionality; request must include a confirmation code.
        [Route("users/request-password-reset")]
        [HttpPost]
        public async Task<ActionResult> UserRequestPasswordResetAsync([FromBody] RequestPasswordResetRequestModel request)
        {
            // TODO: CALL SERVICE METHOD TO FIND ACCOUNT MATCHING USERNAMEOREMAIL, THEN RETURN ACCESS TOKEN WITH RESET ROLE IF CONFIRMATION CODE MATCHES
            // NOTE: We are not explicitly using a separate Reset Token because we can just use a very short
            //  access token with the reset role.

            return Ok(); 
        }

        [Authorize(Roles = TokenService.Roles.ResetPassword)]       // Only allow endpoint access for reset_password token roles.
        [Route("users/reset-password")]
        [HttpPost]
        public async Task<ActionResult> UserResetPasswordAsync([FromBody] Models.UserRequests.ResetPasswordRequest request)
        {
            // Retrieve account username and GUID from token.
            var username = User.Identity?.Name;                                 // UniqueName maps directly to Identity.Name.
            var guid = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;      // We use Jti for GUID on token creation.
            if (username == null || guid == null)
            {
                _logger.LogInformation("Client logout failed, incorrectly formatted access token in request header");
                return BadRequest("Failed to logout: incorrectly formatted bearer token.");
            }



            // TODO: CALL SERVICE METHOD TO ENSURE ACCOUNT WITH USERNAME EXISTS (TOKEN IS VALIDATED HERE), THEN RESET PASSWORD IF REAL
            // NOTE: We must invalidate (blacklist) the token GUID because full_access login is now needed.

            return Ok();
        }

        #endregion

        #region Public: Admin Account Access

        // These methods should use the '/api/admin/_' endpoint structure.

        #endregion
    }
}
