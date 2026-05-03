using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using RPG_Login_API.Models.UserRequests;
using RPG_Login_API.Services;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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

        private readonly ILoginApiService _service;
        private readonly ILogger _logger;

        public LoginApiController(ILoginApiService service, ILogger<LoginApiController> logger)
        {
            // Adding the LoginApiService object as a constructor parameter utilizes ASP.NET's built-in dependency
            //  injection system. The controller is effectively requesting the Service from the services container
            //  configured in Program.cs.
            _service = service;
            _logger = logger;
        }



        #region Public: User Account Operations

        [AllowAnonymous]                // Logging in requires allowing un-authorized users to access endpoint.
        [Route("users/login-refresh")]
        [HttpPost]
        public async Task<ActionResult> UserLoginFromRefreshAsync([FromBody] RefreshLoginRequestModel request)
        {
            // Validate request body immediately.
            if (request.RefreshToken == string.Empty)
            {
                _logger.LogInformation("Client refresh login failed: missing refresh token in request body");
                return BadRequest("Missing refresh token in API request.");
            }

            try
            {
                var responseModel = await _service.UserLoginFromRefreshAsync(request.RefreshToken);

                _logger.LogInformation($"User refresh login successful (username: {responseModel.Username}) with login code {responseModel.LoginStatusCode}");
                return Ok(responseModel);
            }
            catch (KeyNotFoundException ex)
            {
                _logger.LogInformation(ex.Message);
                return NotFound("Failed to find user account for the provided username.");
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogInformation(ex.Message);
                return Unauthorized("Invalid or expired refresh token.");
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during refresh login, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during refresh login, please try again.");
            }
        }



        [AllowAnonymous]        // Allow un-authorized users to access this endpoint (not logged in = no token yet).
        [Route("users/login")]  // Appends to route defined in class declaration. Can begin with '/' to override prefix in class declaration.
        [HttpPost]
        public async Task<ActionResult> UserLoginAsync([FromBody] LoginRequestModel loginRequest)
        {
            // Immediately reject any request with empty input fields.
            if (loginRequest.UsernameOrEmail == string.Empty || loginRequest.Password == string.Empty)
            {
                _logger.LogInformation("Client login failed: missing username/email or password fields in request body");
                return BadRequest("Missing username/email or password in API request.");
            }

            try
            {
                var responseModel = await _service.UserLoginAsync(loginRequest.UsernameOrEmail, loginRequest.Password);

                _logger.LogInformation($"User login successful (username: {responseModel.Username}) with login code {responseModel.LoginStatusCode}");
                return Ok(responseModel);
            }
            catch (KeyNotFoundException ex)
            {
                // IMPORTANT: Return generic failure to prevent username/email lookup attacks.
                _logger.LogInformation(ex.Message);
                return Unauthorized("Invalid username/email or password, please try again.");
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogInformation(ex.Message);
                return Unauthorized("Invalid username/email or password, please try again.");
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during login, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during login, please try again.");
            }
        }



        [AllowAnonymous]
        [Route("users/register")]
        [HttpPost]
        public async Task<ActionResult> UserRegisterAsync([FromBody] RegisterRequestModel registerRequest)
        {
            // Verify validity of email, username, and password with simple(?) regex. This is also checked client-side.
            string emailPattern = @"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$";
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
            string passwordPattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&]).{8,}$";  // Password, 8+ chars, 1+ upper lower digit symbol
            if (!Regex.IsMatch(registerRequest.Password, passwordPattern))
            {
                _logger.LogInformation($"Client registration failed, password failed regex check (username: {registerRequest.Username})");
                return UnprocessableEntity("New password must be 8+ characters and include at least one uppercase letter, lowercase letter, digit, and symbol.");

                // TODO: ADD CHECK TO PREVENT GENERIC PASSWORDS (USE LIBRARY FOR THIS). RETURN 422 'UNPROCESSABLE ENTITY' IF GENERIC.
                // https://github.com/andrewlock/CommonPasswordsValidator
            }

            try
            {
                var responseModel = await _service.UserRegisterAsync(registerRequest.Username, registerRequest.Email, registerRequest.Password);

                _logger.LogInformation($"New user registration successful (username: {registerRequest.Username} | email: {registerRequest.Email})");
                return Ok(responseModel);
            }
            catch (ArgumentException ex)
            {
                _logger.LogInformation(ex.Message);
                return Conflict(ex.Message);    // Directly send message because it denotes whether username or email is already in use.
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during registration, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during registration, please try again.");
            }
        }



        [Authorize(Roles = TokenService.Roles.Any)]     // Require access token, any role. Only allow authenticated user to log out.
        [Route("users/logout")]
        [HttpPost]
        public async Task<ActionResult> UserLogoutAsync()
        {
            // Retrieve account username and GUID from token.
            if (!TryReadUsernameAndGuidFromAccessToken(User, out var username, out var guid))
            {
                _logger.LogInformation("Client logout failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            try
            {
                await _service.UserLogoutAsync(username);

                _logger.LogInformation($"User logout successful (username: {username})");
                return Ok();
            }
            catch (KeyNotFoundException ex)
            {
                _logger.LogInformation(ex.Message);
                return NotFound("Failed to find user account for the provided username.");
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during logout, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during logout, please try again.");
            }
        }

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only considered online if logged in with full access.
        [Route("users/ping-online-status")]
        [HttpGet]
        public async Task<ActionResult> UserPingOnlineStatus()
        {
            // Retrieve account username and GUID from token.
            if (!TryReadUsernameAndGuidFromAccessToken(User, out var username, out var guid))
            {
                _logger.LogInformation("Client ping online status failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            try
            {
                await _service.UserPingOnlineStatusAsync(username);

                _logger.LogInformation($"User ping online status successful (username: {username})");
                return Ok();
            }
            catch (KeyNotFoundException ex)
            {
                _logger.LogInformation(ex.Message);
                return NotFound("Failed to find user account for the provided username.");
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during online status ping, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during online status ping, please try again.");
            }
        }



        [AllowAnonymous]            // Anyone can request a confirmation code (necessary to allow forgot password functionality).
        [Route("users/confirmation-code")]
        [HttpPost]
        public async Task<ActionResult> UserSendConfirmationCodeAsync([FromBody] SendConfirmationCodeRequestModel request)
        {
            // Immediately reject any request with an empty account username/email body.
            if (request.UsernameOrEmail == string.Empty)
            {
                _logger.LogInformation("Client confirmation code request failed, empty username/email field in request body");
                return BadRequest("Missing username/email in API request.");
            }

            // NOTE: We always return 200 (OK) to prevent the confirmation code endpoint from being used as a method
            //  for malicious actors to lookup existing usernames/emails. By always returning 200 (OK), users cannot
            //  know whether an account is associated with the username/email.

            try
            {
                await _service.UserSendConfirmationCodeAsync(request.UsernameOrEmail);

                _logger.LogInformation($"User confirmation code request successful (username/email: {request.UsernameOrEmail})");
                return Ok();
            }
            catch (KeyNotFoundException ex)
            {
                _logger.LogInformation(ex.Message);
                return Ok();                            // See note above.
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogInformation(ex.Message);
                return Ok();                            // See note above.
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during code request, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during code request, please try again.");
            }
        }



        [Authorize(Roles = TokenService.Roles.EmailNotVerified)]    // Only allow endpoint access for accounts not yet verified.
        [Route("users/verify-email")]
        [HttpPost]
        public async Task<ActionResult> UserVerifyAccountEmail([FromBody] VerifyEmailRequestModel request)
        {
            // Retrieve account username and GUID from token.
            if (!TryReadUsernameAndGuidFromAccessToken(User, out var username, out var guid))
            {
                _logger.LogInformation("Client email verification failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            try
            {
                var responseModel = await _service.UserVerifyAccountEmailAsync(username, request.Code);

                _logger.LogInformation($"User email verification successful (username: {username})");
                return Ok(responseModel);
            }
            catch (KeyNotFoundException ex)
            {
                _logger.LogInformation(ex.Message);
                return NotFound("Failed to find user account for the provided username.");
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogInformation(ex.Message);
                return Unauthorized("Invalid or expired confirmation code.");
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during email verification, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during email verification, please try again.");
            }
        }



        [AllowAnonymous]        // Allow anonymous to enable forgot password functionality; request must include a confirmation code.
        [Route("users/request-password-reset")]
        [HttpPost]
        public async Task<ActionResult> UserRequestPasswordResetAsync([FromBody] RequestPasswordResetRequestModel request)
        {
            // NOTE: Requesting a password reset returns only an access token with the ResetPassword role. This endpoint ensures 
            //  that only valid users can receive this access token by requiring a short-duration one-time-use confirmation code
            //  alongside the passed-in account username or email.
            // We are not explicitly using a separate Reset Token because we can just use a very short access token with the reset role.

            // Immediately reject any request with an empty account username/email OR missing confirmation code in request body.
            if (request.UsernameOrEmail == string.Empty || request.Code == string.Empty)
            {
                _logger.LogInformation("Client request password reset failed, empty username/email or confirmation code field request body");
                return BadRequest("Missing username/email or confirmation code in API request.");
            }

            try
            {
                var responseModel = await _service.UserRequestPasswordResetAsync(request.UsernameOrEmail, request.Code);

                _logger.LogInformation($"User request password reset successful (username/email: {request.UsernameOrEmail})");
                return Ok(responseModel);
            }
            catch (KeyNotFoundException ex)
            {
                // IMPORTANT: Do not tell the client whether username/email is valid to prevent lookup attacks.
                _logger.LogInformation(ex.Message);
                return Unauthorized("Invalid or expired confirmation code.");
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogInformation(ex.Message);
                return Unauthorized("Invalid or expired confirmation code.");
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during reset request, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during reset request, please try again.");
            }
        }



        [Authorize(Roles = TokenService.Roles.ResetPassword)]       // Only allow endpoint access for reset_password token roles.
        [Route("users/reset-password")]
        [HttpPost]
        public async Task<ActionResult> UserResetPasswordAsync([FromBody] PasswordResetRequestModel request)
        {
            // NOTE: On successful password reset, the user is fully logged-out server side.

            // Retrieve account username and GUID from token.
            if (!TryReadUsernameAndGuidFromAccessToken(User, out var username, out var guid))
            {
                _logger.LogInformation("Client password reset failed, incorrectly formatted reset (access) token in request header");
                return BadRequest("Malformed password reset token in API request.");
            }

            // Verify passed-in password matches basic password regex. This is also checked client-side.
            string passwordPattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&]).{8,}$";  // Password, 8+ chars, 1+ upper lower digit symbol
            if (!Regex.IsMatch(request.NewPassword, passwordPattern))
            {
                _logger.LogInformation($"Client password reset failed, new password failed regex check (username: {username})");
                return UnprocessableEntity("New password must be 8+ characters and include at least one uppercase letter, lowercase letter, digit, and symbol.");
                
                // TODO: ADD CHECK TO PREVENT GENERIC PASSWORDS (USE LIBRARY FOR THIS). RETURN 422 'UNPROCESSABLE ENTITY' IF GENERIC.
                // https://github.com/andrewlock/CommonPasswordsValidator
            }

            try
            {
                await _service.UserResetPasswordAsync(username, request.NewPassword);

                _logger.LogInformation($"User password reset successful (username: {username})");
                return Ok();
            }
            catch (KeyNotFoundException ex)
            {
                _logger.LogInformation(ex.Message);
                return NotFound("Failed to find user account for the provided username.");
            }
            catch (InvalidOperationException ex)
            {
                // CUSTOM 493 STATUS CODE FOR NOT YET (403 Forbidden is reserved for bad token).
                _logger.LogInformation(ex.Message);
                return StatusCode(493, "Cannot change password within 24 hours of previous change.");
            }
            catch (ArgumentException ex)
            {
                _logger.LogInformation(ex.Message);
                return Conflict("New password cannot be the same as old password.");
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during password reset, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during password reset, please try again.");
            }
        }

        [Authorize(Roles = TokenService.Roles.FullAccess)]      // Only allow username change if user has full access.
        [Route("users/change-username")]
        [HttpPost]
        public async Task<ActionResult> UserChangeUsernameAsync([FromBody] ChangeUsernameRequestModel request)
        {
            // Retrieve account's existing username and GUID from token.
            if (!TryReadUsernameAndGuidFromAccessToken(User, out var username, out var guid))
            {
                _logger.LogInformation("Client username change failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            // Verify new username is not the same as the old username.
            if (string.Equals(username, request.NewUsername))
            {
                _logger.LogInformation("Client username change failed, passed-in new username is the same as existing username");
                return Conflict("New username cannot be the same as old username.");
            }

            // Verify passed-in username matches basic username regex. This is also checked client-side.
            string usernamePattern = @"^[a-zA-Z0-9_]{5,20}$";                   // Username, 5-20 chars, upper lower digit underscore
            if (!Regex.IsMatch(request.NewUsername, usernamePattern))
            {
                _logger.LogInformation($"Client username change failed, new username failed regex check (username: {username})");
                return UnprocessableEntity("New username must be 5-20 characters and can only include uppercase and lowercase letters, digits, and underscores.");
            }

            try
            {
                // If username passes regex, account for this user exists, and the user is allowed to change, actually change username.
                var responseModel = await _service.UserChangeUsernameAsync(username, request.NewUsername);

                _logger.LogInformation($"User successfully changed username (old username: {username} | new username: {request.NewUsername})");
                return Ok(responseModel);
            }
            catch (KeyNotFoundException ex)
            {
                _logger.LogInformation(ex.Message);
                return NotFound("Failed to find user account for the provided username.");
            }
            catch (InvalidOperationException ex)
            {
                // CUSTOM 493 STATUS CODE FOR NOT YET (403 Forbidden is reserved for bad token).
                _logger.LogInformation(ex.Message);
                return StatusCode(493, "Cannot change username within 30 days of previous change.");
            }
            catch (TimeoutException ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(503, "An unexpected database error occurred during username change, please try again.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return Problem("An unexpected error occurred during username change, please try again.");
            }
        }


        // NOTE: LEGITIMATE ENDPOINTS WILL ONLY ALLOW ACCESS VIA THE full_access ROLE; OTHER ROLES WILL NOT BE ALLOWED

        #endregion

        #region Public: Admin Account Access

        // These methods should use the '/api/admin/_' endpoint structure.

        #endregion

        #region Public: Ping (async)

        [AllowAnonymous]
        [Route("ping")]
        [HttpGet]
        public async Task<ActionResult> Ping()
        {
            return Ok();
        }

        #endregion

        #region Private: Utility

        private bool TryReadUsernameAndGuidFromAccessToken(ClaimsPrincipal user, [NotNullWhen(true)] out string? username, [NotNullWhen(true)] out string? guid)
        {
            username = user.Identity?.Name;                                 // UniqueName maps directly to Identity.Name.
            guid = user.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;      // We use Jti for GUID on token creation.

            // Returns true when username and GUID are valid, false otherwise.
            return (username != null && guid != null);
        }

        #endregion
    }
}
