using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using RPG_Login_API.Models.UserRequests;
using RPG_Login_API.Services;
using RPG_Login_API.Utility;

namespace RPG_Login_API.Controllers
{
    // PERMISSION ROLES CURRENTLY USED ARE: "user",

    [Authorize]         // Denotes that all requests BY DEFAULT require JWT token authentication (passed in the HTTP request).
                        //  The token passed to the controller must be the access token. Refresh tokens are handled manually.
    [Route("api")]      // Makes all endpoints begin with "[URL]/api"; endpoint methods below define suffixes.
    [ApiController]
    public class LoginApiController : Controller
    {
        // TODO: CONSIDER USING GLOBAL EXCEPTION HANDLING INTEAD OF TRY-CATCH BLOCKS IN EACH CONTROLLER METHOD

        // TODO: BREAK USER CONTROLLER AND ADMIN CONTROLLERS INTO SEPARATE CLASSES

        private readonly LoginApiService service;

        public LoginApiController(LoginApiService service)
        {
            // Adding the LoginApiService object as a constructor parameter utilizes ASP.NET's built-in dependency
            //  injection system. The controller is effectively requesting the Service from the services container
            //  configured in Program.cs.
            this.service = service;
        }



        #region Public: User Account Access

        [AllowAnonymous]                // Logging in requires allowing un-authorized users to access endpoint.
        [Route("users/login/refresh")]
        [HttpPost]
        public async Task<ActionResult> UserLoginFromRefreshAsync([FromBody] LoginFromRefreshRequestModel request)
        {
            // Validate request body immediately.
            if (request.RefreshToken == string.Empty)
            {
                LogUtility.LogError("LoginFromRefresh", "client login from refresh failed, missing refresh token in request body");
                return BadRequest("Failed to login with refresh token: refresh token field cannot be empty.");
            }

            try
            {
                var responseModel = await service.UserLoginFromRefreshAsync(request.RefreshToken);
                if (responseModel == null)
                {
                    LogUtility.LogError("Login", $"client login from refresh failed, invalid or expired token");
                    return Unauthorized("Login failed: invalid or expired refresh token.");
                }

                LogUtility.LogMessage("Login", $"client successfully logged in");
                return Ok(responseModel);
            }
            catch (Exception ex)
            {
                LogUtility.LogError("LoginFromRefresh", ex.Message);
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
                LogUtility.LogError("Login", "invalid client login request, missing username or password fields in request body");
                return BadRequest("Login failed: username and password fields must not be empty.");
            }

            try
            {
                var responseModel = await service.UserLoginAsync(loginRequest.Username, loginRequest.Password);
                if (responseModel == null)
                {
                    LogUtility.LogError("Login", $"client login failed (username {loginRequest.Username}), invalid username or password");
                    return Unauthorized("Login failed: Invalid username or password.");
                }

                LogUtility.LogMessage("Login", $"client successfully logged in (username {loginRequest.Username})");
                return Ok(responseModel);
            }
            catch (Exception ex)
            {
                LogUtility.LogError("Login", ex.Message);
                return Problem();
            }
            
            // Consider adding a finally{} block that destroys the LoginRequestModel, removing raw password from memory.
        }

        #endregion

        #region Public: Admin Account Access

        // These methods should use the '/api/admin/_' endpoint structure.

        #endregion
    }
}
