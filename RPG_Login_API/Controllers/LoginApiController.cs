using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RPG_Login_API.Models.UserRequests;
using RPG_Login_API.Services;

namespace RPG_Login_API.Controllers
{
    // PERMISSION ROLES CURRENTLY USED ARE: "user",

    [Authorize]         // Denotes that all requests BY DEFAULT require JWT token authentication (passed in the HTTP request).
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

        [AllowAnonymous]        // Allow un-authorized users to access this endpoint (not logged in = no token yet).
        [Route("users/login")]  // Appends to route defined in class declaration. Can begin with '/' to override prefix in class declaration.
        [HttpPost]
        public async Task<ActionResult> UserLoginAsync([FromBody] LoginRequestModel loginRequest)
        {
            // Immediately reject any request with empty input fields.
            if (loginRequest.Username == string.Empty || loginRequest.Password == string.Empty)
            {
                // TODO: ADD LOGUTILITY CALL TO LOG ERROR
                return BadRequest("Login failed: username and password fields must not be empty.");
            }

            try
            {
                var responseModel = await service.UserLoginAsync(loginRequest.Username, loginRequest.Password);
                if (responseModel == null)
                {
                    // TODO: LOG ERROR
                    return Unauthorized("Login failed: Invalid username or password.");
                }

                return Ok(responseModel);
            }
            catch (Exception ex)
            {
                // TODO: LOG ERROR USING LOGUTILITY CLASS, INSTEAD OF RAW CONSOLE.WRITELINE()
                Console.WriteLine(ex);
                return Problem();
            }
            finally
            {
                // TODO: Destroy LoginRequestModel object here for security reasons.
            }
        }

        #endregion

        #region Public: Admin Account Access

        // These methods should use the '/api/admin/_' endpoint structure.

        #endregion
    }
}
