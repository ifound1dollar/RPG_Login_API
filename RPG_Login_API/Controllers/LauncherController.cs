using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;

namespace RPG_Login_API.Controllers
{
    [EnableRateLimiting("IpLimitPolicy")]   // Limit requests from any specific IP.
    [Authorize]             // Denotes that all requests BY DEFAULT require JWT token authentication (passed in the HTTP request).
    [Route("launcher")]     // Makes all endpoints begin with "[URL]/launcher/"; endpoint methods below define suffixes.
    [ApiController]
    public class LauncherController : Controller
    {
        private readonly ILauncherService _launcherService;
        private readonly ILogger _logger;

        public LauncherController(ILauncherService launcherService, ILogger<LauncherController> logger)
        {
            // Adding the services as constructor parameters utilizes ASP.NET's built-in dependency injection
            //  system. The controller is effectively requesting the Service from the services container
            //  configured in Program.cs.
            _launcherService = launcherService;

            _logger = logger;
        }

        

        #region Play Game Operations

        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only fully-logged-in can play the game.
        [Route("play-game")]
        [HttpPost]
        public async Task<ActionResult> UserPlayGame()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("play game from launcher failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _launcherService.PlayGameFromLauncherAsync(username);
            return StatusCode(code, response);
        }

        #endregion



        #region Launcher State Tracking

        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only considered in launcher if logged in with full access.
        [Route("ping-in-launcher")]
        [HttpPost]
        public async Task<ActionResult> UserPingInLauncher()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("ping in launcher failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _launcherService.PingInLauncherAsync(username);
            return (code == 204) ? NoContent() : StatusCode(code, response);
        }

        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only process exit for fully-logged-in users.
        [Route("notify-launcher-exit")]
        [HttpPost]
        public async Task<ActionResult> UserNotifyLauncherExit()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("notify launcher exit failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _launcherService.NotifyLauncherExitAsync(username);
            return (code == 204) ? NoContent() : StatusCode(code, response);
        }

        #endregion

    }
}
