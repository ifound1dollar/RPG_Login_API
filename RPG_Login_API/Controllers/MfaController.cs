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
    [Route("mfa")]          // Makes all endpoints begin with "[URL]/mfa/"; endpoint methods below define suffixes.
    [ApiController]
    public class MfaController : Controller
    {
        private readonly IMfaService _mfaService;
        private readonly ILogger _logger;

        public MfaController(IMfaService mfaSetupService, ILogger<MfaController> logger)
        {
            _mfaService = mfaSetupService;
            _logger = logger;
        }



        #region MFA Setup and Recovery

        [Authorize(Roles = TokenUtility.Roles.MfaNotEnabled + "," + TokenUtility.Roles.FullAccess)]
        [Route("begin-mfa-setup")]
        [HttpPost]
        public async Task<ActionResult> UserBeginMfaSetup()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("begin MFA setup failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaService.BeginMfaSetup(username);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.MfaNotEnabled + "," + TokenUtility.Roles.AwaitingMfa + "," + TokenUtility.Roles.FullAccess)]
        [Route("verify-mfa-setup")]     // ^ MFA not enabled for initial setup, awaiting MFA for recover, full access for manual change
        [HttpPost]
        public async Task<ActionResult> UserVerifyMfaSetup(VerifyMfaSetupRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("verify MFA setup failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaService.VerifyMfaSetupAsync(username, request.MfaCode);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.AwaitingMfa)]
        [Route("recover-mfa")]
        [HttpPost]
        public async Task<ActionResult> UserRecoverMfa(RecoverMfaRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("recover MFA configuration failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaService.RecoverMfaAsync(username, request.RecoveryCode);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.FullAccess)]      // Only fully-logged-in users can regenerate recovery code.
        [Route("regenerate-mfa-recovery-code")]
        [HttpPost]
        public async Task<ActionResult> UserRegenerateMfaRecoveryCode()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("regenerate MFA recovery code failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaService.RegenerateMfaRecoveryCodeAsync(username);
            return StatusCode(code, response);
        }

        #endregion



        #region MFA Hard Reset

        [Authorize(Roles = TokenUtility.Roles.AwaitingMfa)]     // Reset can only be done by partial-login (awaiting MFA)
        [Route("request-mfa-hard-reset")]
        [HttpPost]
        public async Task<ActionResult> UserRequestMfaHardResetAsync()
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("request MFA hard reset failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaService.RequestMfaHardResetAsync(username);
            return StatusCode(code, response);
        }



        [Authorize(Roles = TokenUtility.Roles.AwaitingMfa)]     // Reset can only be done by partial-login (awaiting MFA)
        [Route("initiate-mfa-hard-reset")]
        [HttpPost]
        public async Task<ActionResult> UserInitiateMfaHardResetAsync(InitiateMfaHardResetRequestModel request)
        {
            // Retrieve account data (username, role, guid) from access token in request header.
            if (!ControllerUtility.TryReadAccessTokenData(User, out var username, out var role, out var guid))
            {
                _logger.LogInformation("initiate MFA hard reset failed, incorrectly formatted access token in request header");
                return BadRequest("Malformed access token in API request.");
            }

            (int code, object? response) = await _mfaService.InitiateMfaHardResetAsync(username, request.Code);
            return StatusCode(code, response);
        }



        [AllowAnonymous]
        [Route("cancel-mfa-hard-reset")]
        [HttpGet]
        public async Task<ActionResult> UserCancelMfaHardResetAsync([FromQuery] CancelMfaHardResetRequestModel request)
        {
            // This endpoint must allow anonymous use from email. There is no token to read, so simply try to cancel.
            // Note that this will return an error message, but that error message will be generic (unless successful).

            (int code, object? response) = await _mfaService.CancelMfaHardResetAsync(request.Username, request.CancelCode);
            return StatusCode(code, response);
        }

        #endregion
    }
}
