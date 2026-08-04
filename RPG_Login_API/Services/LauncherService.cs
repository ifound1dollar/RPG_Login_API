using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Services.Interfaces;

namespace RPG_Login_API.Services
{
    public class LauncherService : ILauncherService
    {
        private readonly IDatabaseService _databaseService;
        private readonly ITokenService _tokenService;
        private readonly IUtilityService _utilityService;
        private readonly ILogger _logger;

        public LauncherService(IDatabaseService databaseService, ITokenService tokenService, IUtilityService utilityService,
            ILogger<LauncherService> logger)
        {
            _databaseService = databaseService;
            _tokenService = tokenService;
            _utilityService = utilityService;

            _logger = logger;
        }



        public async Task<(int, object?)> PlayGameFromLauncherAsync(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "play game from launcher");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "play game from launcher")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // ENSURE USER IS NOT ALREADY IN GAME | Check whether the 'online' flag is set, and ensure it is not a zombie.
            if (!EnsureAccountIsNotAlreadyInGame(userAccount))
            {
                return (409, "User account is already logged-in and in game.");
            }

            // VALID TO PLAY: GENERATE CONNECT TOKEN | Generate a 256-bit unique token for this user.
            string connectTokenBase64 = _tokenService.GenerateGameConnectToken(username);

            // SEND CONNECT TOKEN TO ONLINE SERVICE | Send token to the online service so it can accept the new player.
            await Task.Delay(500);  // TEMP DELAY FOR SIMULATION

            _logger.LogInformation($"play game from launcher successful (username: {username})");
            return (200, connectTokenBase64);
        }

        public async Task<(int, object?)> PingInLauncherAsync(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "ping in launcher");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "ping in launcher")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // Update in launcher status and time for this account in the database.
            userAccount.InLauncherStatus = true;
            userAccount.LastInLauncherTime = DateTime.UtcNow;

            // REPLACE IN DATABASE VIA API CALL | Try to replace, returning 500 error if failure.
            if (!await _databaseService.ReplaceOneByIdAsync(userAccount.Id, userAccount))
            {
                return (500, "An unexpected database error occurred during the request.");
            }

            _logger.LogInformation($"ping in launcher successful (username: {username})");
            return (204, string.Empty);
        }

        public async Task<(int, object?)> NotifyLauncherExitAsync(string username)
        {
            // FIND ACCOUNT | Try to retrieve user account from username.
            var userAccount = await _utilityService.TryRetrieveAccountByUsernameAsync(username, "notify launcher exit");
            if (userAccount == null)
            {
                return (404, "Failed to find user account for the provided username.");
            }

            // ENSURE ACCOUNT NOT LOCKED | Logs and clears refresh token in method if locked.
            if (!(await _utilityService.EnsureAccountIsNotLockedAsync(userAccount, "notify launcher exit")))
            {
                return (403, "Account currently locked for security reasons, please check account email.");
            }

            // Update in launcher status and set time of exit to last in launcher time.
            userAccount.InLauncherStatus = false;
            userAccount.LastInLauncherTime = DateTime.UtcNow;

            // REPLACE IN DATABASE VIA API CALL | Try to replace, returning 500 error if failure.
            if (!await _databaseService.ReplaceOneByIdAsync(userAccount.Id, userAccount))
            {
                return (500, "An unexpected database error occurred during the request.");
            }

            _logger.LogInformation($"notify launcher exit successful (username: {username})");
            return (204, "");
        }



        #region Private: Local utility methods

        private bool EnsureAccountIsNotAlreadyInGame(UserAccountModel userAccount)
        {
            // If is flagged online and has an online ping in the last 3 minutes, then the account is definitely online.
            if (userAccount.OnlineStatus && (DateTime.UtcNow - userAccount.LastOnlineTime < TimeSpan.FromMinutes(3)))
            {
                _logger.LogInformation($"play game from launcher failed: account is already online (username: {userAccount.Username}, last online time: {userAccount.LastOnlineTime.ToShortTimeString()})");
                return false;
            }
            return true;
        }

        #endregion
    }
}
