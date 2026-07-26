namespace RPG_Login_API.Services.Interfaces
{
    public interface ILauncherService
    {
        public Task<(int, object?)> PlayGameFromLauncherAsync(string username);

        public Task<(int, object?)> PingInLauncherAsync(string username);
        public Task<(int, object?)> NotifyLauncherExitAsync(string username);
    }
}
