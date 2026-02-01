namespace RPG_Login_API.Configuration
{
    public class DatabaseSettings
    {
        public string ConnectionString { get; set; } = null!;
        public string DatabaseName { get; set; } = null!;
        public string UserAccountsCollectionName { get; set; } = null!;
    }
}
