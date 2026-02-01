namespace RPG_Login_API.Configuration
{
    /// <summary>
    /// Represents database configuration data like connection string and database name in object form.
    ///  Should be populated from JSON configuration data, accessed within Program.cs.
    /// </summary>
    public class DatabaseSettings
    {
        public string ConnectionString { get; set; } = null!;
        public string DatabaseName { get; set; } = null!;
        public string UserAccountsCollectionName { get; set; } = null!;
    }
}
