namespace RPG_Login_API.Configuration
{
    /// <summary>
    /// Represents remote database API configuration settings like username and password, which are
    ///  required to access the authenticated database. Any configurable data is included here, like
    ///  base URI for the database.
    /// </summary>
    public class DatabaseApiSettings
    {
        public string RemoteUri { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
