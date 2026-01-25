namespace RPG_Login_API.Data
{
    public class AccessTokenData
    {
        public string Username { get; private set; }
        public string Token { get; private set; }
        public DateTime Expiration { get; private set; }

        public AccessTokenData(string username, string token, double durationMinutes)
        {
            Username = username;
            Token = token;
            Expiration = DateTime.UtcNow.AddMinutes(durationMinutes);
        }
    }
}
