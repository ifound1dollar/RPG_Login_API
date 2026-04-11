namespace RPG_Login_API.Data
{
    public class ConfirmationCodeData
    {
        public string Code { get; private set; }
        public DateTime Created { get; private set; }
        public DateTime Expiration { get; private set; }
        public int AttemptCounter { get; set; }

        public ConfirmationCodeData(string code, double durationMinutes = 5)
        {
            Code = code;
            Created = DateTime.UtcNow;
            Expiration = DateTime.UtcNow.AddMinutes(durationMinutes);
            AttemptCounter = 0;
        }
    }
}
