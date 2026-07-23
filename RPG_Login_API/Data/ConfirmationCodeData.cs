namespace RPG_Login_API.Data
{
    public class ConfirmationCodeData
    {
        public enum CodeContext { None, PrimaryEmailVerification, PasswordReset, ChangePrimaryEmail, SecondaryEmailVerification }

        public string Code { get; private set; }
        public CodeContext Context { get; private set; }
        public DateTime Created { get; private set; }
        public DateTime Expiration { get; private set; }
        public int AttemptCounter { get; set; }

        public ConfirmationCodeData(string code, CodeContext context, double durationMinutes = 5)
        {
            Code = code;
            Context = context;
            Created = DateTime.UtcNow;
            Expiration = DateTime.UtcNow.AddMinutes(durationMinutes);
            AttemptCounter = 0;
        }
    }
}
