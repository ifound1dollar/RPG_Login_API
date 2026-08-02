namespace RPG_Login_API.Utility
{
    public class TokenUtility
    {
        public static class Roles
        {
            public const string EmailNotVerified = "email_not_verified";
            public const string MfaNotEnabled = "mfa_not_enabled";
            public const string AwaitingMfa = "awaiting_mfa";
            public const string FullAccess = "full_access";
            public const string ResetPassword = "reset_password";   // UNIQUE ROLE

            public const string Any = EmailNotVerified + "," + MfaNotEnabled + "," + AwaitingMfa + "," + FullAccess + "," + ResetPassword;
        }
    }
}
