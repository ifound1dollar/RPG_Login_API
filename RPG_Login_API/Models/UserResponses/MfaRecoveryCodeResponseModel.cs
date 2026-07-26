namespace RPG_Login_API.Models.UserResponses
{
    public class MfaRecoveryCodeResponseModel
    {
        public MfaRecoveryCodeResponseModel(AccessResponseModel accessResponseModel)
        {
            Username = accessResponseModel.Username;
            PrimaryEmail = accessResponseModel.PrimaryEmail;
            SecondaryEmail = accessResponseModel.SecondaryEmail;
            LoginStatusCode = accessResponseModel.LoginStatusCode;
            RefreshToken = accessResponseModel.RefreshToken;
            AccessToken = accessResponseModel.AccessToken;
            AccessTokenExpiration = accessResponseModel.AccessTokenExpiration;
        }

        public string RecoveryCode { get; init; } = string.Empty;

        public string Username { get; } = string.Empty;
        public string PrimaryEmail { get; } = string.Empty;
        public string SecondaryEmail { get; } = string.Empty;
        public int LoginStatusCode { get; } = -1;
        public string RefreshToken { get; } = string.Empty;
        public string AccessToken { get; } = string.Empty;
        public DateTime AccessTokenExpiration { get; }
    }
}
