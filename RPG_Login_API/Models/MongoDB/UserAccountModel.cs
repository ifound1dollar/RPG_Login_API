
namespace RPG_Login_API.Models.MongoDB
{
    /// <summary>
    /// Represents a user account document model, containing necessary data like ObjectId and any
    ///  additional user-defined elements. Model instances created without setting every
    ///  field will use default values. Likewise, documents retrieved from the database without
    ///  values set will be automatically set to default values (ex. int to 0). This class must
    ///  exactly match the model class in the database API.
    /// </summary>
    public class UserAccountModel
    {
        public string Id { get; init; } = string.Empty;

        public string Username { get; set; } = string.Empty;

        public string PrimaryEmail { get; set; } = string.Empty;

        public string SecondaryEmail { get; set; } = string.Empty;

        public string PasswordHash { get; set; } = string.Empty;



        public bool IsEmailVerified { get; set; } = false;

        public bool DoesPasswordNeedReset { get; set; } = false;



        public string PendingNewPrimaryEmail { get; set; } = string.Empty;

        public string PendingNewSecondaryEmail { get; set; } = string.Empty;



        public string ActiveMfaKey { get; set; } = string.Empty;

        public string PendingMfaKey { get; set; } = string.Empty;

        public string MfaRecoveryCodeHash { get; set; } = string.Empty;

        public DateTime MfaHardResetInitiatedTime { get; set; } = DateTime.MinValue;

        public DateTime MfaHardResetLockedUntilTime { get; set; } = DateTime.MinValue;

        public string MfaHardResetCancelCode { get; set; } = string.Empty;



        public string RefreshTokenHash { get; set; } = string.Empty;



        // NOTE: BELOW OBJECTS ARE INIT-ONLY, PREVENTING REPLACEMENT BUT ALLOWING INTERNAL PROPERTIES TO BE SET.
        public ActiveStatusesModel ActiveStatuses { get; init; } = new();

        public TimeTrackersModel TimeTrackers { get; init; } = new();

        public GameDataModel GameData { get; init; } = new();



        public class ActiveStatusesModel
        {
            public bool InLauncherStatus { get; set; } = false;

            public DateTime LastInLauncherTime { get; set; } = DateTime.MinValue;

            public bool OnlineStatus { get; set; } = false;

            public DateTime LastOnlineTime { get; set; } = DateTime.MinValue;

            public string ConnectToken { get; set; } = string.Empty;
        }

        public class TimeTrackersModel
        {
            public DateTime AccountCreatedTime { get; set; } = DateTime.MinValue;

            public DateTime AccountLockedUntil { get; set; } = DateTime.MinValue;

            public DateTime LastUsernameChangedTime { get; set; } = DateTime.MinValue;

            public DateTime LastPasswordChangedTime { get; set; } = DateTime.MinValue;

            public DateTime LastEmailChangedTime { get; set; } = DateTime.MinValue;
        }

        public class GameDataModel
        {
            public List<string> CharacterIds { get; set; } = [];

            public string LastPlayedCharacterName { get; set; } = string.Empty;
        }
    }
}
