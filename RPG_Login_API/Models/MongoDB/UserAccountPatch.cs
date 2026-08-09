namespace RPG_Login_API.Models.MongoDB
{
    public class UserAccountPatch
    {
        public string? Username { get; init; }

        public string? PrimaryEmail { get; init; }

        public string? SecondaryEmail { get; init; }

        public string? PasswordHash { get; init; }



        public bool? IsEmailVerified { get; init; }

        public bool? DoesPasswordNeedReset { get; init; }



        public string? PendingNewPrimaryEmail { get; init; }

        public string? PendingNewSecondaryEmail { get; init; }



        public string? ActiveMfaKey { get; init; }

        public string? PendingMfaKey { get; init; }

        public string? MfaRecoveryCodeHash { get; init; }

        public DateTime? MfaHardResetInitiatedTime { get; init; }

        public DateTime? MfaHardResetLockedUntilTime { get; init; }

        public string? MfaHardResetCancelCode { get; init; }



        public string? RefreshTokenHash { get; init; }



        // NOTE: BELOW OBJECTS ARE INIT-ONLY, PREVENTING REPLACEMENT BUT ALLOWING INTERNAL PROPERTIES TO BE SET.
        public ActiveStatusesModel? ActiveStatuses { get; init; }

        public TimeTrackersModel? TimeTrackers { get; init; }

        public GameDataModel? GameData { get; init; }



        public class ActiveStatusesModel
        {
            public bool? InLauncherStatus { get; init; }

            public DateTime? LastInLauncherTime { get; init; }

            public bool? OnlineStatus { get; init; }

            public DateTime? LastOnlineTime { get; init; }
        }

        public class TimeTrackersModel
        {
            public DateTime? AccountCreatedTime { get; init; }

            public DateTime? AccountLockedUntil { get; init; }

            public DateTime? LastUsernameChangedTime { get; init; }

            public DateTime? LastPasswordChangedTime { get; init; }

            public DateTime? LastEmailChangedTime { get; init; }
        }

        public class GameDataModel
        {
            public List<string>? CharacterIds { get; init; }

            public string? LastPlayedCharacterId { get; init; }
        }
    }
}
