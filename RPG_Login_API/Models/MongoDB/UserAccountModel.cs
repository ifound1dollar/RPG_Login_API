using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace RPG_Login_API.Models.MongoDB
{
    /// <summary>
    /// Represents a MongoDB document model, containing necessary data like ObjectId and any
    ///  additional user-defined elements. Model instances created without setting every
    ///  field will use default values. Likewise, documents retrieved from the database without
    ///  values set will be automatically set to default values (ex. int to 0).
    /// </summary>
    [BsonIgnoreExtraElements]   // THIS PREVENTS THROWING EXCEPTIONS IF EXTRA FIELDS ARE FOUND
    public class UserAccountModel
    {
        public enum AccountOnlineStatus { Offline, InLauncher, Online, InGame }



        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? Id { get; set; }

        [BsonElement("username")]
        public string Username { get; set; } = string.Empty;

        [BsonElement("email")]
        public string Email { get; set; } = string.Empty;

        [BsonElement("password_hash")]
        public string PasswordHash { get; set; } = string.Empty;

        [BsonElement("is_email_verified")]
        public bool IsEmailVerified { get; set; } = false;

        [BsonElement("does_password_need_reset")]
        public bool DoesPasswordNeedReset { get; set; } = false;

        [BsonElement("refresh_token")]
        public string RefreshTokenHash { get; set; } = string.Empty;

        [BsonElement("online_status")]
        public AccountOnlineStatus OnlineStatus { get; set; }



        [BsonElement("account_created_time")]
        public DateTime AccountCreatedTime { get; set; } = DateTime.MinValue;

        [BsonElement("last_online_time")]
        public DateTime LastOnlineTime { get; set; } = DateTime.MinValue;

        [BsonElement("last_password_changed_time")]
        public DateTime LastPasswordChangedTime { get; set; } = DateTime.MinValue;

        [BsonElement("last_username_changed_time")]
        public DateTime LastUsernameChangedTime { get; set; } = DateTime.MinValue;



        [BsonElement("character_ids")]
        public List<string> CharacterIds { get; set; } = [];
    }
}
