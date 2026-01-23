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
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? Id { get; set; }

        [BsonElement("username")]
        public string Username { get; set; } = string.Empty;

        [BsonElement("password_hash")]
        public string PasswordHash { get; set; } = string.Empty;

        [BsonElement("character_ids")]
        public List<string> CharacterIds { get; set; } = [];
    }
}
