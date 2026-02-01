namespace RPG_Login_API.Models.UserRequests
{
    /// <summary>
    /// A data model containing simple login request data. Stores elements as raw strings that are pulled
    ///  directly from the request body.
    /// </summary>
    public class LoginRequestModel
    {
        // CONSIDER IMPLEMENTING THE IDisposable INTERFACE TO DESTROY AND CLEAR MEMORY IMMEDIATELY

        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
