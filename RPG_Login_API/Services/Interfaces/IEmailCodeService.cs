using RPG_Login_API.Data;

namespace RPG_Login_API.Services.Interfaces
{
    public interface IEmailCodeService
    {
        /// <summary>
        /// Asynchronously tries to send a randomly-generated confirmation code to the provided email
        ///  using Gmail SMTP. Handles logging and errors internally within this method.
        /// </summary>
        /// <param name="email"> The email to try to send the confirmation code to. </param>
        /// <param name="context"> The context which the code is for, used to ensure codes are not cross-used. </param>
        public Task SendCodeToEmailAsync(string email, ConfirmationCodeData.CodeContext context);

        /// <summary>
        /// Validates a user-submitted email confirmation code, checking its expiration and whether it
        ///  matches the stored code (if a stored code exists). Handles all confirmation code storage and
        ///  removal, and logs on success or failure.
        /// </summary>
        /// <param name="email"> The email associated with the account which submitted the code. </param>
        /// <param name="code"> The submitted confirmation code. </param>
        /// <param name="context"> The context which the user request is for, which must match the server-side code. </param>
        /// <returns> True if the code is non-expired and matches stored code, false otherwise. </returns>
        public bool ValidateSubmittedCode(string email, string code, ConfirmationCodeData.CodeContext context);
    }
}
