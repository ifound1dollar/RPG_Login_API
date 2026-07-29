using RPG_Login_API.Data;

namespace RPG_Login_API.Services.Interfaces
{
    public interface IEmailService
    {
        /// <summary>
        /// Asynchronously tries to send a randomly-generated confirmation code to the provided email
        ///  using Gmail SMTP. Handles logging and errors internally within this method.
        /// </summary>
        /// <param name="email"> The email to try to send the confirmation code to. </param>
        /// <param name="context"> The context which the code is for, used to ensure codes are not cross-used. </param>
        public Task<(int, string)> SendCodeToEmailAsync(string email, ConfirmationCodeData.CodeContext context);

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

        /// <summary>
        /// Asynchronously tries to send a randomly-genrated confirmation code to the provided email using
        ///  Gmail SMTP. This is specifically for when a user requests to hard reset their MFA configuration, and
        ///  includes different information for security reasons. Handles logging and errors within this method.
        /// </summary>
        /// <param name="email"> The email to try to send the confirmation code to. </param>
        /// <param name="isPrimaryEmail"> Whether the target email is primary or secondary, which determines the locked until time. </param>
        /// <param name="context"> The context which the code is for, used to ensure codes are not cross-used. </param>
        public Task<(int, string)> SendMfaHardResetRequestToEmailAsync(string email, bool isPrimaryEmail, ConfirmationCodeData.CodeContext context);

        /// <summary>
        /// Asynchronously tries to send a notification email to the provided email, warning the user that an MFA
        ///  hard reset operation was initiated for their account. A randomly-generated cancel code must be passed to
        ///  the method, which must match the cancel code written to the database (allows the user to cancel this
        ///  operation for security reasons). The time which the account is locked until must also be passed in for
        ///  informational reasons.
        /// </summary>
        /// <param name="email"> The email to try to send the notification to. </param>
        /// <param name="username"> The username of the account the MFA hard reset is for, which is used in the cancellation link. </param>
        /// <param name="cancelCode"> The cancel code that will be appended to a user-specific cancel link in the email. </param>
        /// <param name="lockedUntilTime"> The time which the user's account is locked until, used for informational purposes. </param>
        public Task<(int, string)> SendMfaHardResetInitiatedToEmailAsync(string email, string username, string cancelCode, DateTime lockedUntilTime);

        /// <summary>
        /// Asynchronously tries to send a notification to the provided email, letting the user know that the pending
        ///  MFA hard reset for their account was successfully cancelled.
        /// </summary>
        /// <param name="email"> The email to try to send the notification to. </param>
        public Task<(int, string)> SendMfaHardResetCancelledNotifToEmailAsync(string email);

        /// <summary>
        /// Asynchronously tries to send a notification to the provided email, letting the user know that their MFA
        ///  setup was successfully hard reset and the account is now accessible again.
        /// </summary>
        /// <param name="email"> The email to try to send the notification to. </param>
        public Task<(int, string)> SendMfaHardResetCompletedNotifToEmailAsync(string email);
    }
}
