using RPG_Login_API.Data;
using RPG_Login_API.Services.Interfaces;
using System.Collections.Concurrent;
using MailKit.Net.Smtp;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using RPG_Login_API.Configuration;
using MimeKit;

namespace RPG_Login_API.Services
{
    public class EmailCodeService : IEmailCodeService
    {
        // Stores temporary confirmation codes with expiration, use a concurrent dictionary for async safety.
        private readonly ConcurrentDictionary<string, ConfirmationCodeData> _confirmationCodes = [];

        private readonly IOptions<EmailServiceSettings> _settings;
        private readonly ILogger _logger;

        public EmailCodeService(IOptions<EmailServiceSettings> settings, ILogger<EmailCodeService> logger)
        {
            _settings = settings;
            _logger = logger;
        }



        public bool ValidateSubmittedCode(string email, string code, ConfirmationCodeData.CodeContext context)
        {
            // First, convert code to all uppercase (non-case-sensitive code and we use uppercase in generation).
            code = code.ToUpperInvariant();

            // Try to find stored code in dictionary, then if exists, check for expiration.
            if (!_confirmationCodes.TryGetValue(email, out var codeData))
            {
                _logger.LogInformation($"Confirmation code validation failed: no local confirmation code found for this email (email: {email}, context: {context.ToString()})");
                return false;
            }
            if (codeData.Expiration < DateTime.UtcNow)
            {
                // Remove expired code data, discarding out variable because it is not needed.
                _confirmationCodes.Remove(email, out _);

                _logger.LogInformation($"Confirmation code validation failed: expired user-provided confirmation code (email: {email}, context: {context.ToString()})");
                return false;
            }

            // Verify submitted code context (from endpoint) matches stored code (prevents unintended cross-usage).
            if (codeData.Context != context)
            {
                // Simply reject request, interpreting it as an invalid request entirely. Do not increment failed attempt counter.
                _logger.LogInformation($"Confirmation code validation failed: confirmation code context in request does not match context of" +
                    $" stored code (email: {email}, submitted context: {context.ToString()}, stored context: {codeData.Context.ToString()})");
                return false;
            }

            // Compare user-provided code with stored code, returning false if mismatch. Also check counter.
            if (codeData.Code != code)
            {
                // Increment code counter, which is used to invalidate the code after 3 failed code submit attempts.
                codeData.AttemptCounter++;
                if (codeData.AttemptCounter >= 3)
                {
                    // If counter now >= 3, invalidate code by removing from local container.
                    _confirmationCodes.Remove(email, out _);
                }

                _logger.LogInformation($"Email verification failed: incorrect confirmation code submitted by user (email: {email}, context: {context.ToString()})");
                return false;
            }

            // If we reach here, then there is a stored non-expired code for this user AND the submitted code matches.
            _confirmationCodes.Remove(email, out _);
            return true;
        }

        public async Task<(int, string)> SendCodeToEmailAsync(string email, ConfirmationCodeData.CodeContext context)
        {
            // PREVENT NEW CODE SPAM | Ensure there is not an existing confirmation code for this account created less than 60 seconds ago.
            if (_confirmationCodes.TryGetValue(email, out var codeData))
            {
                // If existing code was created less than 60 seconds ago, log error and return.
                if ((DateTime.UtcNow - codeData.Created) < TimeSpan.FromMinutes(1))
                {
                    _logger.LogInformation($"Failed to send code to email: cannot generate new code within 60 seconds of previous (email: {email}, context: {context.ToString()})");
                    return (403, "Cannot request a new confirmation code within 60 seconds of previous request.");
                }
            }

            // Generate code and add to in-memory Dictionary, replacing if an entry already exists.
            string code = Helper.GenerateRandomAlphanumericCode();
            _confirmationCodes[email] = new ConfirmationCodeData(code, context, durationMinutes: 5);

            // If in development mode, print to console so developer can test fake emails, then return.
            if (Program.IsDevelopment)
            {
                _logger.LogInformation($"CONFIRMATION CODE FOR USER (email: {email}, context: {context.ToString()}): {code}");
                return (200, "Email confirmation code sent successfully.");
            }

            // If not in development mode, use Gmail SMTP to send a code to the user.
            try
            {
                var bodyBuilder = new BodyBuilder
                {
                    HtmlBody = Helper.GenerateEmailHtml(code)
                };
                MimeMessage message = new();
                message.From.Add(new MailboxAddress("RPG Login API noreply", "rpg.login.api.noreply@gmail.com"));
                message.To.Add(new MailboxAddress(email, email));
                message.Subject = "One-time confirmation code";
                message.Body = bodyBuilder.ToMessageBody();

                using (var smtp = new SmtpClient())
                {
                    // Connect to provider, then sign into SMTP server using secure credentials.
                    await smtp.ConnectAsync("smtp.gmail.com", 587, MailKit.Security.SecureSocketOptions.StartTls);
                    await smtp.AuthenticateAsync(_settings.Value.EmailAddress, _settings.Value.AppPassword);

                    // Actually send the message, then disconnect gracefully.
                    await smtp.SendAsync(message);
                    await smtp.DisconnectAsync(true);
                }

                _logger.LogInformation($"Email confirmation code successfully sent (email: {email}, context: {context.ToString()})");
                return (200, "Email confirmation code sent successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return (500, "An unexpected error occurred during the request, please try again.");
            }
        }



        private static class Helper
        {
            // Valid characters do NOT include I, L, O, 0 (zero), or 1. 
            private const string alphanumericChars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

            public static string GenerateRandomAlphanumericCode(int length = 8)
            {
                if (length < 0) throw new ArgumentException("Length must be greater than or equal to 0");

                char[] result = new char[length];
                for (int i = 0; i < length; i++)
                {
                    int index = RandomNumberGenerator.GetInt32(alphanumericChars.Length);
                    result[i] = alphanumericChars[index];
                }

                return new string(result);
            }

            public static string GenerateEmailHtml(string code)
            {
                return $"<table align=\"center\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px; background-color: #ffffff; margin: 40px auto; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);\">\r\n    " +
                    $"<tr>\r\n      " +
                    $"<td align=\"center\" style=\"padding-bottom: 20px;\">\r\n        " +
                    $"<!-- Replace with your company's logo -->\r\n        " +
                    $"<h2 style=\"color: #333333; margin: 0;\">RPG Login API</h2>\r\n      " +
                    $"</td>\r\n    " +
                    $"</tr>\r\n    " +
                    $"<tr>\r\n      " +
                    $"<td align=\"center\" style=\"padding-bottom: 30px;\">\r\n        " +
                    $"<h1 style=\"color: #333333; margin: 0;\">Confirmation Code</h1>\r\n      " +
                    $"</td>\r\n    " +
                    $"</tr>\r\n    " +
                    $"<tr>\r\n      " +
                    $"<td align=\"center\" style=\"padding-bottom: 30px;\">\r\n        " +
                    $"<p style=\"color: #666666; font-size: 16px; line-height: 24px; margin: 0;\">\r\n          " +
                    $"Please use the following one-time code to complete your login or verification process. This code will expire in 5 minutes.\r\n        " +
                    $"</p>\r\n      </td>\r\n    </tr>\r\n    <tr>\r\n      <td align=\"center\" style=\"padding-bottom: 40px;\">\r\n        " +
                    $"<!-- Code Display Box -->\r\n        " +
                    $"<div style=\"background-color: #f0f4f8; color: #1a365d; font-size: 32px; font-weight: bold; letter-spacing: 8px; padding: 20px 30px; border-radius: 6px; display: inline-block;\">\r\n          " +
                    $"{code}\r\n        " +
                    $"</div>\r\n      " +
                    $"</td>\r\n    " +
                    $"</tr>\r\n    " +
                    $"<tr>\r\n      " +
                    $"<td align=\"center\" style=\"border-top: 1px solid #eeeeee; padding-top: 20px;\">\r\n        " +
                    $"<p style=\"color: #999999; font-size: 14px; margin: 0;\">\r\n          " +
                    $"If you did not request this code, you can safely ignore this email. No changes were made to your account.\r\n        " +
                    $"</p>\r\n      " +
                    $"</td>\r\n    " +
                    $"</tr>\r\n  " +
                    $"</table>";
            }
        }
    }
}
