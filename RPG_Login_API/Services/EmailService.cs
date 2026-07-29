using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using RPG_Login_API.Configuration;
using RPG_Login_API.Data;
using RPG_Login_API.Services.Interfaces;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using static Org.BouncyCastle.Crypto.Engines.SM2Engine;
using static QRCoder.PayloadGenerator.SwissQrCode;

namespace RPG_Login_API.Services
{
    public class EmailService : IEmailService
    {
        // Stores temporary confirmation codes with expiration, use a concurrent dictionary for async safety.
        private readonly ConcurrentDictionary<string, ConfirmationCodeData> _confirmationCodes = [];

        private readonly IOptions<EmailServiceSettings> _settings;
        private readonly ILogger _logger;

        public EmailService(IOptions<EmailServiceSettings> settings, ILogger<EmailService> logger)
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
            // ENSURE EMAIL IS NOT EMPTY
            if (string.IsNullOrEmpty(email))
            {
                _logger.LogInformation($"Failed to send code to email: provided email was empty string (email: {email}, context: {context.ToString()})");
                return (400, "Cannot send code to empty email.");
            }

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
                    HtmlBody = Helper.GenerateConfirmationCodeHtml(code)
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

        public async Task<(int, string)> SendMfaHardResetRequestToEmailAsync(string email, bool isPrimaryEmail, ConfirmationCodeData.CodeContext context)
        {
            // ENSURE EMAIL IS NOT EMPTY
            if (string.IsNullOrEmpty(email))
            {
                _logger.LogInformation($"Failed to send code to email: provided email was empty string (email: {email}, context: {context.ToString()})");
                return (400, "Cannot send code to empty email.");
            }

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
                string lockedUntilTime = (isPrimaryEmail) ? "7 days" : "24 hours";
                var bodyBuilder = new BodyBuilder
                {
                    HtmlBody = Helper.GenerateRequestMfaHardResetHtml(code, lockedUntilTime)
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

        public async Task<(int, string)> SendMfaHardResetInitiatedToEmailAsync(string email, string username, string cancelCode, DateTime lockedUntilTime)
        {
            // ENSURE EMAIL IS NOT EMPTY
            if (string.IsNullOrEmpty(email))
            {
                _logger.LogInformation($"Failed to send initiated MFA hard reset notification to email: provided email was empty string (email: {email})");
                return (400, "Cannot send notification to empty email.");
            }

            // If in development mode, print cancel code to console so developer can test fake emails, then return.
            if (Program.IsDevelopment)
            {
                _logger.LogInformation($"MFA HARD RESET CANCEL CODE FOR USER (email: {email}): {cancelCode}");
                return (200, "MFA hard reset initiated notification sent successfully.");
            }

            // If not in development mode, use Gmail SMTP to send an email to the user.
            try
            {
                string cancelUrl = $"login.edranagame.com/users/cancel-mfa-hard-reset?username={username}&cancelcode={cancelCode}";
                var bodyBuilder = new BodyBuilder
                {
                    HtmlBody = Helper.GenerateMfaHardResetInitiatedHtml(cancelUrl, lockedUntilTime.ToString())
                };
                MimeMessage message = new();
                message.From.Add(new MailboxAddress("RPG Login API noreply", "rpg.login.api.noreply@gmail.com"));
                message.To.Add(new MailboxAddress(email, email));
                message.Subject = "MFA hard reset initiated";
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

                _logger.LogInformation($"initiated MFA hard reset notification successfully sent (email: {email})");
                return (200, "MFA hard reset initiated notification sent successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return (500, "An unexpected error occurred during the request, please try again.");
            }
        }

        public async Task<(int, string)> SendMfaHardResetCancelledNotifToEmailAsync(string email)
        {
            // ENSURE EMAIL IS NOT EMPTY
            if (string.IsNullOrEmpty(email))
            {
                _logger.LogInformation($"Failed to send MFA hard reset cancelled notification to email: provided email was empty string (email: {email})");
                return (400, "Cannot send notification to empty email.");
            }

            // If not in development mode, use Gmail SMTP to send an email to the user.
            try
            {
                var bodyBuilder = new BodyBuilder
                {
                    HtmlBody = Helper.GenerateMfaHardResetCancelledHtml()
                };
                MimeMessage message = new();
                message.From.Add(new MailboxAddress("RPG Login API noreply", "rpg.login.api.noreply@gmail.com"));
                message.To.Add(new MailboxAddress(email, email));
                message.Subject = "MFA hard reset cancelled";
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

                _logger.LogInformation($"MFA hard reset cancelled notification successfully sent (email: {email})");
                return (200, "MFA hard reset cancelled notification sent successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return (500, "An unexpected error occurred during the request, please try again.");
            }
        }

        public async Task<(int, string)> SendMfaHardResetCompletedNotifToEmailAsync(string email)
        {
            // ENSURE EMAIL IS NOT EMPTY
            if (string.IsNullOrEmpty(email))
            {
                _logger.LogInformation($"Failed to send MFA hard reset completed notification to email: provided email was empty string (email: {email})");
                return (400, "Cannot send notification to empty email.");
            }

            // If not in development mode, use Gmail SMTP to send an email to the user.
            try
            {
                var bodyBuilder = new BodyBuilder
                {
                    HtmlBody = Helper.GenerateMfaHardResetCompletedHtml()
                };
                MimeMessage message = new();
                message.From.Add(new MailboxAddress("RPG Login API noreply", "rpg.login.api.noreply@gmail.com"));
                message.To.Add(new MailboxAddress(email, email));
                message.Subject = "MFA hard reset completed";
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

                _logger.LogInformation($"MFA hard reset completed notification successfully sent (email: {email})");
                return (200, "MFA hard reset completed notification sent successfully.");
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

            public static string GenerateConfirmationCodeHtml(string code)
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

            public static string GenerateRequestMfaHardResetHtml(string code, string lockedTimeString)
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
                    $"A request to reset your account's multi-factor authentication setup was made. Please enter the confirmation code below to confirm the reset request; the code will expire in 5 minutes. Note that no changes will be made to your account until the code below is submitted. After submitting this code to initiate the reset process, your account will be locked for {lockedTimeString} for security reasons.\r\n        " +
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
                    $"If you did not make this request, please immedately log into your account using your current multi-factor authentication setup and change your password.\r\n        " +
                    $"</p>\r\n      " +
                    $"</td>\r\n    " +
                    $"</tr>\r\n  " +
                    $"</table>";
            }

            public static string GenerateMfaHardResetInitiatedHtml(string cancelUrl, string lockedUntilDateTime)
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
                    $"A multi-factor authentication reset was initiated for your account. For security reasons, your account is locked until {lockedUntilDateTime} to ensure account security. After this time, your account will be un-locked and the multi-factor authentication setup will need to be re-configured. If you did not initiate this reset or want to cancel the reset, please click the link below before {lockedUntilDateTime}.\r\n        " +
                    $"</p>\r\n      </td>\r\n    </tr>\r\n    <tr>\r\n      <td align=\"center\" style=\"padding-bottom: 40px;\">\r\n        " +
                    $"<!-- Code Display Box -->\r\n        " +
                    $"<div style=\"background-color: #f0f4f8; color: #1a365d; font-size: 24px; font-weight: bold; letter-spacing: 2px; padding: 20px 30px; border-radius: 6px; display: inline-block;\">\r\n          " +
                    $"<a href=\"{cancelUrl}\">Cancel Reset</a>\r\n        " +
                    $"</div>\r\n      " +
                    $"</td>\r\n    " +
                    $"</tr>\r\n    " +
                    $"<tr>\r\n      " +
                    $"<td align=\"center\" style=\"border-top: 1px solid #eeeeee; padding-top: 20px;\">\r\n        " +
                    $"<p style=\"color: #999999; font-size: 14px; margin: 0;\">\r\n          " +
                    $"Clicking the link above will return your account to its original state before the reset was initiated, restoring the existing multi-factor authentication configuration. For security reasons, canceling the reset will require you to change your password on the next successful login.\r\n        " +
                    $"</p>\r\n      " +
                    $"</td>\r\n    " +
                    $"</tr>\r\n  " +
                    $"</table>";
            }

            public static string GenerateMfaHardResetCancelledHtml()
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
                    $"The pending multi-factor authentication hard reset for your account was successfully cancelled. Your existing MFA configuration has been fully restored. For security reasons, please immediately log into your account using your current multi-factor authentication setup and reset your password.\r\n        " +
                    $"</p>\r\n      </td>\r\n    </tr>\r\n        " +
                    $"</table>";
            }

            public static string GenerateMfaHardResetCompletedHtml()
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
                    $"Your account's multi-factor authentication setup was just hard reset. Any cancellation link sent to your email is now invalid. If you did not initiate this reset, please contact customer support.\r\n        " +
                    $"</p>\r\n      </td>\r\n    </tr>\r\n        " +
                    $"</table>";
            }
        }
    }
}
