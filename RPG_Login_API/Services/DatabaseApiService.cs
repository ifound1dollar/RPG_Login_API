using Microsoft.Extensions.Options;
using RPG_Login_API.Configuration;
using RPG_Login_API.Models.MongoDB;
using RPG_Login_API.Models.Responses;
using RPG_Login_API.Services.Interfaces;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using static Org.BouncyCastle.Crypto.Engines.SM2Engine;
using static QRCoder.PayloadGenerator;

namespace RPG_Login_API.Services
{
    public class DatabaseApiService : IDatabaseService
    {
        private readonly ILogger _logger;
        private readonly DatabaseApiSettings _settings;

        private readonly HttpClient _httpClient;
        private readonly JsonSerializerOptions _jsonOptions;

        private ApiUserAccessResponse? accessTokenData = null;

        public DatabaseApiService(ILogger<DatabaseApiService> logger, IOptions<DatabaseApiSettings> settings)
        {
            _logger = logger;
            _settings = settings.Value;

            // Create HttpClient and set base URI from DatabaseApiSettings.
            _httpClient = new()
            {
                BaseAddress = new Uri(settings.Value.RemoteUri)
            };

            // Create default JSON serializer options, specifically to remove the default 'to camelCase' naming policy.
            _jsonOptions = new()
            {
                PropertyNamingPolicy = null     // Retains PascalCase
            };
        }

        /// <summary>
        /// This method calls a basic MongoDB function using the database connection, which fails if
        ///  the connection is unsuccessful. Returns true if successful, false if failure.
        /// </summary>
        /// <returns> True if the database connection is valid, false otherwise. </returns>
        public async Task<bool> CheckConnectionStatus()
        {
            try
            {
                // The HTTP request will throw an HttpRequestException (timeout) if the server is offline.
                using HttpResponseMessage response = await _httpClient.GetAsync("ping");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return false;
            }
        }



        public async Task<List<UserAccountModel>?> GetAllAsync()
        {
            if (!await EnsureAccessTokenIsValid()) return null;

            try
            {
                // Make request to database API to find user accounts. HttpClient has access token automatically configured.
                var rawResponse = await _httpClient.GetAsync($"/users");
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation("Failed to get all user accounts from database API: " + errorMessage);
                    return null;
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<List<UserAccountModel>>() ?? throw new JsonException();

                return responseData;
            }
            catch (Exception ex)
            {
                _logger.LogError("[EXCEPTION] Failed to get all user accounts from database API: " + ex.Message);
                return null;
            }
        }

        public async Task<UserAccountModel?> GetOneByIdAsync(string id)
        {
            if (!await EnsureAccessTokenIsValid()) return null;

            try
            {
                // Make request to database API to find user account by ID (ObjectId). HttpClient has access token automatically configured.
                var rawResponse = await _httpClient.GetAsync($"/users/id/{id}");
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation($"Failed to get user account by ID from database API (ID: {id}): " + errorMessage);
                    return null;
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<UserAccountModel>() ?? throw new JsonException();

                return responseData;
            }
            catch (Exception ex)
            {
                _logger.LogError("[EXCEPTION] Failed to get user account by ID from database API: " + ex.Message);
                return null;
            }
        }

        public async Task<UserAccountModel?> GetOneByUsernameAsync(string username)
        {
            if (!await EnsureAccessTokenIsValid()) return null;

            try
            {
                // Make request to database API to find user account by username. HttpClient has access token automatically configured.
                var rawResponse = await _httpClient.GetAsync($"/users/username/{username}");
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation($"Failed to get user account by username from database API (username: {username}): " + errorMessage);
                    return null;
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<UserAccountModel>() ?? throw new JsonException();

                return responseData;
            }
            catch (Exception ex)
            {
                _logger.LogError("[EXCEPTION] Failed to get user account by username from database API: " + ex.Message);
                return null;
            }
        }

        public async Task<UserAccountModel?> GetOneByEmailAsync(string email)
        {
            if (!await EnsureAccessTokenIsValid()) return null;

            try
            {
                // Make request to database API to find user account by email. HttpClient has access token automatically configured.
                var rawResponse = await _httpClient.GetAsync($"/users/email/{email}");
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation($"Failed to get user account by email from database API (email: {email}): " + errorMessage);
                    return null;
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<UserAccountModel>() ?? throw new JsonException();

                return responseData;
            }
            catch (Exception ex)
            {
                _logger.LogError("[EXCEPTION] Failed to get user account by email from database API: " + ex.Message);
                return null;
            }
        }



        public async Task<bool> InsertOneAsync(UserAccountModel model)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request, automatically parsing UserAccountModel to JSON. HttpClient has access token automatically configured.
                var rawResponse = await _httpClient.PostAsJsonAsync($"/users", model, _jsonOptions);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation($"Failed to insert user account to database API (username: {model.Username}): " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to insert user account to database API: " + ex.Message);
                return false;
            }
        }



        public async Task<bool> UpdateOneByIdAsync<T>(string id, T patchData)
        {
            try
            {
                // Make request, automatically parsing anonymous data to JSON. HttpClient has access token automatically configured.
                var rawResponse = await _httpClient.PatchAsJsonAsync($"/users/id/{id}", patchData, _jsonOptions);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation($"Failed to update user account by ID in database API (ID: {id}): " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("[EXCEPTION] Failed to update user account by ID in database API: " + ex.Message);
                return false;
            }
        }



        public async Task<bool> ReplaceOneByIdAsync(string id, UserAccountModel model)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request, automatically parsing UserAccountModel to JSON. HttpClient has access token automatically configured.
                var rawResponse = await _httpClient.PutAsJsonAsync($"/users/id/{id}", model, _jsonOptions);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation($"Failed to replace user account by ID in database API (ID: {model.Id}): " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("[EXCEPTION] Failed to replace user account by ID in database API: " + ex.Message);
                return false;
            }
        }



        public async Task<bool> DeleteOneByIdAsync(string id)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request to database API to delete item by ID. HttpClient has access token automatically configured.
                var rawResponse = await _httpClient.DeleteAsync($"/users/id/{id}");
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation($"Failed to delete user account by ID from database API (ID: {id}): " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("[EXCEPTION] Failed to delete user account by ID from database API: " + ex.Message);
                return false;
            }
        }



        public async Task<bool> IsSecondaryEmailInUseAsync(string secondaryEmail)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request to database API to find user account by secondary email. HttpClient has access token automatically configured.
                var rawResponse = await _httpClient.GetAsync($"/users/email-secondary/{secondaryEmail}");
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If status code is 404, then the email is not in use, so return false.
                    if (rawResponse.StatusCode == HttpStatusCode.NotFound)
                    {
                        return false;
                    }

                    // Else any other status code is an error, so read it and return true (in use) to be safe.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogInformation($"Failed to check whether secondary email is in use from database API (secondary email: {secondaryEmail}): " + errorMessage);
                    return true;
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<UserAccountModel>() ?? throw new JsonException();

                // If response data is not null (retrieved valid account), then in use so return true.
                if (responseData != null)
                {
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("[EXCEPTION] Failed to check whether secondary email is in use from database API: " + ex.Message);
                return true;            // Assume true to be safe.
            }
        }



        #region Private: Remote API Login AND Request Modularization

        /// <summary>
        /// Checks whether there is a current, valid access token (which is required to access the remote
        ///  database API. If not valid, tries to log in again. Returns a boolean describing whether the
        ///  current access token is valid and usable. Handles all login processing within this method.
        /// </summary>
        /// <returns> True if the current token is valid OR a valid new token was acquired, false otherwise. </returns>
        private async Task<bool> EnsureAccessTokenIsValid()
        {
            // If access token data is null or empty OR expiration is less than one minute from now, try to log in again.
            if (accessTokenData == null || accessTokenData.AccessTokenExpiration - DateTime.UtcNow < TimeSpan.FromMinutes(1))
            {
                return await LoginToDatabaseApi();  // Directly return result of login.
            }

            return true;
        }

        /// <summary>
        /// Tries to log into the remote database API using credentials stored in configuration environment
        ///  variables. Handles all processing internally, setting access token in-memory fields if success.
        ///  Returns a boolean describing whether the login was successful (logs internally).
        /// </summary>
        /// <returns> True if login was successful, false otherwise. </returns>
        private async Task<bool> LoginToDatabaseApi()
        {
            try
            {
                // Make request to database API to log in as API user. Create anonymous type for username and password payload.
                var rawResponse = await _httpClient.PostAsJsonAsync($"/auth/login", new
                {
                    Username = _settings.Username,
                    Password = _settings.Password
                }, _jsonOptions);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogError("failed to log into database API: " + errorMessage);
                    return false;
                }

                // Parse raw response into ApiUserAccessResponse. Will automatically throw exception within method on failure.
                var responseModel = await rawResponse.Content.ReadFromJsonAsync<ApiUserAccessResponse>() ?? throw new JsonException();

                // Ensure access response has valid fields.
                if (string.IsNullOrEmpty(responseModel.AccessToken) || responseModel.AccessTokenExpiration < DateTime.UtcNow)
                {
                    _logger.LogError("failed to log into database API: malformed ApiUserAccessResponse data");
                    return false;
                }

                // Else successful, so store tokens and expiration AND set HttpClient bearer token (sent automatically on request).
                _logger.LogInformation("successfully (re)logged into database API");
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", responseModel.AccessToken);
                accessTokenData = responseModel;
                return true;
            }
            catch (JsonException ex)
            {
                _logger.LogError("Failed to log into database API: " + ex.Message);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to log into database API: " + ex.Message);
                return false;
            }
        }

        #endregion

    }
}
