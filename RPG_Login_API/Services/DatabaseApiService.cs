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
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Get, "/users", accessTokenData?.AccessToken);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to get all user accounts from database API: " + errorMessage);
                    return null;
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<List<UserAccountModel>>() ?? throw new JsonException();

                return responseData;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to get all user accounts from database API: " + ex.Message);
                return null;
            }
        }

        public async Task<UserAccountModel?> GetOneByIdAsync(string id)
        {
            if (!await EnsureAccessTokenIsValid()) return null;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Get, $"/users/id/{id}", accessTokenData?.AccessToken);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to get user account by ID from database API: " + errorMessage);
                    return null;
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<UserAccountModel>() ?? throw new JsonException();

                return responseData;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to get user account by ID from database API: " + ex.Message);
                return null;
            }
        }

        public async Task<UserAccountModel?> GetOneByUsernameAsync(string username)
        {
            if (!await EnsureAccessTokenIsValid()) return null;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Get, $"/users/username/{username}", accessTokenData?.AccessToken);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to get user account by username from database API: " + errorMessage);
                    return null;
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<UserAccountModel>() ?? throw new JsonException();

                return responseData;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to get user account by username from database API: " + ex.Message);
                return null;
            }
        }

        public async Task<UserAccountModel?> GetOneByEmailAsync(string email)
        {
            if (!await EnsureAccessTokenIsValid()) return null;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Get, $"/users/email/{email}", accessTokenData?.AccessToken);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to get user account by email from database API: " + errorMessage);
                    return null;
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<UserAccountModel>() ?? throw new JsonException();

                return responseData;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to get user account by email from database API: " + ex.Message);
                return null;
            }
        }



        public async Task<bool> InsertOneAsync(UserAccountModel model)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Post, $"/users", accessTokenData?.AccessToken,
                    CreateStringContent(new { model }));        // Directly serialize UserAccountModel into string content.
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to insert user account to database API: " + errorMessage);
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
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Patch, $"/users/id/{id}", accessTokenData?.AccessToken,
                    CreateStringContent(new { patchData }));    // Directly serialize anonymous patch data into string content.
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to update user account by ID to database API: " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to update user account by ID to database API: " + ex.Message);
                return false;
            }
        }

        public async Task<bool> UpdateOneByUsernameAsync<T>(string username, T patchData)
        {
            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Patch, $"/users/username/{username}", accessTokenData?.AccessToken,
                    CreateStringContent(new { patchData }));    // Directly serialize anonymous patch data into string content.
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to update user account by username to database API: " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to update user account by username to database API: " + ex.Message);
                return false;
            }
        }

        public async Task<bool> UpdateOneByEmailAsync<T>(string email, T patchData)
        {
            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Patch, $"/users/email/{email}", accessTokenData?.AccessToken,
                    CreateStringContent(new { patchData }));    // Directly serialize anonymous patch data into string content.
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to update user account by email to database API: " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to update user account by email to database API: " + ex.Message);
                return false;
            }
        }



        public async Task<bool> ReplaceOneByIdAsync(string id, UserAccountModel model)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // TODO: MAKE ALL USERACCOUNTMODEL ENDPOINTS USE THIS INSTEAD OF CUSTOM SERIALIZATION

                //var request = new HttpRequestMessage(HttpMethod.Put, $"/users/id/{id}");
                //request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessTokenData?.AccessToken);

                var rawResponse = await _httpClient.PutAsJsonAsync($"/users/id/{id}", model);

                //// Make request to API and check response code.
                //var rawResponse = await PerformApiRequestAsync(HttpMethod.Put, $"/users/id/{id}", accessTokenData?.AccessToken,
                //    CreateStringContent(new { model }));        // Directly serialize UserAccountModel into string content.
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to replace user account by ID to database API: " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to replace user account by ID to database API: " + ex.Message);
                return false;
            }
        }

        public async Task<bool> ReplaceOneByUsernameAsync(string username, UserAccountModel model)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Put, $"/users/username/{username}", accessTokenData?.AccessToken,
                    CreateStringContent(new { model }));        // Directly serialize UserAccountModel into string content.
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to replace user account by username to database API: " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to replace user account by username to database API: " + ex.Message);
                return false;
            }
        }
        public async Task<bool> ReplaceOneByEmailAsync(string email, UserAccountModel model)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Put, $"/users/email/{email}", accessTokenData?.AccessToken,
                    CreateStringContent(new { model }));        // Directly serialize UserAccountModel into string content.
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to replace user account by email to database API: " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to replace user account by email to database API: " + ex.Message);
                return false;
            }
        }



        public async Task<bool> DeleteOneByIdAsync(string id)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Delete, $"/users/id/{id}", accessTokenData?.AccessToken);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to delete user account by ID from database API: " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to delete user account by ID from database API: " + ex.Message);
                return false;
            }
        }

        public async Task<bool> DeleteOneByUsernameAsync(string username)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Delete, $"/users/username/{username}", accessTokenData?.AccessToken);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to delete user account by username from database API: " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to delete user account by username from database API: " + ex.Message);
                return false;
            }
        }

        public async Task<bool> DeleteOneByEmailAsync(string email)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Delete, $"/users/email/{email}", accessTokenData?.AccessToken);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to delete user account by email from database API: " + errorMessage);
                    return false;
                }

                // Else good status code, so simply return true.
                return true;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to delete user account by email from database API: " + ex.Message);
                return false;
            }
        }



        public async Task<bool> IsSecondaryEmailInUseAsync(string secondaryEmail)
        {
            if (!await EnsureAccessTokenIsValid()) return false;

            try
            {
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Get, $"/users/secondary-email/{secondaryEmail}", accessTokenData?.AccessToken);
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    //_logger.LogError("Failed to check whether secondary email is in use from database API: " + errorMessage);
                    return true;        // Assume true to be safe.
                }

                // Parse raw response into usable data. Will automatically throw exception within method on failure.
                var responseData = await rawResponse.Content.ReadFromJsonAsync<UserAccountModel>() ?? throw new JsonException();

                // If response data is null, then is not in use. Else in use.
                if (responseData != null)
                {
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                //_logger.LogError("Failed to check whether secondary email is in use from database API: " + ex.Message);
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
                // Make request to API and check response code.
                var rawResponse = await PerformApiRequestAsync(HttpMethod.Post, "/auth/login", null, CreateStringContent(new
                {
                    Username = _settings.Username,
                    Password = _settings.Password
                }));
                if (!rawResponse.IsSuccessStatusCode)
                {
                    // If not success status code, then there was some error, so log it and return.
                    string errorMessage = await rawResponse.Content.ReadAsStringAsync();
                    _logger.LogError("Failed to log into database API: " + errorMessage);
                    return false;
                }

                // Parse raw response into ApiUserAccessResponse. Will automatically throw exception within method on failure.
                var responseModel = await rawResponse.Content.ReadFromJsonAsync<ApiUserAccessResponse>() ?? throw new JsonException();

                // Ensure access response has valid fields.
                if (string.IsNullOrEmpty(responseModel.AccessToken) || responseModel.AccessTokenExpiration < DateTime.UtcNow)
                {
                    _logger.LogError("Failed to log into database API: invalid data present in ApiUserAccessResponse");
                    return false;
                }

                // Else successful, so set local field and return true.
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

        #region Private: Request Creation and Execution

        private async Task<HttpResponseMessage> PerformApiRequestAsync(HttpMethod method, string requestUri, string? authToken = null,
            StringContent? content = null)
        {
            // Create request object from required data.
            var request = new HttpRequestMessage(method, requestUri);

            // Add authorization if applicable (non-null).
            if (authToken != null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authToken);
            }

            // If content is present, add it to request.
            if (content != null)
            {
                request.Content = content;
            }

            return await _httpClient.SendAsync(request);
        }

        private static StringContent CreateStringContent<T>(T data)
        {
            return new StringContent(
                JsonSerializer.Serialize(data),
                Encoding.UTF8,
                "application/json");
        }

        #endregion
    }
}
