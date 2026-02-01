# Summary

This project runs a login API backend which allows users to login, logout, and manage account state for an exploratory in-development RPG project. It is designed for use alongside the RPG_Launcher WPF desktop application. It securely handles user account access and management, database access, and account data retrieval for gameplay purposes (like retrieving in-game character data for a 'game start' screen). Currently, this API directly accesses a secure MongoDB instance; in the future, it will access the database using a dedicated database API.

---

# Technical Description

The login web API runs on ASP.NET Core using .NET 8. It is designed from the ground up using industry best practices for structure and security, like heavily leveraging Dependency Injection and carefully considering separation of responsibilities, as well as ensuring that account information like passwords are stored in salted and hashed form within the database according to current OWASP standards. This project is still under development and will be expanded with more features like admin access and other game-relevant operations.

### API Controller(s) and endpoints

ASP.NET Core Web APIs are split into split into two primary areas of consideration: Controllers and Services. Services perform actual logical operations and are passed around the web application using Dependency Injection (DI), with this structure being heavily leveraged by ASP.NET by design. On the other hand, Controllers define and run API endpoints which directly process user requests and responses. In this API, most controller endpoints are concerned with account login and security operations like login, register, logout, verify email, submit confirmation code, reset password, and so on. Other endpoints include non-account-management operations like retrieving a list of RPG Character IDs owned by the account. The API controller depends on the LoginApiService class for actual functionality.

### Services and Dependency Injection

Dependency Injection (DI) is heavily leveraged by ASP.NET Core web applications as is the industry standard for managing multiple services in a modular and maintainable way. DI allows clear decoupling of services from one another, helping prevent 'spaghetti code' by enabling separation of concerns. In this API, multiple services are used alongside one another to ensure that each service is only responsible for a specific category of tasks rather than creating a single monolithic service that does everything. The three main services are:
1. Database Service - This service is registered as a singleton and is the only part of the application that connects to and performs CRUD operations on the MongoDB database (see the Database Solution section below). This service securely connects to the database (with MongoDB user authentication) and then verifies that it is successfully connected by performing a basic query on the MongoDB Instance.
2. Token Service - This service is registered as a singleton and is tasked with performing all manual JWT token operations like token creation, parsing, and comparison. It retrives a secure JWT signing key on application initialization and uses it to build token validation parameters. While the ASP.NET Core validation middleware typically handles access token validation in the controller, various manual JWT token operations must be performed using this service.
3. Login API Service - This is the main service that the Controller uses. This service depends directly on the two aforementioned services to perform CRUD operations on the database and to handle manual JWT token operations when necessary. Both of these services are passed to this service via DI on application initialization, then finally this service is automatically passed to the Controller when the application is built.

### Database solution

Currently, MongoDB is the database solution used to store account data. This leverages the official .NET MongoDB Driver NuGet package, which offers a robust toolset for interacting with MongoDB instances/databases/collections. User account objects are defined as MongoDB BSON models and used by the DatabaseService class to perform CRUD operations on the database. The MongoDB driver handles all conversion to and from BSON/JSON, given that the correct model classes are implemented.

### Logging

ASP.NET Core implements a robust logging system by default, and this system is used throughout the API. At the moment, only console logging is being used (this can be extended to support third-party libraries in the future). The built-in ILogger<> interface is passed via DI into each service and controller, abstracting any lower-level logging behavior from API development entirely. Methods like LogInformation() and LogError() can be easily called using the ILogger<> object. The application's *appsettings.json* file allows configuring the minimum log level that will be actually written/printed. By default, Information is the minimum for generic logging, whereas Warning is the default for ASP.NET logging (?).

---

# Security

### Secure communication over HTTPS

The API is only accessible by clients via TLS-secured HTTPS communication. ASP.NET handles this configuration automatically, given that launchSettings.json is configured to remove the HTTP profile. Currently, a self-signed certificate is being used to facilitate TLS, though this will need to be a valid third-party CA signed certificate in the future.

### Authentication and authorization

As is standard for any secure API, user authentication and authorization is critical. At the heart of this system lies Json Web Tokens (JWTs), which are used for authenticating users on login and for verifying a user's authorization when trying to access API endpoints. User data used for authentication is stored in a secure MongoDB database collection (details in the Secure Account Storage section below). Authorization depends on JWT token Role claims embedded inside the tokens, and are determined based on account state and checked on a per-API-endpoint basis.

### JWT access tokens and refresh tokens

Two different token types are primarily used for user account access and API endpoint access:
- Refresh tokens are persistent, long-lived JWT tokens which are used by clients to log in without requiring the user to enter their credentials again. On successful login, the API returns a new refresh token (along with an access token) to the client and stores this token internally within the database document associated with the user account. The client should securely store this token in a cookie or some other secure storage (like Windows DPAPI for a WPF app), and pass it to the login-from-refresh-token API endpoint to re-login without requiring full credentials. The API will validate this token and compare it against the stored token in the database to ensure the identity of the user. Upon successful refresh login, the old refresh token is replaced with a new token to improve security and ensure that the user's account access is persistent.
- Access tokens are short-lived JWT tokens which are used universally to manage API endpoint access. A valid access token is the only way in which clients verify that they are securely logged in. A new token is returned by the API on successful login, and importantly is *not* stored server-side at all (stateless). Clients must provide a valid access token to the server whenever trying to access any non-login endpoint, which the server will then validate using built-in ASP.NET Core validation middleware. Access tokens store a unique username, a per-token GUID, and a Role which determines which endpoints the token allows access to; these together with the secret JWT signing key allow the API to ensure the validity of the user providing the token. When an access token is close to expiration, it is the client's responsibility to renew their token by logging into the API again with their stored refresh token. Upon logout request, the API validates the passed-in access token then invalidates the user's refresh token in the database and blacklists the current access token until it expires.

### Secure user account storage in database

The MongoDB database used by the API carefully implements user roles to ensure that users (like this API) can only access the database(s) and collection(s) necessary to operate. The connection string that this API uses to connect to the database includes credentials for a database user which can only access the necessary database and collection, adhering to the Principle of Least Privilege. Naturally, this connection string is highly sensitive and is stored outside the project in a secure location (see section below).

Additionally, user data within the database follows industry standards to ensure the integrity of user accounts in case of a database breach. Most importantly, passwords are *never* stored in plaintext form, and are instead stored in salted and hashed form. The API handles generating salt and hash, and this process follows current OWASP standards to ensure proper security (currently uses PBKDF2 with 600000 iterations, as is the OWASP standard as of December 2025). This can and should be updated as OWASP standards change. Refresh tokens stored within the database are also hashed using a secure hashing algorithm (SHA256), but are not salted.

### Secret storage (for development only)

Sensitive data like JWT token signing key and MongoDB instance connection string must never be hard-coded or stored anywhere that it is at risk of being compromised. For development, the API is leveraging the built-in ASP.NET Core **User Secrets file (secrets.json)** which exists outside the solution/project directory and thus is not at risk of accidentally being included in source control like Git. Note that this file is unencrypted and is thus not particularly secure, and thus should only be used for production. Generally, environment variables (or servies like **Azure Key Vault**) should be used for secure secret storage in production.

On application initialization, the built-in ASP.NET Core configuration manager is used to access the secrets.json file by section and retrieve data accordingly. An example file named *secrets.example.json* is include in the project which demonstrates the file structure that is expected by the application. In Visual Studio, the associated secrets file can be accessed by *[Right Click Project] -> Manage User Secrets*. This will open the secrets.json file, which should be populated to match the *secrets.example.json* example file.

### Other account security considerations

To help mitigate account security concerns (not to be mistaken for API security concerns), a handful of account security considerations are done on the server. These are concerned primarily with account security from the user's perspective, not technical API security.

**NOTE: Many of these are not yet implemented, as the project is still being developed.**

- One example is refresh and access token invalidation on the server whenever a user manually logs out *or* whenever suspicious activity is detected for a given account; instead of allowing an access token remain valid until expiration, the token's ID is added to a blacklist to ensure that a now-invalidated token cannot be misused for the remainder of its original 15-minute duration.
- Another security feature is account locking after multiple consecutive failed login attempts. When a given account retrieves a significant number (ex. 3+ or 5+) failed login attempts within a short period of time, the user account is locked and will require a password change (which requires email verification) on next successful login. This also invalidates the account's stored refresh token in the database, if one exists.
- Password reset logic requires submitting a short-duration (5 minute) one-time confirmation code that is sent to the user account's associated email. This confirmation is required for any password change, whether user-initiated (ex. via forgot password) or API-initiated (ex. account lock on too many failed login attempts). After submitting this confirmation code, the user is given a 5-minute one-time-use *password reset token* that must be submitted to the associated 'change password' API endpoint. Using a reset token instead of the normal access token with a dedicated 'reset' Role claim helps prevent the risk of undesired endpoint access. Unlike with access tokens, the server retains an in-memory list of both confirmation codes and reset tokens to ensure one-time-only use (not stateless).
