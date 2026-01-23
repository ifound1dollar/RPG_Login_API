# Summary

This project runs a login API backend that supports the RPG_Launcher WPF desktop application. It securely handles user account access and management, database access, and account data retrieval for gameplay purposes (like retrieving in-game character data for a 'game start' screen). Currently, this API directly accesses a secure MongoDB instance; in the future, it will itself access the database using a dedicated database API.

## High-level description

DESCRIBE (much of this can be pulled from NetworkServices description):
- basic information like operating only over HTTPS
- JWT tokens, authentication, and role claims
- secret storage outside of the project/solution directory, noting that this is safe for development only (see NetworkServices description)
- secure user account storage in database (database also secured by roles and password protection)
- endpoints like login, register, confirm, etc.
- refresh and access token logic, with refresh tokens stored only in hashed form in the database
- security considerations server-side, like token invalidation, failed login attempt counters, and password reset tokens