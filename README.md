# Keycloak Extensions

Playground for [Keycloak](https://www.keycloak.org) extensions, providers, SPI implementations, etc.

[![CI build](https://github.com/dasniko/keycloak-extensions-demo/actions/workflows/maven.yml/badge.svg)](https://github.com/dasniko/keycloak-extensions-demo/actions/workflows/maven.yml)
![](https://img.shields.io/github/license/dasniko/keycloak-extensions-demo?label=License)
![](https://img.shields.io/badge/Keycloak-26.4-blue)

[MFA Authenticator](./mfa-authenticator) - Authenticator sends an OTP email to the user.

### Running in development mode
To run Keycloak with the custom extensions in development mode, use the following command:
```bash
./mvnw clean package -DskipTests '&&' docker compose up
```

### Building Docker Image
To build the Docker image with the custom Keycloak extensions, run the following command:
```bash
./mvnw clean package -DskipTests '&&' docker build -t customized-keycloak:latest .
```  


### Customized Password Validation Endpoint
1. Validate password

```bash
# Request

curl --location '{baseURL}/realms/{realm}/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'client_id={client_id}' \
--data-urlencode 'username={username}' \
--data-urlencode 'password={password}' \
--data-urlencode 'action=validate-password'

# Response

{
    "is_valid": true # or false,
    "message": "Valid password" # or "Invalid password"
}
```

2. Generate Authentication Token (For users with skipped MFA)

```bash
# Request
curl --location '{baseURL}/realms/{realm}/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'client_id={client_id}' \
--data-urlencode 'username={username}' \
--data-urlencode 'password={password}' \
--data-urlencode 'action=login'

# Response

# Successful authentication. 200 OK
{
    "access_token": "{access_token}",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "refresh_token": "{refresh_token}",
    "token_type": "Bearer",
    "not-before-policy": 0,
    "session_state": "{session_state}",
    "scope": "email profile"
}

# Wrong password. 401 Unauthorized
{
    "error": "invalid_grant",
    "error_description": "Invalid user credentials"
}
```

3. Create OTP. (For users requiring MFA)

```bash
# Request
curl --location '{baseURL}/realms/{realm}/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'client_id={client_id}' \
--data-urlencode 'username={username}' \
--data-urlencode 'password={password}' \
--data-urlencode 'action=request-otp'

# Response

## OTP created successfully. 201 Created
{
    "message": ""OTP created successfully""
}

## Wrong password. 401 Unauthorized
{
    "error": "invalid_grant",
    "error_description": "Invalid user credentials"
}

## Frequent requests. 429 Too Many Requests
{
    "status": 429,
    "error": "frequent_otp",
    "error_description": "Minimum time gap two OTPs should be 60 seconds"
}
```

4. Validate OTP and generate Authentication Token (For users requiring MFA)

```bash
# Request
curl --location '{baseURL}/realms/{realm}/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'client_id={client_id}' \
--data-urlencode 'username={username}' \
--data-urlencode 'password={password}' \
--data-urlencode 'otp={otp}' \
--data-urlencode 'action=login'

# Response
# Successful authentication. 200 OK
{
    "access_token": "{access_token}",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "refresh_token": "{refresh_token}",
    "token_type": "Bearer",
    "not-before-policy": 0,
    "session_state": "{session_state}",
    "scope": "email profile"
}
# Wrong password or OTP. 401 Unauthorized
{
    "error": "invalid_grant",
    "error_description": "Invalid user credentials or OTP"
}
```