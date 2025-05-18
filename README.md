# REST Auth Node Manfra

## Overview

This project is a Node.js REST API that demonstrates advanced authentication and authorization mechanisms, including JWT-based authentication, refresh tokens, and Two-Factor Authentication (2FA) using authenticator apps. It also supports role-based access control for secure endpoints.

---

## Table of Contents

- [Features](#features)
- [Packages Used](#packages-used)
- [Authentication & Authorization Flow](#authentication--authorization-flow)
- [API Endpoints](#api-endpoints)
- [How 2FA Works](#how-2fa-works)
- [Extending the System](#extending-the-system)
- [Project Structure](#project-structure)

---

## Features

- User registration and login with hashed passwords
- JWT access and refresh tokens for stateless authentication
- Refresh token rotation and blacklisting
- Two-Factor Authentication (2FA) with authenticator apps (TOTP)
- Role-based access control (admin, moderator, member)
- Secure endpoints for sensitive actions
- In-memory and file-based data storage using NeDB

---

## Packages Used

| Package         | 
Purpose                                                                 |
|-----------------|-------------------------------------------------------------------------|
| **express**     | Web framework for building REST APIs                                    |
| **bcryptjs**    | Hashing and verifying user passwords                                    |
| **jsonwebtoken**| Creating and verifying JWT access and refresh tokens                    |
| **nedb-promises**| Lightweight, file-based database for storing users and tokens          |
| **node-cache**  | In-memory cache for temporary tokens (e.g., tempToken for 2FA)          |
| **otplib**      | Generating and verifying TOTP codes for 2FA                             |
| **qrcode**      | Generating QR codes for 2FA secret sharing                              |
| **nodemon**     | Development tool for auto-restarting the server on code changes         |

---

## Authentication & Authorization Flow

### 1. **Registration**
- User registers with name, email, and password.
- Password is hashed using bcrypt before being stored.
- User is assigned a default role (`member`).

### 2. **Login**
- User submits email and password.
- If credentials are valid and 2FA is **not enabled**, access and refresh tokens are issued.
- If 2FA **is enabled**, a temporary token (`tempToken`) is issued and the user must verify their OTP.

### 3. **Two-Factor Authentication (2FA)**
- **Enabling 2FA:**  
  Authenticated users can enable 2FA. The server generates a secret and QR code for use with authenticator apps (e.g., Google Authenticator). The secret is stored in the database.
- **Login with 2FA:**  
  After password verification, users must provide an OTP from their authenticator app using the `/api/auth/login/2fa/verify-temp-token` route.
- **Verifying OTP for Sensitive Actions:**  
  Authenticated users can verify their OTP for sensitive actions using `/api/auth/2fa/verify`.

### 4. **Token Management**
- **Access Token:**  
  Short-lived JWT used for authenticating API requests.
- **Refresh Token:**  
  Long-lived JWT used to obtain new access tokens via `/api/auth/refresh-token`.
- **Token Blacklisting:**  
  On logout, tokens are blacklisted to prevent reuse.

### 5. **Authorization**
- **Role-Based Access:**  
  Middleware (`authorizeRoles`) restricts access to certain routes based on user roles (e.g., admin, moderator).
- **Usage Example:**  
  ```js
  app.get('/api/auth/admin/dashboard', authenticateToken, authorizeRoles(['admin']), ...);

### 6. **Middleware**
- **authenticateToken:**  
  Checks for a valid access token and attaches user info to the request.
- **authorizeRoles:**  
  Checks if the authenticated user has the required role(s) for a route.

---

## API Endpoints

| Route                                      | Purpose                                  | Auth Required | 2FA Required | Role Required      |
|---------------------------------------------|------------------------------------------|---------------|--------------|-------------------|
| POST `/api/auth/register`                   | Register new user                        | No            | No           | No                |
| POST `/api/auth/login`                      | Login with email & password              | No            | If enabled   | No                |
| POST `/api/auth/login/2fa/verify-temp-token`| Complete login with OTP                  | Temp token    | Yes          | No                |
| GET  `/api/auth/2fa/generate`               | Enable 2FA, get QR code                  | Yes           | No           | No                |
| POST `/api/auth/2fa/verify`                 | Verify OTP for sensitive actions         | Yes           | Yes          | No                |
| POST `/api/auth/refresh-token`              | Refresh access token                     | Yes           | No           | No                |
| GET  `/api/auth/logout`                     | Logout and blacklist tokens              | Yes           | No           | No                |
| GET  `/api/auth/admin/dashboard`            | Admin dashboard                          | Yes           | No           | Admin             |
| GET  `/api/auth/moderator/dashboard`        | Moderator/Admin dashboard                | Yes           | No           | Admin/Moderator   |

---

## How 2FA Works

1. **Enabling 2FA**
    - User requests to enable 2FA.
    - Server generates a secret and a QR code.
    - User scans the QR code with an authenticator app.
    - Server stores the secret and marks 2FA as enabled.

2. **Login with 2FA**
    - User logs in with email and password.
    - If 2FA is enabled, server issues a temporary token and asks for OTP.
    - User submits OTP and temp token.
    - Server verifies OTP using the stored secret.
    - If valid, server issues access and refresh tokens.

3. **Verifying OTP for Sensitive Actions**
    - For actions like enabling/disabling 2FA or changing security settings, user must provide a valid OTP.
    - Server verifies OTP before allowing the action.

---

## Extending the System

- **Add new roles:**  
  Update the `role` field in user objects and adjust `authorizeRoles` usage.
- **Change token expiration:**  
  Edit values in your `config.js`.
- **Add more sensitive actions:**  
  Use `/api/auth/2fa/verify` to require OTP for those actions.

---

## Project Structure

```
.
├── index.js           # Main application file
├── package.json       # Project metadata and dependencies
├── .env               # Environment variables (not committed)
├── users.db           # NeDB database file for users
├── userRefreshTokens.db # NeDB database file for refresh tokens
├── README.md          # Project documentation
└── ...                # Other supporting files
```

---

## Security Notes

- **Never commit `.env` or database files to version control.**
- **Store refresh tokens securely (preferably in httpOnly cookies).**
- **Always use HTTPS in production.**
- **Keep your JWT secrets and 2FA secrets safe.**

---


---

## Author

*Prajwal Siwakoti*


