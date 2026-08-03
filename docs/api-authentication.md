# API Authentication & Reference

## Overview

This document provides comprehensive API documentation for all REST Controllers in the Passwordless Multi-Auth project. The API follows RESTful principles with standardized response formats and internationalization support.

**Base URL:** `/api`

**Authentication:** JWT Token-based (obtained via MagicLink authentication flow)

---

## Table of Contents

1. [Authentication API](#1-authentication-api)
2. [User Management API](#2-user-management-api)
3. [Role Management API](#3-role-management-api)
4. [Authority Management API](#4-authority-management-api)
5. [Last Login Info API](#5-last-login-info-api)
6. [Push Notification API](#6-push-notification-api)
7. [Common DTOs](#7-common-dtos)

---

## 1. Authentication API

**Controller:** `AuthController`  
**Base Path:** `/api/auth`

### 1.1 Send MagicLink

Send a passwordless MagicLink to user's email for API/mobile authentication.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/auth/email-magiclink/send` |
| **HTTP Method** | `POST` |
| **@PreAuthorize** | Public (no authentication required) |

**Request Body:**
```json
{
  "email": "string"  // Required, valid email format
}
```

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "login.magiclink.sent",
  "locale": "en",
  "data": {
    "email": "user@example.com",
    "ttlSeconds": 120,
    "expiresAt": "2025-01-20T10:17:00Z"
  },
  "timestamp": "2025-01-20T10:15:00Z"
}
```

> **Anti-enumeration:** The same success response is returned whether or not the
> account exists; a MagicLink is only generated and emailed for existing accounts.
> The token is single-use and expires after `app.magiclink.api.ttl-seconds`
> (default **120 seconds**).

**Error Responses:**
- `400 Bad Request` - Invalid email format or missing email
- `500 Internal Server Error` - Email sending failed

---

### 1.2 Verify MagicLink (Browser Entry Point)

Verify a MagicLink token from the email link. This endpoint is opened in the **browser**,
so it never returns JSON — it responds with a `302` redirect to the mobile app scheme
(`app.mobile.callback-url`, default `passwordless://auth/callback`).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/auth/verify` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | Public (no authentication required) |

**Request Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | String | Yes | MagicLink token from email |

**Redirect Outcomes** (`302 Found`, `Location: passwordless://auth/callback?...`):

| Query | Meaning | Next step |
|-------|---------|-----------|
| `?code={oneTimeCode}` | Login success | `POST /api/auth/exchange` (see 1.3) |
| `?status=totp_required&username={u}&email={e}` | MFA enabled | `POST /api/auth/totp/verify` (see 1.4) |
| `?status=error&reason={reason}` | Failure | Show error to the user |

Possible `reason` values: `token_missing`, `token_invalid`, `user_not_found`,
`account_disabled`, `account_locked`, `verification_failed`.

---

### 1.3 Exchange Code for Tokens

Trade the one-time exchange code (from the app-scheme redirect) for a token pair.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/auth/exchange` |
| **HTTP Method** | `POST` |
| **@PreAuthorize** | Public (no authentication required) |

**Request Body:**
```json
{
  "code": "string"  // Required, one-time code from the redirect (60 s TTL, single use)
}
```

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "login.success",
  "locale": "en",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "expiresAt": "2025-01-20T11:15:00Z",
    "refreshToken": "9f3b2c1d-...",
    "refreshTokenExpiresAt": "2025-02-19T10:15:00Z"
  },
  "timestamp": "2025-01-20T10:15:00Z"
}
```

Access tokens expire after `app.jwt.ttl-seconds` (default **1 hour**);
refresh tokens after `app.jwt.refresh-ttl-seconds` (default **30 days**).

**Error Responses:**
- `400 Bad Request` - Missing exchange code
- `401 Unauthorized` - Invalid, expired or already used exchange code
- `403 Forbidden` - Account disabled or locked

---

### 1.4 Verify TOTP

Verify TOTP (Time-based One-Time Password) code for MFA.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/auth/totp/verify` |
| **HTTP Method** | `POST` |
| **@PreAuthorize** | Public (after MagicLink verification) |

**Request Body:**
```json
{
  "username": "string",  // Required
  "code": "string"       // Required, 6-digit TOTP code
}
```

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "login.success",
  "locale": "en",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "expiresAt": "2025-01-20T11:15:00Z",
    "refreshToken": "9f3b2c1d-...",
    "refreshTokenExpiresAt": "2025-02-19T10:15:00Z"
  },
  "timestamp": "2025-01-20T10:15:00Z"
}
```

**Error Responses:**
- `400 Bad Request` - TOTP not enabled, invalid code, or verification error
- `403 Forbidden` - Account locked

---

### 1.5 Register User

Register a new user with email verification via OTP.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/auth/register` |
| **HTTP Method** | `POST` |
| **@PreAuthorize** | Public (requires reCAPTCHA) |

**Request Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `X-Recaptcha-Token` | Yes | reCAPTCHA v3 token |

**Request Body:**
```json
{
  "name": "string",   // Required, not blank
  "email": "string"   // Required, valid email format
}
```

**Response:**
```json
{
  "status": "otp_sent"
}
```

**Error Responses:**
- `400 Bad Request` - reCAPTCHA verification failed

---

### 1.6 Verify OTP

Verify OTP code to complete user registration.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/auth/verify-otp` |
| **HTTP Method** | `POST` |
| **@PreAuthorize** | Public |

**Request Body:**
```json
{
  "email": "string",  // Required, valid email format
  "otp": "string"     // Required, not blank
}
```

**Response:**
```json
{
  "status": "verified"
}
```

**Error Responses:**
- `400 Bad Request` - Invalid OTP

---

### 1.7 Refresh Access Token

Exchange a valid refresh token for a new token pair. The presented refresh token
is invalidated (single-use rotation).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/auth/refresh` |
| **HTTP Method** | `POST` |
| **@PreAuthorize** | Public (no authentication required) |

**Request Body:**
```json
{
  "refreshToken": "string"  // Required
}
```

**Response:** same token-pair shape as [1.3](#13-exchange-code-for-tokens).

**Error Responses:**
- `400 Bad Request` - Missing refresh token
- `401 Unauthorized` - Refresh token invalid, expired or already used

---

### 1.8 Logout

Revoke the current access token and (optionally) a refresh token.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/auth/logout` |
| **HTTP Method** | `POST` |
| **@PreAuthorize** | Authenticated (`Authorization: Bearer {token}`) |

**Request Body (optional):**
```json
{
  "refreshToken": "string"  // Also revoke this refresh token
}
```

**Response:** `204 No Content`

---

### 1.9 Current User

Return profile, roles and MFA status of the authenticated user.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/auth/me` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | Authenticated (`Authorization: Bearer {token}`) |

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "api.me.success",
  "locale": "en",
  "data": {
    "username": "john_doe",
    "email": "john@example.com",
    "name": "John Doe",
    "profileImage": "",
    "mfaEnabled": true,
    "roles": ["ROLE_USER"]
  },
  "timestamp": "2025-01-20T10:15:00Z"
}
```

**Error Responses:**
- `401 Unauthorized` - Missing or invalid access token

---

## 2. User Management API

**Controller:** `EnhancedUserController`  
**Base Path:** `/api/users`

### 2.1 Get User Profile

Get user profile information (optimized projection).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/users/{username}/profile` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN') or #username == authentication.name` |

**Path Variables:**
| Variable | Type | Description |
|----------|------|-------------|
| `username` | String | Username of the user |

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "success",
  "locale": "en",
  "data": {
    "username": "john_doe",
    "email": "john@example.com",
    "enabled": true,
    "lastLoginIp": "192.168.1.1",
    "locale": "en"
  },
  "timestamp": "2025-01-20T10:15:00Z"
}
```

---

### 2.2 Get User Security Info

Get user security information including MFA settings (admin only).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/users/{username}/security` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Path Variables:**
| Variable | Type | Description |
|----------|------|-------------|
| `username` | String | Username of the user |

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "success",
  "locale": "en",
  "data": {
    "username": "john_doe",
    "email": "john@example.com",
    "enabled": true,
    "locked": false,
    "mfaEnabled": true,
    "phoneNumber": "+1234567890",
    "oauthProvider": "GOOGLE",
    "lastLoginAt": "2025-01-19T15:30:00Z",
    "lastLoginIp": "192.168.1.1",
    "roles": ["USER", "ADMIN"],
    "locale": "en"
  },
  "timestamp": "2025-01-20T10:15:00Z"
}
```

---

### 2.3 Get Active Users

Get list of active users (admin only).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/users/active` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "success",
  "locale": "en",
  "data": [
    {
      "username": "john_doe",
      "email": "john@example.com",
      "enabled": true,
      "locked": false,
      "createdAt": "2024-01-01T00:00:00Z",
      "lastLoginAt": "2025-01-19T15:30:00Z",
      "locale": "en"
    }
  ],
  "timestamp": "2025-01-20T10:15:00Z"
}
```

---

### 2.4 Get Inactive Users

Get list of inactive users for cleanup operations (admin only).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/users/inactive` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | Integer | 90 | Number of days of inactivity |

**Response:** Same structure as Get Active Users

---

### 2.5 Get Locked Users

Get list of locked users for security review (admin only).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/users/locked` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Response:** Same structure as Get Active Users

---

### 2.6 Get OAuth Users

Get list of users who registered via OAuth (admin only).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/users/oauth` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Response:** Same structure as Get Active Users

---

## 3. Role Management API

**Controller:** `EnhancedRoleController`  
**Base Path:** `/api/roles`

### 3.1 Get Role

Get role information with authorities.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/roles/{code}` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Path Variables:**
| Variable | Type | Description |
|----------|------|-------------|
| `code` | Enum | Role code (USER, ADMIN, SERVICE, etc.) |

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "success",
  "locale": "en",
  "data": {
    "code": "ADMIN",
    "name": "Administrator",
    "authorities": ["user:read", "user:write", "role:manage"],
    "locale": "en"
  },
  "timestamp": "2025-01-20T10:15:00Z"
}
```

---

### 3.2 Get All Roles

Get all roles with authorities.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/roles` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "success",
  "locale": "en",
  "data": [
    {
      "code": "USER",
      "name": "User",
      "authorities": ["user:read"],
      "locale": "en"
    },
    {
      "code": "ADMIN",
      "name": "Administrator",
      "authorities": ["user:read", "user:write", "role:manage"],
      "locale": "en"
    }
  ],
  "timestamp": "2025-01-20T10:15:00Z"
}
```

---

### 3.3 Get Basic Roles

Get basic roles for user assignment (lightweight).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/roles/basic` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Response:** Same structure as Get All Roles

---

## 4. Authority Management API

**Controller:** `EnhancedAuthorityController`  
**Base Path:** `/api/authorities`

### 4.1 Get Authority

Get authority information.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/authorities/{name}` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Path Variables:**
| Variable | Type | Description |
|----------|------|-------------|
| `name` | String | Authority name |

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "success",
  "locale": "en",
  "data": {
    "name": "user:read",
    "description": "Read user information",
    "locale": "en"
  },
  "timestamp": "2025-01-20T10:15:00Z"
}
```

---

### 4.2 Get All Authorities

Get all authorities.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/authorities` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Response:**
```json
{
  "error": false,
  "status": 200,
  "message": "success",
  "locale": "en",
  "data": [
    {
      "name": "user:read",
      "description": "Read user information",
      "locale": "en"
    },
    {
      "name": "user:write",
      "description": "Write user information",
      "locale": "en"
    }
  ],
  "timestamp": "2025-01-20T10:15:00Z"
}
```

---

### 4.3 Search Authorities

Search authorities by name pattern.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/authorities/search` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | String | Yes | Search pattern |

**Response:** Same structure as Get All Authorities

---

### 4.4 Get Authorities by Names (Batch)

Get multiple authorities by names (batch operation).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/authorities/batch` |
| **HTTP Method** | `POST` |
| **@PreAuthorize** | `hasRole('ADMIN')` |

**Request Body:**
```json
["user:read", "user:write", "role:manage"]
```

**Response:** Same structure as Get All Authorities

---

## 5. Last Login Info API

**Controller:** `LastLoginInfoController`  
**Base Path:** `/api/last-login`

### 5.1 Get Current User Last Login

Get last login information for the authenticated user.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/last-login/current` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | Authenticated users |

**Response:**
```json
{
  "email": "user@example.com",
  "userName": "John Doe",
  "loginMethod": "MAGICLINK",
  "profileImageUrl": "https://example.com/avatar.jpg",
  "lastLoginAt": "2025-01-19T15:30:00Z"
}
```

**Note:** Returns `null` if no login info exists or user is not authenticated.

---

### 5.2 Get Last Login by Email

Get last login information by email (for pre-login display).

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/last-login` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | Public |

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `email` | String | No | User email address |

**Response:** Same structure as Get Current User Last Login

**Note:** Returns `null` if email is not provided or no login info exists.

---

## 6. Push Notification API

**Controller:** `PushController`  
**Base Path:** `/api/push`

### 6.1 Send Push Message

Send a push notification message.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/push/send` |
| **HTTP Method** | `POST` |
| **@PreAuthorize** | `hasAnyRole('ADMIN','SERVICE','USER')` |

**Request Body:**
```json
{
  "type": "string",      // Required, message type
  "title": "string",     // Required, message title
  "body": "string",      // Required, message body
  "timestamp": "2025-01-20T10:15:00Z"  // Optional, defaults to now
}
```

**Response:**
- `202 Accepted` - Message accepted for delivery

---

### 6.2 Stream Push Messages

Subscribe to Server-Sent Events (SSE) stream for real-time push notifications.

| Attribute | Value |
|-----------|-------|
| **URL** | `/api/push/stream` |
| **HTTP Method** | `GET` |
| **@PreAuthorize** | Public (connection-based) |
| **Content-Type** | `text/event-stream` |

**Response:**
SSE stream with events:
```
event: notification
data: {"type":"alert","title":"New Message","body":"You have a new notification","timestamp":"2025-01-20T10:15:00Z"}

retry: 3000
```

**Connection Settings:**
- Timeout: 30 minutes
- Reconnect interval: 3 seconds

---

## 7. Common DTOs

### 7.1 ApiResponse<T>

Standardized API response wrapper used by most endpoints.

```java
public record ApiResponse<T>(
    boolean error,      // true if error occurred
    int status,         // HTTP status code
    String message,     // Response message (i18n key or text)
    String locale,      // Response locale (e.g., "en", "en-US")
    T data,             // Payload data (generic type)
    Instant timestamp   // Response timestamp
)
```

### 7.2 UserProfileResponse

```java
public record UserProfileResponse(
    String username,      // User's username
    String email,         // User's email
    boolean enabled,      // Account enabled status
    String lastLoginIp,   // Last login IP address
    String locale         // User's locale
)
```

### 7.3 UserSecurityResponse

```java
public record UserSecurityResponse(
    String username,       // User's username
    String email,          // User's email
    boolean enabled,       // Account enabled status
    boolean locked,        // Account lock status
    boolean mfaEnabled,    // MFA enabled status
    String phoneNumber,    // Phone number (if set)
    String oauthProvider,  // OAuth provider (if applicable)
    Instant lastLoginAt,   // Last login timestamp
    String lastLoginIp,    // Last login IP
    Set<String> roles,     // User roles
    String locale          // User's locale
)
```

### 7.4 UserSummaryResponse

```java
public record UserSummaryResponse(
    String username,     // User's username
    String email,        // User's email
    boolean enabled,     // Account enabled status
    boolean locked,      // Account lock status
    Instant createdAt,   // Account creation timestamp
    Instant lastLoginAt, // Last login timestamp
    String locale        // User's locale
)
```

### 7.5 RoleResponse

```java
public record RoleResponse(
    Role.Code code,      // Role code enum (USER, ADMIN, etc.)
    String name,         // Role display name
    Set<String> authorities,  // Associated authorities
    String locale        // Response locale
)
```

### 7.6 AuthorityResponse

```java
public record AuthorityResponse(
    String name,         // Authority name
    String description,  // Authority description
    String locale        // Response locale
)
```

### 7.7 LoginResponse

```java
public record LoginResponse(
    String token,        // JWT access token
    Instant expiresAt    // Token expiration timestamp
)
```

### 7.8 MagicLinkRequest

```java
public record MagicLinkRequest(
    String email         // User's email address
)
```

### 7.9 MfaVerifyRequest

```java
public record MfaVerifyRequest(
    String username,     // User's username
    String code          // TOTP verification code
)
```

### 7.10 PushMessage

```java
public record PushMessage(
    String type,         // Message type/category
    String title,        // Message title
    String body,         // Message body
    Instant timestamp    // Message timestamp
)
```

---

## Security Notes

1. **JWT Authentication:** Most endpoints require a valid JWT token in the `Authorization` header: `Bearer <token>`

2. **Role-Based Access Control:** Endpoints use `@PreAuthorize` annotations for fine-grained access control

3. **Input Validation:** All DTOs include validation:
   - Email format validation
   - XSS pattern detection
   - Locale format validation (`^[a-z]{2}(-[A-Z]{2})?$`)

4. **reCAPTCHA:** Registration endpoint requires reCAPTCHA v3 token

5. **Rate Limiting:** Authentication endpoints have rate limiting applied

---

## Error Response Format

All errors follow the standardized format:

```json
{
  "error": true,
  "status": 400,
  "message": "error.message.key",
  "locale": "en",
  "data": null,
  "timestamp": "2025-01-20T10:15:00Z"
}
```

Common HTTP Status Codes:
- `200 OK` - Success
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Authentication required or failed
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

---

## Internationalization

All API responses support internationalization. The locale is determined by:
1. `Accept-Language` header
2. User's preferred locale (if authenticated)
3. Default locale (en)

Response messages are i18n keys that can be resolved by clients.
