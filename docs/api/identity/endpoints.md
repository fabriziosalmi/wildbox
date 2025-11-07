# Identity & Authentication Service API

**Service Port**: 8000
**Base URL**: `http://localhost:8000/api/v1`
**Authentication**: Bearer Token (JWT) required
**Documentation**: [Live Swagger UI](http://localhost:8000/docs) | [OpenAPI Schema](http://localhost:8000/openapi.json)

---

## Overview

The Identity Service manages all authentication, authorization, and user account operations in Wildbox. It issues JWT tokens, validates credentials, and maintains user permissions.

## Table of Contents

- [Authentication](#authentication)
- [User Management](#user-management)
- [Token Management](#token-management)
- [Permission Management](#permission-management)
- [Error Codes](#error-codes)

---

## Authentication

### POST /auth/login

User login with email and password. Returns JWT token valid for subsequent API requests.

**Method**: `POST`
**Endpoint**: `/auth/login`
**Authentication**: Not required
**Rate Limit**: 5 requests/minute per IP

**Request Body**:

```json
{
  "email": "user@example.com",
  "password": "your-secure-password"
}
```

**Request**:
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "your-secure-password"
  }'
```

**Response (200 OK)**:
```json
{
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3ItMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0...",
    "user_id": "usr-123",
    "email": "user@example.com",
    "expires_in": 3600,
    "token_type": "Bearer"
  },
  "status": "success"
}
```

**Error (401 Unauthorized)**:
```json
{
  "error": "Unauthorized",
  "message": "Invalid email or password",
  "status": "error"
}
```

**Parameters**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User email address |
| password | string | Yes | User password (minimum 8 characters) |

---

### POST /auth/refresh

Refresh an existing JWT token to extend the session without requiring re-authentication.

**Method**: `POST`
**Endpoint**: `/auth/refresh`
**Authentication**: Required (Bearer Token)

**Request**:
```bash
curl -X POST http://localhost:8000/auth/refresh \
  -H "Authorization: Bearer {current_token}"
```

**Response (200 OK)**:
```json
{
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600
  },
  "status": "success"
}
```

---

### POST /auth/logout

Logout user and revoke the current JWT token. Token becomes invalid for future requests.

**Method**: `POST`
**Endpoint**: `/auth/logout`
**Authentication**: Required (Bearer Token)

**Request**:
```bash
curl -X POST http://localhost:8000/auth/logout \
  -H "Authorization: Bearer {token}"
```

**Response (204 No Content)**:
```
(Empty response body)
```

---

## User Management

### GET /users

List all users with pagination, filtering, and sorting support.

**Method**: `GET`
**Endpoint**: `/users`
**Authentication**: Required (Bearer Token)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | integer | No | 20 | Number of results (max 100) |
| offset | integer | No | 0 | Pagination offset |
| status | string | No | - | Filter by status: active, inactive, suspended |
| role | string | No | - | Filter by role: admin, analyst, viewer |
| sort | string | No | created_at:desc | Sort field and direction |

**Request**:
```bash
curl -X GET "http://localhost:8000/users?limit=10&status=active" \
  -H "Authorization: Bearer {token}"
```

**Response (200 OK)**:
```json
{
  "data": [
    {
      "id": "usr-001",
      "email": "user1@example.com",
      "full_name": "John Doe",
      "role": "analyst",
      "status": "active",
      "created_at": "2024-01-15T10:30:00Z",
      "last_login": "2024-11-07T14:25:00Z"
    },
    {
      "id": "usr-002",
      "email": "user2@example.com",
      "full_name": "Jane Smith",
      "role": "viewer",
      "status": "active",
      "created_at": "2024-02-20T09:15:00Z",
      "last_login": "2024-11-06T16:45:00Z"
    }
  ],
  "pagination": {
    "limit": 10,
    "offset": 0,
    "total": 45,
    "pages": 5
  },
  "status": "success"
}
```

---

### POST /users

Create a new user account with specified role and permissions.

**Method**: `POST`
**Endpoint**: `/users`
**Authentication**: Required (Bearer Token - admin only)

**Request Body**:

```json
{
  "email": "newuser@example.com",
  "full_name": "New User",
  "password": "secure-password-123",
  "role": "analyst",
  "teams": ["team-001", "team-002"]
}
```

**Request**:
```bash
curl -X POST http://localhost:8000/users \
  -H "Authorization: Bearer {admin_token}" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "full_name": "New User",
    "password": "secure-password-123",
    "role": "analyst"
  }'
```

**Response (201 Created)**:
```json
{
  "data": {
    "id": "usr-123",
    "email": "newuser@example.com",
    "full_name": "New User",
    "role": "analyst",
    "status": "active",
    "created_at": "2024-11-07T15:30:00Z"
  },
  "status": "success"
}
```

**Error (400 Bad Request)**:
```json
{
  "error": "Bad Request",
  "message": "Email already exists",
  "status": "error"
}
```

**Parameters**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User email address (must be unique) |
| full_name | string | Yes | User full name |
| password | string | Yes | Initial password (minimum 8 characters) |
| role | string | Yes | User role: admin, analyst, viewer |
| teams | array | No | Team IDs to assign user |

---

### GET /users/{id}

Retrieve detailed information about a specific user.

**Method**: `GET`
**Endpoint**: `/users/{id}`
**Authentication**: Required (Bearer Token)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| id | string | User ID |

**Request**:
```bash
curl -X GET http://localhost:8000/users/usr-001 \
  -H "Authorization: Bearer {token}"
```

**Response (200 OK)**:
```json
{
  "data": {
    "id": "usr-001",
    "email": "user@example.com",
    "full_name": "John Doe",
    "role": "analyst",
    "status": "active",
    "teams": [
      {
        "id": "team-001",
        "name": "Security Team"
      }
    ],
    "permissions": [
      "read:findings",
      "execute:scans",
      "manage:alerts"
    ],
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-11-07T14:25:00Z",
    "last_login": "2024-11-07T14:25:00Z"
  },
  "status": "success"
}
```

---

### PUT /users/{id}

Update user profile, role, permissions, and team assignments.

**Method**: `PUT`
**Endpoint**: `/users/{id}`
**Authentication**: Required (Bearer Token - admin or user updating self)

**Request Body**:
```json
{
  "full_name": "Updated Name",
  "role": "analyst",
  "status": "active",
  "teams": ["team-001", "team-002"]
}
```

**Request**:
```bash
curl -X PUT http://localhost:8000/users/usr-001 \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "Updated Name",
    "role": "analyst"
  }'
```

**Response (200 OK)**:
```json
{
  "data": {
    "id": "usr-001",
    "email": "user@example.com",
    "full_name": "Updated Name",
    "role": "analyst",
    "updated_at": "2024-11-07T15:35:00Z"
  },
  "status": "success"
}
```

---

### DELETE /users/{id}

Delete a user account and revoke all associated tokens and permissions.

**Method**: `DELETE`
**Endpoint**: `/users/{id}`
**Authentication**: Required (Bearer Token - admin only)

**Request**:
```bash
curl -X DELETE http://localhost:8000/users/usr-001 \
  -H "Authorization: Bearer {admin_token}"
```

**Response (204 No Content)**:
```
(Empty response body)
```

---

## Token Management

### GET /tokens

List all active tokens for the current user.

**Method**: `GET`
**Endpoint**: `/tokens`
**Authentication**: Required (Bearer Token)

**Response (200 OK)**:
```json
{
  "data": [
    {
      "id": "token-001",
      "name": "API Token",
      "created_at": "2024-11-07T10:30:00Z",
      "expires_at": "2024-11-08T10:30:00Z",
      "last_used": "2024-11-07T14:25:00Z"
    }
  ],
  "status": "success"
}
```

---

### POST /tokens/revoke

Revoke a specific token immediately.

**Method**: `POST`
**Endpoint**: `/tokens/revoke`
**Authentication**: Required (Bearer Token)

**Request Body**:
```json
{
  "token_id": "token-001"
}
```

---

## Permission Management

### GET /permissions

List all available permissions in the system.

**Method**: `GET`
**Endpoint**: `/permissions`
**Authentication**: Required (Bearer Token)

**Response (200 OK)**:
```json
{
  "data": {
    "read": [
      "read:findings",
      "read:scans",
      "read:reports"
    ],
    "write": [
      "write:findings",
      "write:reports"
    ],
    "execute": [
      "execute:scans",
      "execute:playbooks"
    ],
    "manage": [
      "manage:users",
      "manage:teams",
      "manage:integrations"
    ]
  },
  "status": "success"
}
```

---

## Error Codes

| Code | Status | Description |
|------|--------|-------------|
| 400 | Bad Request | Invalid request parameters or body |
| 401 | Unauthorized | Missing or invalid authentication token |
| 403 | Forbidden | Authenticated but not authorized for this action |
| 404 | Not Found | User or resource not found |
| 409 | Conflict | Resource already exists (e.g., email) |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error (contact support) |

---

## Rate Limiting

Authentication endpoints are rate limited to prevent brute force attacks:

- **Login endpoint**: 5 requests/minute per IP
- **Other endpoints**: 100 requests/minute per user

Rate limit information is returned in response headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1730963100
```

---

## Examples

### Complete Authentication Workflow

```bash
# 1. Login
TOKEN=$(curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password"
  }' | jq -r '.data.token')

# 2. Use token for subsequent requests
curl -X GET http://localhost:8000/users \
  -H "Authorization: Bearer $TOKEN"

# 3. Refresh token if needed
NEW_TOKEN=$(curl -X POST http://localhost:8000/auth/refresh \
  -H "Authorization: Bearer $TOKEN" | jq -r '.data.token')

# 4. Logout
curl -X POST http://localhost:8000/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

---

## Related Documentation

- [Security Policy](../../security/policy.md) - Authentication and authorization requirements
- [API Reference Hub](../api-reference.html) - All service endpoints
- [Quickstart Guide](../../guides/quickstart.md) - Getting started with API

---

**Last Updated**: November 7, 2024
**API Version**: v1
**Status**: Stable
