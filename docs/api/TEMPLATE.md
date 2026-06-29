# API Documentation Template

Use this template for documenting each service's endpoints. Copy and customize for each service.

---

## [SERVICE NAME] API Reference

**Base URL**: `http://localhost:[PORT]/api/v1`
**Service**: [Service Description]
**Authentication**: Bearer Token (JWT) in Authorization header

### Table of Contents
- [Authentication](#authentication)
- [Endpoints](#endpoints)
  - [Endpoint Group 1](#endpoint-group-1)
  - [Endpoint Group 2](#endpoint-group-2)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Examples](#examples)

---

## Authentication

All endpoints require authentication via Bearer token in the Authorization header:

```bash
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Obtaining a Token**:
```bash
curl -X POST http://localhost:[PORT]/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "your-password"
  }'
```

---

## Endpoints

### Endpoint Group 1

#### GET /resource

Retrieve a list of resources.

**Method**: `GET`
**Path**: `/v1/resource`
**Authentication**: Required (Bearer Token)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `limit` | integer | No | Number of results to return (default: 20, max: 100) |
| `offset` | integer | No | Pagination offset (default: 0) |
| `filter` | string | No | Filter expression for results |
| `sort` | string | No | Sort field and direction (e.g., "name:asc") |

**Request**:
```bash
curl -X GET "http://localhost:[PORT]/v1/resource?limit=10&offset=0" \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json"
```

**Response (200 OK)**:
```json
{
  "data": [
    {
      "id": "resource-001",
      "name": "Resource Name",
      "status": "active",
      "created_at": "2024-11-07T10:30:00Z"
    }
  ],
  "pagination": {
    "limit": 10,
    "offset": 0,
    "total": 150
  },
  "status": "success"
}
```

**Error Response (401 Unauthorized)**:
```json
{
  "error": "Unauthorized",
  "message": "Invalid or missing authentication token",
  "status": "error"
}
```

---

#### POST /resource

Create a new resource.

**Method**: `POST`
**Path**: `/v1/resource`
**Authentication**: Required (Bearer Token)
**Content-Type**: `application/json`

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Resource name (max 255 characters) |
| `description` | string | No | Resource description |
| `config` | object | No | Configuration parameters |

**Request**:
```bash
curl -X POST http://localhost:[PORT]/v1/resource \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Resource",
    "description": "Resource description",
    "config": {
      "enabled": true
    }
  }'
```

**Response (201 Created)**:
```json
{
  "data": {
    "id": "resource-002",
    "name": "New Resource",
    "description": "Resource description",
    "config": {
      "enabled": true
    },
    "created_at": "2024-11-07T10:35:00Z"
  },
  "status": "success"
}
```

**Error Response (400 Bad Request)**:
```json
{
  "error": "Bad Request",
  "message": "Field 'name' is required",
  "status": "error",
  "validation_errors": {
    "name": "This field is required"
  }
}
```

---

#### GET /resource/{id}

Retrieve a specific resource by ID.

**Method**: `GET`
**Path**: `/v1/resource/{id}`
**Authentication**: Required (Bearer Token)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| `id` | string | Resource ID |

**Request**:
```bash
curl -X GET http://localhost:[PORT]/v1/resource/resource-002 \
  -H "Authorization: Bearer {token}"
```

**Response (200 OK)**:
```json
{
  "data": {
    "id": "resource-002",
    "name": "New Resource",
    "description": "Resource description",
    "status": "active",
    "created_at": "2024-11-07T10:35:00Z",
    "updated_at": "2024-11-07T10:35:00Z"
  },
  "status": "success"
}
```

---

#### PUT /resource/{id}

Update an existing resource.

**Method**: `PUT`
**Path**: `/v1/resource/{id}`
**Authentication**: Required (Bearer Token)

**Request Body**:
```bash
curl -X PUT http://localhost:[PORT]/v1/resource/resource-002 \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Resource Name",
    "description": "Updated description"
  }'
```

**Response (200 OK)**:
```json
{
  "data": {
    "id": "resource-002",
    "name": "Updated Resource Name",
    "description": "Updated description",
    "updated_at": "2024-11-07T10:40:00Z"
  },
  "status": "success"
}
```

---

#### DELETE /resource/{id}

Delete a resource.

**Method**: `DELETE`
**Path**: `/v1/resource/{id}`
**Authentication**: Required (Bearer Token)

**Request**:
```bash
curl -X DELETE http://localhost:[PORT]/v1/resource/resource-002 \
  -H "Authorization: Bearer {token}"
```

**Response (204 No Content)**:
```
(Empty response body)
```

---

## Error Handling

The API uses standard HTTP status codes and returns error details in JSON format.

### Common Error Codes

| Code | Error | Description |
|------|-------|-------------|
| 400 | Bad Request | Invalid request parameters or body |
| 401 | Unauthorized | Missing or invalid authentication token |
| 403 | Forbidden | Authenticated but not authorized for this resource |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error (contact support) |

### Error Response Format

```json
{
  "error": "Error Code",
  "message": "Human-readable error message",
  "status": "error",
  "request_id": "req-12345",
  "timestamp": "2024-11-07T10:45:00Z"
}
```

---

## Rate Limiting

API endpoints are rate limited to prevent abuse.

**Rate Limits**:
- **Standard endpoints**: 100 requests/minute per user
- **Analysis endpoints**: 10 requests/minute per user
- **Authentication endpoints**: 5 requests/minute per IP

**Rate Limit Headers**:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1730963100
```

When rate limit is exceeded, the API returns:
```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Try again in 45 seconds.",
  "status": "error"
}
```

---

## Examples

### Complete Workflow Example

**1. Login and get token**:
```bash
TOKEN=$(curl -X POST http://localhost:[PORT]/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password"
  }' | jq -r '.data.token')
```

**2. Create resource**:
```bash
curl -X POST http://localhost:[PORT]/v1/resource \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Resource",
    "description": "Test resource"
  }' | jq '.'
```

**3. Retrieve resource**:
```bash
curl -X GET http://localhost:[PORT]/v1/resource/resource-id \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

**4. Update resource**:
```bash
curl -X PUT http://localhost:[PORT]/v1/resource/resource-id \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Resource"
  }' | jq '.'
```

**5. Delete resource**:
```bash
curl -X DELETE http://localhost:[PORT]/v1/resource/resource-id \
  -H "Authorization: Bearer $TOKEN"
```

---

## SDKs and Libraries

Official SDKs coming soon for:
- Python
- JavaScript/TypeScript
- Go
- Java

Check [GitHub releases](https://github.com/fabriziosalmi/wildbox/releases) for SDK availability.

---

## Support

For API documentation questions:
- **Documentation Issues**: [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions)
- **Security Issues**: fabrizio.salmi@gmail.com

---

**Last Updated**: November 7, 2024
**API Version**: v1
**Status**: Actively Maintained
