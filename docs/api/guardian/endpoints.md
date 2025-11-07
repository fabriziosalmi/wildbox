# Guardian Service API

**Service Port**: 8001
**Base URL**: `http://localhost:8001/api/v1`
**Authentication**: API Key (X-API-Key header) or Bearer Token (JWT)
**Documentation**: [Live Swagger UI](http://localhost:8001/docs) | [OpenAPI Schema](http://localhost:8001/api/schema/)

---

## Overview

The Guardian Service is the core orchestration platform for security asset management, vulnerability tracking, and remediation workflows. It manages assets, vulnerabilities, security scanners, compliance frameworks, and incident remediation processes. Guardian integrates with security tools, manages scanning operations, and provides workflow automation for security teams.

## Table of Contents

- [Authentication](#authentication)
- [Assets Management](#assets-management)
- [Vulnerabilities Management](#vulnerabilities-management)
- [Scanner Management](#scanner-management)
- [Integration Management](#integration-management)
- [Remediation & Workflows](#remediation--workflows)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)

---

## Authentication

Guardian Service supports multiple authentication methods:

### API Key Authentication

Use the `X-API-Key` header for API requests:

```bash
curl -X GET http://localhost:8001/api/v1/assets/ \
  -H "X-API-Key: your-api-key-here"
```

### Bearer Token (JWT) Authentication

Use the `Authorization: Bearer` header:

```bash
curl -X GET http://localhost:8001/api/v1/assets/ \
  -H "Authorization: Bearer your-jwt-token-here"
```

### Getting an API Key

**Method**: `POST`
**Endpoint**: `/api/v1/auth/api-keys/`
**Authentication**: Required (Bearer Token)

**Request Body**:
```json
{
  "name": "Production API Key",
  "description": "For production integrations",
  "expires_in_days": 365
}
```

**Request**:
```bash
curl -X POST http://localhost:8001/api/v1/auth/api-keys/ \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API Key",
    "description": "For production integrations",
    "expires_in_days": 365
  }'
```

**Response (201 Created)**:
```json
{
  "id": "key-123",
  "name": "Production API Key",
  "key": "gsk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "created_at": "2024-11-07T10:30:00Z",
  "expires_at": "2025-11-07T10:30:00Z",
  "status": "active"
}
```

---

## Assets Management

### GET /assets/

List all security assets with filtering and pagination.

**Method**: `GET`
**Endpoint**: `/api/v1/assets/`
**Authentication**: Required (API Key or Bearer Token)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | integer | No | 20 | Number of results (max 100) |
| offset | integer | No | 0 | Pagination offset |
| status | string | No | - | Filter by status: active, inactive, vulnerable |
| asset_type | string | No | - | Filter by type: server, network, application, database |
| scan_status | string | No | - | Filter by scan status: scanned, pending, failed |
| severity | string | No | - | Filter by highest vulnerability: critical, high, medium, low |

**Request**:
```bash
curl -X GET "http://localhost:8001/api/v1/assets/?limit=20&status=active&severity=critical" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "count": 150,
  "next": "http://localhost:8001/api/v1/assets/?offset=20",
  "previous": null,
  "results": [
    {
      "id": "asset-001",
      "name": "Production Server 1",
      "asset_type": "server",
      "ip_address": "192.168.1.100",
      "hostname": "prod-server-1.example.com",
      "status": "active",
      "vulnerability_count": 5,
      "critical_count": 2,
      "high_count": 3,
      "last_scanned": "2024-11-07T08:15:00Z",
      "next_scan": "2024-11-08T08:15:00Z",
      "owner": "security-team",
      "tags": ["production", "critical"],
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-11-07T14:25:00Z"
    }
  ],
  "pagination": {
    "limit": 20,
    "offset": 0,
    "total": 150,
    "pages": 8
  }
}
```

### POST /assets/

Create a new asset in the system.

**Method**: `POST`
**Endpoint**: `/api/v1/assets/`
**Authentication**: Required (API Key or Bearer Token)

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Asset name or hostname |
| asset_type | string | Yes | Type: server, network, application, database, container |
| ip_address | string | No | IPv4 or IPv6 address |
| hostname | string | No | FQDN or hostname |
| description | string | No | Asset description |
| owner | string | No | Owner or team name |
| tags | array | No | Tags for organization |

**Request**:
```bash
curl -X POST http://localhost:8001/api/v1/assets/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Database Server",
    "asset_type": "database",
    "ip_address": "192.168.1.50",
    "hostname": "db-prod.example.com",
    "owner": "dba-team",
    "tags": ["production", "database", "critical"]
  }'
```

**Response (201 Created)**:
```json
{
  "id": "asset-456",
  "name": "Database Server",
  "asset_type": "database",
  "ip_address": "192.168.1.50",
  "hostname": "db-prod.example.com",
  "status": "active",
  "owner": "dba-team",
  "tags": ["production", "database", "critical"],
  "vulnerability_count": 0,
  "created_at": "2024-11-07T15:30:00Z",
  "updated_at": "2024-11-07T15:30:00Z"
}
```

### GET /assets/{id}/

Retrieve detailed information about a specific asset.

**Method**: `GET`
**Endpoint**: `/api/v1/assets/{id}/`
**Authentication**: Required (API Key or Bearer Token)

**Path Parameters**:

| Name | Type | Description |
|------|------|-------------|
| id | string | Asset ID |

**Request**:
```bash
curl -X GET http://localhost:8001/api/v1/assets/asset-001/ \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "id": "asset-001",
  "name": "Production Server 1",
  "asset_type": "server",
  "ip_address": "192.168.1.100",
  "hostname": "prod-server-1.example.com",
  "status": "active",
  "owner": "security-team",
  "tags": ["production", "critical"],
  "description": "Main production application server",
  "vulnerabilities": [
    {
      "id": "vuln-123",
      "title": "SQL Injection in API",
      "severity": "critical",
      "cvss_score": 9.8,
      "status": "open"
    }
  ],
  "scan_history": [
    {
      "id": "scan-789",
      "scanner_name": "Nessus",
      "status": "completed",
      "vulnerabilities_found": 5,
      "started_at": "2024-11-07T08:00:00Z",
      "completed_at": "2024-11-07T08:15:00Z"
    }
  ],
  "last_scanned": "2024-11-07T08:15:00Z",
  "next_scan": "2024-11-08T08:15:00Z",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-11-07T14:25:00Z"
}
```

### PUT /assets/{id}/

Update an asset's information.

**Method**: `PUT`
**Endpoint**: `/api/v1/assets/{id}/`
**Authentication**: Required (API Key or Bearer Token)

**Request Body**:
```json
{
  "name": "Production Server 1 - Updated",
  "owner": "new-team",
  "tags": ["production", "critical", "updated"],
  "description": "Updated description"
}
```

**Request**:
```bash
curl -X PUT http://localhost:8001/api/v1/assets/asset-001/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "owner": "new-team",
    "tags": ["production", "critical"]
  }'
```

**Response (200 OK)**:
```json
{
  "id": "asset-001",
  "name": "Production Server 1 - Updated",
  "owner": "new-team",
  "tags": ["production", "critical"],
  "updated_at": "2024-11-07T16:30:00Z"
}
```

### DELETE /assets/{id}/

Delete an asset from the system.

**Method**: `DELETE`
**Endpoint**: `/api/v1/assets/{id}/`
**Authentication**: Required (API Key or Bearer Token - admin only)

**Request**:
```bash
curl -X DELETE http://localhost:8001/api/v1/assets/asset-001/ \
  -H "X-API-Key: your-api-key"
```

**Response (204 No Content)**:
```
(Empty response body)
```

### POST /assets/{id}/scan/

Initiate a security scan on an asset.

**Method**: `POST`
**Endpoint**: `/api/v1/assets/{id}/scan/`
**Authentication**: Required (API Key or Bearer Token)

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| scanner_id | string | Yes | Scanner ID to use for scanning |
| scan_profile | string | No | Scan profile: full, quick, vulnerability-only |
| schedule | string | No | Schedule: immediate, daily, weekly |

**Request**:
```bash
curl -X POST http://localhost:8001/api/v1/assets/asset-001/scan/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "scanner_id": "scanner-nessus-01",
    "scan_profile": "full"
  }'
```

**Response (202 Accepted)**:
```json
{
  "id": "scan-job-123",
  "asset_id": "asset-001",
  "scanner_id": "scanner-nessus-01",
  "status": "queued",
  "scan_profile": "full",
  "started_at": "2024-11-07T16:35:00Z",
  "estimated_duration_minutes": 45
}
```

---

## Vulnerabilities Management

### GET /vulnerabilities/

List all vulnerabilities with advanced filtering.

**Method**: `GET`
**Endpoint**: `/api/v1/vulnerabilities/`
**Authentication**: Required (API Key or Bearer Token)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| limit | integer | No | 20 | Number of results (max 100) |
| offset | integer | No | 0 | Pagination offset |
| severity | string | No | - | Filter by severity: critical, high, medium, low, info |
| status | string | No | - | Filter by status: open, in_progress, resolved, false_positive |
| asset_id | string | No | - | Filter by asset |
| cvss_score_min | float | No | - | Filter by minimum CVSS score |
| cvss_score_max | float | No | - | Filter by maximum CVSS score |
| has_exploit | boolean | No | - | Filter vulnerabilities with known exploits |

**Request**:
```bash
curl -X GET "http://localhost:8001/api/v1/vulnerabilities/?severity=critical&status=open" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "count": 45,
  "results": [
    {
      "id": "vuln-001",
      "title": "Remote Code Execution in Web Server",
      "description": "A critical vulnerability allowing remote code execution...",
      "severity": "critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cve_id": "CVE-2024-1234",
      "affected_assets": [
        {
          "id": "asset-001",
          "name": "Production Server 1"
        }
      ],
      "status": "open",
      "detected_at": "2024-11-07T08:15:00Z",
      "updated_at": "2024-11-07T14:25:00Z",
      "remediation_deadline": "2024-11-14T08:15:00Z",
      "assigned_to": "security-team",
      "tags": ["rce", "critical", "exploitable"]
    }
  ],
  "pagination": {
    "limit": 20,
    "offset": 0,
    "total": 45
  }
}
```

### GET /vulnerabilities/{id}/

Retrieve detailed information about a specific vulnerability.

**Method**: `GET`
**Endpoint**: `/api/v1/vulnerabilities/{id}/`
**Authentication**: Required (API Key or Bearer Token)

**Request**:
```bash
curl -X GET http://localhost:8001/api/v1/vulnerabilities/vuln-001/ \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "id": "vuln-001",
  "title": "Remote Code Execution in Web Server",
  "description": "A critical vulnerability allowing remote code execution through improper input validation...",
  "severity": "critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cve_id": "CVE-2024-1234",
  "cwe_ids": ["CWE-78", "CWE-94"],
  "affected_assets": [
    {
      "id": "asset-001",
      "name": "Production Server 1",
      "status": "vulnerable"
    }
  ],
  "status": "open",
  "priority": "immediate",
  "detected_at": "2024-11-07T08:15:00Z",
  "remediation_deadline": "2024-11-14T08:15:00Z",
  "assigned_to": "security-team",
  "remediation_notes": "Patch available from vendor. Testing in non-prod required.",
  "has_exploit": true,
  "exploit_references": [
    "https://www.exploit-db.com/exploits/12345"
  ],
  "mitigation_steps": [
    "Apply security patch version 2.1.0 or later",
    "Enable WAF rules for input validation",
    "Monitor logs for exploitation attempts"
  ],
  "tags": ["rce", "critical", "exploitable"],
  "created_at": "2024-11-07T08:15:00Z",
  "updated_at": "2024-11-07T14:25:00Z"
}
```

### PATCH /vulnerabilities/{id}/

Update a vulnerability's status or assignment.

**Method**: `PATCH`
**Endpoint**: `/api/v1/vulnerabilities/{id}/`
**Authentication**: Required (API Key or Bearer Token)

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| status | string | No | New status: open, in_progress, resolved, false_positive |
| assigned_to | string | No | Team or user to assign |
| priority | string | No | Priority: immediate, high, medium, low |
| remediation_notes | string | No | Notes about remediation |

**Request**:
```bash
curl -X PATCH http://localhost:8001/api/v1/vulnerabilities/vuln-001/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "in_progress",
    "assigned_to": "dba-team",
    "remediation_notes": "Patch scheduled for this weekend"
  }'
```

**Response (200 OK)**:
```json
{
  "id": "vuln-001",
  "status": "in_progress",
  "assigned_to": "dba-team",
  "remediation_notes": "Patch scheduled for this weekend",
  "updated_at": "2024-11-07T17:30:00Z"
}
```

### POST /vulnerabilities/{id}/assign/

Assign a vulnerability to a team or user.

**Method**: `POST`
**Endpoint**: `/api/v1/vulnerabilities/{id}/assign/`
**Authentication**: Required (API Key or Bearer Token)

**Request Body**:
```json
{
  "assigned_to": "team-name",
  "priority": "high",
  "deadline_days": 7
}
```

**Request**:
```bash
curl -X POST http://localhost:8001/api/v1/vulnerabilities/vuln-001/assign/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "assigned_to": "infrastructure-team",
    "priority": "high",
    "deadline_days": 7
  }'
```

**Response (200 OK)**:
```json
{
  "id": "vuln-001",
  "assigned_to": "infrastructure-team",
  "priority": "high",
  "remediation_deadline": "2024-11-14T17:30:00Z",
  "status": "in_progress"
}
```

---

## Scanner Management

### GET /scanners/

List all configured security scanners.

**Method**: `GET`
**Endpoint**: `/api/v1/scanners/`
**Authentication**: Required (API Key or Bearer Token)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| limit | integer | No | Number of results (default: 20) |
| offset | integer | No | Pagination offset |
| status | string | No | Filter by status: active, inactive, error |
| scanner_type | string | No | Filter by type: vulnerability, configuration, network, web |

**Request**:
```bash
curl -X GET "http://localhost:8001/api/v1/scanners/?status=active" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "count": 5,
  "results": [
    {
      "id": "scanner-nessus-01",
      "name": "Nessus - Primary",
      "scanner_type": "vulnerability",
      "vendor": "Tenable",
      "version": "10.4.2",
      "status": "active",
      "last_scan": "2024-11-07T08:15:00Z",
      "total_scans": 156,
      "license_status": "active",
      "license_expires": "2024-12-31T23:59:59Z"
    },
    {
      "id": "scanner-burp-01",
      "name": "Burp Suite - Web",
      "scanner_type": "web",
      "vendor": "PortSwigger",
      "version": "2024.2.1",
      "status": "active",
      "last_scan": "2024-11-06T15:30:00Z",
      "total_scans": 42
    }
  ]
}
```

### POST /scanners/

Register a new security scanner.

**Method**: `POST`
**Endpoint**: `/api/v1/scanners/`
**Authentication**: Required (API Key or Bearer Token - admin only)

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Scanner name |
| scanner_type | string | Yes | Type: vulnerability, configuration, network, web |
| vendor | string | Yes | Scanner vendor |
| api_url | string | Yes | Scanner API endpoint |
| api_key | string | Yes | API authentication key |
| description | string | No | Scanner description |

**Request**:
```bash
curl -X POST http://localhost:8001/api/v1/scanners/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Qualys - New Instance",
    "scanner_type": "vulnerability",
    "vendor": "Qualys",
    "api_url": "https://qualys.example.com/api",
    "api_key": "encrypted-api-key-here"
  }'
```

**Response (201 Created)**:
```json
{
  "id": "scanner-qualys-01",
  "name": "Qualys - New Instance",
  "scanner_type": "vulnerability",
  "vendor": "Qualys",
  "status": "active",
  "created_at": "2024-11-07T18:00:00Z"
}
```

### POST /scanners/{id}/test/

Test connectivity and authentication with a scanner.

**Method**: `POST`
**Endpoint**: `/api/v1/scanners/{id}/test/`
**Authentication**: Required (API Key or Bearer Token)

**Request**:
```bash
curl -X POST http://localhost:8001/api/v1/scanners/scanner-nessus-01/test/ \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "scanner_id": "scanner-nessus-01",
  "status": "connected",
  "version": "10.4.2",
  "message": "Successfully connected to Nessus scanner",
  "test_time": "2024-11-07T18:05:30Z"
}
```

---

## Integration Management

### GET /integrations/

List all configured integrations with external systems.

**Method**: `GET`
**Endpoint**: `/api/v1/integrations/`
**Authentication**: Required (API Key or Bearer Token)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| limit | integer | No | Number of results (default: 20) |
| offset | integer | No | Pagination offset |
| status | string | No | Filter by status: active, inactive, error |
| integration_type | string | No | Filter by type: ticketing, siem, notification, vulnerability |

**Request**:
```bash
curl -X GET "http://localhost:8001/api/v1/integrations/?status=active" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "count": 8,
  "results": [
    {
      "id": "int-jira-01",
      "name": "JIRA - Incident Management",
      "integration_type": "ticketing",
      "platform": "Atlassian JIRA",
      "status": "active",
      "last_sync": "2024-11-07T17:00:00Z",
      "synced_items": 1234,
      "created_at": "2024-06-15T10:30:00Z"
    },
    {
      "id": "int-slack-01",
      "name": "Slack - Alerts",
      "integration_type": "notification",
      "platform": "Slack",
      "status": "active",
      "last_sync": "2024-11-07T17:30:00Z",
      "synced_items": 567
    }
  ]
}
```

### POST /integrations/

Create a new integration with an external system.

**Method**: `POST`
**Endpoint**: `/api/v1/integrations/`
**Authentication**: Required (API Key or Bearer Token)

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Integration name |
| integration_type | string | Yes | Type: ticketing, siem, notification, vulnerability |
| platform | string | Yes | Platform name (JIRA, Slack, etc.) |
| api_url | string | Yes | Platform API endpoint |
| credentials | object | Yes | Authentication credentials |
| config | object | No | Integration configuration |

**Request**:
```bash
curl -X POST http://localhost:8001/api/v1/integrations/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PagerDuty - On-Call",
    "integration_type": "notification",
    "platform": "PagerDuty",
    "api_url": "https://api.pagerduty.com",
    "credentials": {
      "api_key": "encrypted-pagerduty-key"
    }
  }'
```

**Response (201 Created)**:
```json
{
  "id": "int-pagerduty-01",
  "name": "PagerDuty - On-Call",
  "integration_type": "notification",
  "platform": "PagerDuty",
  "status": "active",
  "created_at": "2024-11-07T18:10:00Z"
}
```

### POST /integrations/{id}/test/

Test connectivity and authentication with an integration.

**Method**: `POST`
**Endpoint**: `/api/v1/integrations/{id}/test/`
**Authentication**: Required (API Key or Bearer Token)

**Request**:
```bash
curl -X POST http://localhost:8001/api/v1/integrations/int-jira-01/test/ \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "integration_id": "int-jira-01",
  "status": "connected",
  "platform": "JIRA",
  "message": "Successfully connected to JIRA instance",
  "projects_available": 15,
  "test_time": "2024-11-07T18:15:30Z"
}
```

---

## Remediation & Workflows

### GET /remediation-tickets/

List all remediation tickets and workflows.

**Method**: `GET`
**Endpoint**: `/api/v1/remediation-tickets/`
**Authentication**: Required (API Key or Bearer Token)
**Rate Limit**: 100 requests/minute

**Query Parameters**:

| Name | Type | Required | Description |
|------|------|----------|-------------|
| limit | integer | No | Number of results (default: 20) |
| offset | integer | No | Pagination offset |
| status | string | No | Filter by status: open, in_progress, resolved, rejected |
| priority | string | No | Filter by priority: immediate, high, medium, low |
| assigned_to | string | No | Filter by assignee |

**Request**:
```bash
curl -X GET "http://localhost:8001/api/v1/remediation-tickets/?status=in_progress" \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:
```json
{
  "count": 23,
  "results": [
    {
      "id": "ticket-001",
      "ticket_number": "REM-2024-001",
      "title": "Patch SQL Server Database",
      "description": "Apply security patches for CVE-2024-1234",
      "vulnerability_id": "vuln-001",
      "status": "in_progress",
      "priority": "high",
      "assigned_to": "dba-team",
      "created_at": "2024-11-07T08:15:00Z",
      "deadline": "2024-11-14T23:59:59Z",
      "completed_at": null,
      "progress": 45
    }
  ]
}
```

### POST /remediation-tickets/

Create a new remediation ticket.

**Method**: `POST`
**Endpoint**: `/api/v1/remediation-tickets/`
**Authentication**: Required (API Key or Bearer Token)

**Request Body**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | Ticket title |
| description | string | Yes | Detailed description |
| vulnerability_id | string | No | Associated vulnerability |
| priority | string | Yes | Priority: immediate, high, medium, low |
| assigned_to | string | Yes | Team or user to assign |
| deadline_days | integer | No | Days until deadline |

**Request**:
```bash
curl -X POST http://localhost:8001/api/v1/remediation-tickets/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Update Apache Web Server",
    "description": "Apply security patches for CVE-2024-5678",
    "vulnerability_id": "vuln-002",
    "priority": "high",
    "assigned_to": "infrastructure-team",
    "deadline_days": 7
  }'
```

**Response (201 Created)**:
```json
{
  "id": "ticket-456",
  "ticket_number": "REM-2024-024",
  "title": "Update Apache Web Server",
  "status": "open",
  "priority": "high",
  "assigned_to": "infrastructure-team",
  "deadline": "2024-11-14T18:20:00Z",
  "created_at": "2024-11-07T18:20:00Z"
}
```

---

## Error Codes

| Code | Status | Description |
|------|--------|-------------|
| 400 | Bad Request | Invalid request parameters or body |
| 401 | Unauthorized | Missing or invalid API key/token |
| 403 | Forbidden | Authenticated but not authorized for this action |
| 404 | Not Found | Asset, vulnerability, or resource not found |
| 409 | Conflict | Resource already exists or conflict with current state |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error (contact support) |
| 503 | Service Unavailable | Service temporarily unavailable |

**Error Response Format**:
```json
{
  "error": "Bad Request",
  "message": "Asset ID is required",
  "status": "error",
  "code": 400
}
```

---

## Rate Limiting

Guardian Service enforces rate limits to ensure fair use:

- **Anonymous users**: 100 requests/hour
- **Authenticated users (Bearer Token)**: 1,000 requests/hour
- **API Key users**: 5,000 requests/hour

Rate limit information is returned in response headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1730963100
X-RateLimit-Retry-After: 3600
```

When rate limit is exceeded (429 error):
```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Try again after 3600 seconds",
  "status": "error",
  "retry_after": 3600
}
```

---

## Examples

### Complete Vulnerability Management Workflow

```bash
# 1. Get all critical vulnerabilities
CRITICAL_VULNS=$(curl -s -X GET "http://localhost:8001/api/v1/vulnerabilities/?severity=critical&status=open" \
  -H "X-API-Key: your-api-key" | jq -r '.results[0].id')

# 2. Get vulnerability details
curl -s -X GET http://localhost:8001/api/v1/vulnerabilities/$CRITICAL_VULNS/ \
  -H "X-API-Key: your-api-key" | jq '.title, .cvss_score, .affected_assets'

# 3. Assign to team
curl -X POST http://localhost:8001/api/v1/vulnerabilities/$CRITICAL_VULNS/assign/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "assigned_to": "security-team",
    "priority": "immediate",
    "deadline_days": 3
  }'

# 4. Create remediation ticket
curl -X POST http://localhost:8001/api/v1/remediation-tickets/ \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Remediate critical vulnerability",
    "description": "Apply patches for identified vulnerability",
    "vulnerability_id": "'$CRITICAL_VULNS'",
    "priority": "immediate",
    "assigned_to": "security-team",
    "deadline_days": 3
  }'

# 5. Monitor ticket progress
curl -s -X GET "http://localhost:8001/api/v1/remediation-tickets/?assigned_to=security-team" \
  -H "X-API-Key: your-api-key" | jq '.results[] | {id, status, progress}'
```

### Automated Asset Scanning

```bash
# 1. Get all active assets
ASSETS=$(curl -s -X GET "http://localhost:8001/api/v1/assets/?status=active&limit=50" \
  -H "X-API-Key: your-api-key" | jq -r '.results[].id')

# 2. Get active Nessus scanner
SCANNER=$(curl -s -X GET "http://localhost:8001/api/v1/scanners/?status=active&scanner_type=vulnerability" \
  -H "X-API-Key: your-api-key" | jq -r '.results[0].id')

# 3. Start scanning each asset
for asset in $ASSETS; do
  echo "Starting scan for $asset"
  curl -X POST http://localhost:8001/api/v1/assets/$asset/scan/ \
    -H "X-API-Key: your-api-key" \
    -H "Content-Type: application/json" \
    -d "{
      \"scanner_id\": \"$SCANNER\",
      \"scan_profile\": \"full\"
    }"
  sleep 5
done
```

---

## Related Documentation

- [Security Policy](../../security/policy.md) - Authentication and authorization requirements
- [API Reference Hub](../api-reference.html) - All service endpoints
- [Integration Guide](../../guides/integrations.md) - Integration setup instructions
- [Quickstart Guide](../../guides/quickstart.md) - Getting started with API

---

**Last Updated**: November 7, 2024
**API Version**: v1
**Status**: Stable
**Base Port**: 8001
