# Open Security Guardian API Documentation

## Overview

The Open Security Guardian provides a comprehensive REST API for vulnerability management, compliance tracking, asset inventory, and security reporting. This document outlines the available endpoints, authentication methods, and usage examples.

## Base URL

```
http://localhost:8000/api/v1/
```

## Authentication

The API supports multiple authentication methods:

### 1. API Key Authentication

Include the API key in the request headers:

```http
X-API-Key: your-api-key-here
```

### 2. JWT Token Authentication

First, obtain a token:

```http
POST /api/v1/auth/token/
Content-Type: application/json

{
    "username": "your-username",
    "password": "your-password"
}
```

Then include the token in subsequent requests:

```http
Authorization: Bearer your-jwt-token-here
```

### 3. Session Authentication

Standard Django session authentication for web interface.

## API Endpoints

### Assets Management

#### List Assets
```http
GET /api/v1/assets/
```

Query parameters:
- `asset_type`: Filter by asset type
- `environment`: Filter by environment
- `criticality`: Filter by criticality level
- `is_active`: Filter by active status
- `search`: Search in hostname, name, or description
- `page`: Page number for pagination
- `page_size`: Number of items per page (max 100)

Example response:
```json
{
    "count": 250,
    "next": "http://localhost:8000/api/v1/assets/?page=2",
    "previous": null,
    "results": [
        {
            "id": "uuid-here",
            "hostname": "web-server-01",
            "ip_address": "192.168.1.100",
            "asset_type": "server",
            "environment": "production",
            "criticality": "high",
            "is_active": true,
            "last_seen": "2025-06-25T10:30:00Z",
            "vulnerability_count": 15,
            "created_at": "2025-06-01T08:00:00Z",
            "updated_at": "2025-06-25T10:30:00Z"
        }
    ]
}
```

#### Create Asset
```http
POST /api/v1/assets/
Content-Type: application/json

{
    "hostname": "new-server-01",
    "ip_address": "192.168.1.101",
    "asset_type": "server",
    "environment": "production",
    "criticality": "medium",
    "description": "New production web server",
    "owner": "DevOps Team",
    "location": "Data Center A"
}
```

#### Get Asset Details
```http
GET /api/v1/assets/{id}/
```

#### Update Asset
```http
PUT /api/v1/assets/{id}/
Content-Type: application/json

{
    "criticality": "high",
    "description": "Updated description"
}
```

#### Asset Vulnerabilities
```http
GET /api/v1/assets/{id}/vulnerabilities/
```

#### Asset Scan History
```http
GET /api/v1/assets/{id}/scan_history/
```

### Vulnerability Management

#### List Vulnerabilities
```http
GET /api/v1/vulnerabilities/
```

Query parameters:
- `severity`: Filter by severity (critical, high, medium, low)
- `status`: Filter by status (open, in_progress, resolved, false_positive)
- `asset`: Filter by asset ID
- `cve_id`: Filter by CVE ID
- `discovered_after`: Filter by discovery date (ISO format)
- `search`: Search in title, description, or CVE ID

Example response:
```json
{
    "count": 1250,
    "results": [
        {
            "id": "uuid-here",
            "title": "Apache HTTP Server Vulnerability",
            "description": "Buffer overflow vulnerability in Apache HTTP Server",
            "severity": "critical",
            "cvss_score": 9.8,
            "cve_id": "CVE-2024-1234",
            "status": "open",
            "asset": {
                "id": "asset-uuid",
                "hostname": "web-server-01"
            },
            "port": 80,
            "protocol": "tcp",
            "discovered_at": "2025-06-25T09:15:00Z",
            "risk_score": 9.2,
            "exploitability": "high",
            "days_open": 5
        }
    ]
}
```

#### Create Vulnerability
```http
POST /api/v1/vulnerabilities/
Content-Type: application/json

{
    "title": "SQL Injection Vulnerability",
    "description": "SQL injection vulnerability in user input form",
    "severity": "high",
    "cvss_score": 8.5,
    "cve_id": "CVE-2024-5678",
    "asset": "asset-uuid-here",
    "port": 443,
    "protocol": "tcp",
    "proof_of_concept": "Detailed PoC here"
}
```

#### Update Vulnerability Status
```http
PATCH /api/v1/vulnerabilities/{id}/
Content-Type: application/json

{
    "status": "in_progress",
    "assigned_to": "security-team@example.com",
    "notes": "Working on patch deployment"
}
```

#### Vulnerability Statistics
```http
GET /api/v1/vulnerabilities/stats/
```

Response:
```json
{
    "total_count": 1250,
    "by_severity": {
        "critical": 45,
        "high": 180,
        "medium": 650,
        "low": 375
    },
    "by_status": {
        "open": 890,
        "in_progress": 280,
        "resolved": 80
    },
    "trending": {
        "daily_new": 12,
        "weekly_resolved": 35
    }
}
```

### Scanner Management

#### List Scanners
```http
GET /api/v1/scanners/
```

#### Create Scanner Configuration
```http
POST /api/v1/scanners/
Content-Type: application/json

{
    "name": "Production Nessus Scanner",
    "scanner_type": "nessus",
    "hostname": "nessus.example.com",
    "port": 8834,
    "credentials": {
        "username": "scanner_user",
        "password": "secure_password"
    },
    "verify_ssl": true,
    "is_active": true
}
```

#### Run Scan
```http
POST /api/v1/scanners/{id}/scan/
Content-Type: application/json

{
    "targets": ["192.168.1.0/24"],
    "scan_profile": "full_scan",
    "schedule": "immediate"
}
```

#### Scan Results
```http
GET /api/v1/scanners/scans/{scan_id}/results/
```

### Compliance Management

#### List Compliance Frameworks
```http
GET /api/v1/compliance/frameworks/
```

#### Framework Controls
```http
GET /api/v1/compliance/frameworks/{id}/controls/
```

#### List Assessments
```http
GET /api/v1/compliance/assessments/
```

#### Create Assessment
```http
POST /api/v1/compliance/assessments/
Content-Type: application/json

{
    "name": "Q2 2025 PCI-DSS Assessment",
    "framework": "framework-uuid",
    "assessment_type": "internal_audit",
    "scope_description": "All production card processing systems",
    "due_date": "2025-07-31T23:59:59Z"
}
```

#### Assessment Summary
```http
GET /api/v1/compliance/assessments/{id}/summary/
```

Response:
```json
{
    "total_controls": 285,
    "compliant": 220,
    "non_compliant": 35,
    "partially_compliant": 25,
    "not_tested": 5,
    "compliance_percentage": 77.19,
    "high_risk": 8,
    "medium_risk": 15,
    "low_risk": 12
}
```

#### Submit Evidence
```http
POST /api/v1/compliance/evidence/
Content-Type: multipart/form-data

assessment: assessment-uuid
control: control-uuid
title: Configuration Screenshot
evidence_type: screenshot
file: @/path/to/evidence.png
```

### Remediation Management

#### List Remediation Workflows
```http
GET /api/v1/remediation/workflows/
```

#### Create Ticket
```http
POST /api/v1/remediation/tickets/
Content-Type: application/json

{
    "vulnerability": "vuln-uuid",
    "workflow": "workflow-uuid",
    "title": "Fix Apache HTTP Server Vulnerability",
    "description": "Apply security patch for CVE-2024-1234",
    "priority": "critical",
    "due_date": "2025-06-28T23:59:59Z"
}
```

#### Update Ticket Status
```http
PATCH /api/v1/remediation/tickets/{id}/
Content-Type: application/json

{
    "status": "in_progress",
    "assigned_to": "devops-team@example.com"
}
```

#### Add Comment
```http
POST /api/v1/remediation/tickets/{id}/comments/
Content-Type: application/json

{
    "comment": "Patch has been tested in staging environment",
    "is_internal": false
}
```

### Reporting & Analytics

#### List Report Templates
```http
GET /api/v1/reports/templates/
```

#### Generate Report
```http
POST /api/v1/reports/templates/{id}/generate/
Content-Type: application/json

{
    "format": "pdf",
    "parameters": {
        "date_range": {
            "start": "2025-06-01",
            "end": "2025-06-30"
        }
    },
    "filters": {
        "severity": ["critical", "high"],
        "environment": ["production"]
    }
}
```

#### Download Report
```http
GET /api/v1/reports/reports/{id}/download/
```

#### Dashboard Data
```http
GET /api/v1/reports/dashboards/{id}/data/
```

### Integration Management

#### List External Systems
```http
GET /api/v1/integrations/systems/
```

#### Test Integration
```http
POST /api/v1/integrations/systems/{id}/test/
```

#### Sync Data
```http
POST /api/v1/integrations/systems/{id}/sync/
Content-Type: application/json

{
    "sync_type": "vulnerabilities",
    "full_sync": false
}
```

## Response Formats

### Success Response
All successful responses return JSON with appropriate HTTP status codes:
- `200 OK`: Successful GET, PUT, PATCH
- `201 Created`: Successful POST
- `204 No Content`: Successful DELETE

### Error Response
Error responses include details about the failure:

```json
{
    "error": "Validation Error",
    "message": "The provided data is invalid",
    "details": {
        "field_name": ["This field is required."]
    },
    "code": "VALIDATION_ERROR"
}
```

### Pagination
List endpoints support pagination:

```json
{
    "count": 1000,
    "next": "http://localhost:8000/api/v1/assets/?page=3",
    "previous": "http://localhost:8000/api/v1/assets/?page=1",
    "results": []
}
```

## Rate Limiting

The API implements rate limiting:
- Anonymous users: 100 requests/hour
- Authenticated users: 1000 requests/hour
- API key users: 5000 requests/hour

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1625097600
```

## Filtering and Searching

Most list endpoints support filtering and searching:

### Date Filters
```http
GET /api/v1/vulnerabilities/?discovered_after=2025-06-01&discovered_before=2025-06-30
```

### Multiple Value Filters
```http
GET /api/v1/vulnerabilities/?severity=critical,high&status=open
```

### Search
```http
GET /api/v1/assets/?search=web-server
```

### Ordering
```http
GET /api/v1/vulnerabilities/?ordering=-cvss_score,discovered_at
```

## Webhooks

Configure webhooks to receive real-time notifications:

### Register Webhook
```http
POST /api/v1/integrations/webhooks/
Content-Type: application/json

{
    "url": "https://your-system.com/webhook",
    "events": ["vulnerability.created", "compliance.assessment.completed"],
    "secret": "your-webhook-secret",
    "is_active": true
}
```

### Webhook Events
- `vulnerability.created`
- `vulnerability.updated`
- `asset.created`
- `scan.completed`
- `compliance.assessment.completed`
- `remediation.ticket.created`

## SDK and Client Libraries

Official client libraries are available:
- Python: `pip install guardian-api-client`
- JavaScript: `npm install @wildbox/guardian-client`
- Go: `go get github.com/wildbox/guardian-go-client`

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid data provided |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Validation error |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |

## Best Practices

1. **Use HTTPS**: Always use HTTPS in production
2. **Rate Limiting**: Implement client-side rate limiting
3. **Pagination**: Use pagination for large datasets
4. **Caching**: Implement appropriate caching strategies
5. **Error Handling**: Handle all error responses gracefully
6. **Versioning**: Always specify API version in requests
7. **Authentication**: Store API keys and tokens securely
8. **Monitoring**: Monitor API usage and response times

## Support

For API support and questions:
- Documentation: https://docs.wildbox.security/guardian/api
- GitHub Issues: https://github.com/wildbox/open-security-guardian/issues
- Email: support@wildbox.security
