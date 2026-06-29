# Guardian Service - API Quick Reference Guide

## Location
`/Users/fab/GitHub/wildbox/open-security-guardian/`

## Quick Start

### Base URL
```
http://localhost:8000/api/v1/
```

### Authentication

**API Key (Recommended)**
```bash
curl -H "X-API-Key: your-api-key-here" http://localhost:8000/api/v1/assets/
```

**Bearer Token**
```bash
curl -H "Authorization: Bearer your-token" http://localhost:8000/api/v1/assets/
```

### Documentation
- **Swagger UI**: http://localhost:8000/docs/
- **ReDoc**: http://localhost:8000/redoc/
- **OpenAPI Schema**: http://localhost:8000/api/schema/
- **Health Check**: http://localhost:8000/health/

---

## Core Endpoints by Category

### 1. Assets (`/api/v1/assets/`)
```
GET    /assets/                          List all assets
POST   /assets/                          Create asset
GET    /assets/{id}/                     Get asset details
PUT    /assets/{id}/                     Update asset
DELETE /assets/{id}/                     Delete asset
POST   /assets/{id}/scan/                Trigger scan
POST   /assets/discover/                 Discover assets
GET    /assets/statistics/               Get statistics
```

### 2. Vulnerabilities (`/api/v1/vulnerabilities/`)
```
GET    /                                 List vulnerabilities
POST   /                                 Create vulnerability
GET    /{id}/                            Get vulnerability
PUT    /{id}/                            Update vulnerability
DELETE /{id}/                            Delete vulnerability
POST   /{id}/assign/                     Assign to user
POST   /{id}/close/                      Close vulnerability
GET    /stats/                           Get statistics
GET    /trends/                          Get trends
POST   /bulk_action/                     Bulk operations
```

### 3. Scanners (`/api/v1/scanners/`)
```
GET    /scanners/                        List scanners
POST   /scanners/                        Create scanner
POST   /scanners/{id}/test_connection/   Test connection
GET    /scans/                           List scans
POST   /scans/{id}/start/                Start scan
POST   /scans/{id}/stop/                 Stop scan
GET    /scans/{id}/results/              Get results
```

### 4. Remediation (`/api/v1/remediation/`)
```
GET    /tickets/                         List tickets
POST   /tickets/                         Create ticket
POST   /tickets/{id}/assign/             Assign ticket
POST   /workflows/                       Create workflow
POST   /workflows/{id}/start/            Start workflow
GET    /workflows/{id}/progress/         Get progress
```

### 5. Compliance (`/api/v1/compliance/`)
```
GET    /frameworks/                      List frameworks
GET    /assessments/                     List assessments
POST   /assessments/                     Create assessment
GET    /assessments/{id}/summary/        Get compliance summary
POST   /assessments/{id}/evidence/       Submit evidence
GET    /metrics/dashboard/               Dashboard metrics
```

### 6. Reports (`/api/v1/reports/`)
```
GET    /templates/                       List templates
POST   /templates/{id}/generate/         Generate report
GET    /reports/{id}/download/           Download report
GET    /dashboards/                      List dashboards
GET    /dashboards/{id}/data/            Get dashboard data
```

### 7. Integrations (`/api/v1/integrations/`)
```
GET    /systems/                         List integrations
POST   /systems/{id}/test_connection/    Test connection
POST   /webhooks/                        Create webhook
POST   /notifications/                   Create channel
```

---

## Common Query Parameters

### Pagination
```
?page=1&page_size=50
```

### Filtering
```
?severity=critical&status=open
?asset_type=server&environment=production
```

### Search
```
?search=web-server
?search=CVE-2024
```

### Ordering
```
?ordering=-created_at
?ordering=name,severity
```

### Date Range
```
?discovered_after=2025-06-01&discovered_before=2025-06-30
```

---

## Response Format

### Success (List)
```json
{
  "count": 100,
  "next": "http://localhost:8000/api/v1/assets/?page=2",
  "previous": null,
  "results": [
    {
      "id": "uuid",
      "name": "asset-name",
      "asset_type": "server",
      ...
    }
  ]
}
```

### Success (Create/Update)
```json
{
  "id": "uuid",
  "name": "asset-name",
  "status": "created",
  ...
}
```

### Error
```json
{
  "error": "Validation Error",
  "message": "Invalid data provided",
  "details": {
    "field": ["Error message"]
  }
}
```

---

## Authentication & Authorization

### Methods
- **API Key** (Header: `X-API-Key`)
- **JWT Token** (Header: `Authorization: Bearer`)
- **Session** (Django standard)

### Permissions
- `IsAuthenticated` - Most endpoints
- `IsAssetManager` - Asset operations
- `IsComplianceManager` - Compliance operations
- `IsSecurityAnalyst` - Analysis operations
- `IsVulnerabilityManager` - Vulnerability operations

---

## Rate Limits

| User Type | Limit | Response Headers |
|-----------|-------|-----------------|
| Anonymous | 100/hour | X-RateLimit-* |
| Authenticated | 1000/hour | X-RateLimit-* |
| API Key | 5000/hour | X-RateLimit-* |

---

## HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | OK (GET, PUT, PATCH) |
| 201 | Created (POST) |
| 202 | Accepted (Async) |
| 204 | No Content (DELETE) |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Rate Limited |
| 500 | Server Error |

---

## Popular Queries

### Get all critical vulnerabilities
```bash
curl -H "X-API-Key: your-key" \
  'http://localhost:8000/api/v1/vulnerabilities/?severity=critical&status=open'
```

### Get asset by hostname
```bash
curl -H "X-API-Key: your-key" \
  'http://localhost:8000/api/v1/assets/?search=web-server'
```

### Get compliance summary
```bash
curl -H "X-API-Key: your-key" \
  'http://localhost:8000/api/v1/compliance/assessments/{id}/summary/'
```

### Generate report
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "pdf",
    "parameters": {"date_range": {"start": "2025-06-01"}}
  }' \
  'http://localhost:8000/api/v1/reports/templates/{id}/generate/'
```

### Run vulnerability bulk operation
```bash
curl -X POST -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_ids": [1,2,3],
    "action": "assign",
    "assigned_to": 1
  }' \
  'http://localhost:8000/api/v1/vulnerabilities/bulk_action/'
```

---

## File Structure

```
open-security-guardian/
├── guardian/
│   ├── urls.py              # Main URL routing
│   ├── settings.py          # Django & API config
│   ├── wsgi.py
│   └── asgi.py
├── apps/
│   ├── core/
│   │   ├── authentication.py
│   │   ├── permissions.py
│   │   └── middleware.py
│   ├── assets/
│   │   ├── views.py
│   │   ├── urls.py
│   │   ├── models.py
│   │   └── serializers.py
│   ├── vulnerabilities/
│   ├── scanners/
│   ├── remediation/
│   ├── compliance/
│   ├── reporting/
│   └── integrations/
├── requirements.txt
├── manage.py
└── docker-compose.yml
```

---

## Key Technologies

- **Framework**: Django 4.x
- **API**: Django REST Framework (DRF)
- **Documentation**: drf-spectacular (OpenAPI/Swagger)
- **Database**: PostgreSQL (via dj_database_url)
- **Cache**: Redis (django-redis)
- **Async**: Celery + Redis
- **Monitoring**: Prometheus, Sentry (optional)
- **Filtering**: django-filter
- **CORS**: django-cors-headers

---

## Environment Variables

```bash
# Core
SECRET_KEY=your-secret-key
DEBUG=false
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/guardian

# Cache
REDIS_URL=redis://localhost:6379/0

# API
API_RATE_LIMIT=1000/hour

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Features
PROMETHEUS_ENABLED=true
```

---

## Management Commands

```bash
# Setup
python manage.py migrate
python manage.py createsuperuser
python manage.py setup_guardian

# Operations
python manage.py generate_compliance_report
python manage.py import_vulnerabilities
python manage.py maintenance

# Development
python manage.py runserver
python manage.py makemigrations
python manage.py migrate
```

---

## Development Server

```bash
# Start Django development server
python manage.py runserver 0.0.0.0:8000

# Start Celery worker (async tasks)
celery -A guardian worker -l info

# Start Celery Beat (scheduled tasks)
celery -A guardian beat -l info

# Access
- API: http://localhost:8000/api/v1/
- Admin: http://localhost:8000/admin/
- Docs: http://localhost:8000/docs/
```

---

## Webhook Events

Subscribe to these events:
- `vulnerability.created`
- `vulnerability.updated`
- `asset.created`
- `scan.completed`
- `compliance.assessment.completed`
- `remediation.ticket.created`

Register webhook:
```bash
POST /api/v1/integrations/webhooks/
{
  "url": "https://your-system.com/webhook",
  "events": ["vulnerability.created"],
  "secret": "webhook-secret",
  "is_active": true
}
```

---

## Health Monitoring

### Health Check
```bash
curl http://localhost:8000/health/
```

### Prometheus Metrics
```bash
curl http://localhost:8000/metrics/
```

---

## Support Resources

- **Full API Docs**: `/Users/fab/GitHub/wildbox/docs/GUARDIAN_API_ENDPOINTS.md`
- **Summary**: `/Users/fab/GitHub/wildbox/docs/GUARDIAN_ENDPOINTS_SUMMARY.txt`
- **API Documentation**: `/Users/fab/GitHub/wildbox/docs/guardian/API_DOCS.md`
- **Getting Started**: `/Users/fab/GitHub/wildbox/docs/guardian/GETTING_STARTED.md`
- **README**: `/Users/fab/GitHub/wildbox/docs/guardian/README.md`

---

## Common Tasks

### Create an Asset
```bash
POST /api/v1/assets/
{
  "hostname": "web-server-01",
  "ip_address": "192.168.1.100",
  "asset_type": "server",
  "environment": "production",
  "criticality": "high"
}
```

### Create a Vulnerability
```bash
POST /api/v1/vulnerabilities/
{
  "title": "SQL Injection",
  "severity": "critical",
  "cve_id": "CVE-2024-1234",
  "asset": "uuid",
  "cvss_score": 9.8
}
```

### Create Compliance Assessment
```bash
POST /api/v1/compliance/assessments/
{
  "name": "PCI-DSS Assessment Q2 2025",
  "framework": "uuid",
  "assessment_type": "internal_audit",
  "due_date": "2025-07-31T23:59:59Z"
}
```

### Start a Scan
```bash
POST /api/v1/scanners/scans/{id}/start/
{}
```

---

Generated Documentation Date: 2025-11-07
Guardian Service Version: 1.0.0
