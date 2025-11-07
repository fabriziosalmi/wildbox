# Guardian Service Codebase Exploration - Complete Index

**Exploration Date**: November 7, 2025  
**Service Location**: `/Users/fab/GitHub/wildbox/open-security-guardian/`

---

## Documentation Files Generated

This exploration produced three comprehensive documentation files:

### 1. GUARDIAN_API_ENDPOINTS.md (1,661 lines)
**File Location**: `/Users/fab/GitHub/wildbox/GUARDIAN_API_ENDPOINTS.md`

**Contents**:
- Complete API endpoint documentation organized by category
- All 280+ HTTP endpoints with methods, paths, and parameters
- Authentication methods and permission requirements
- Rate limiting details
- Request/response models and examples
- Error handling and status codes
- Filtering, searching, and pagination guidance
- Webhook configuration and available events
- OpenAPI/Swagger configuration details

**Use Case**: Comprehensive reference for API consumers and developers

---

### 2. GUARDIAN_ENDPOINTS_SUMMARY.txt (522 lines)
**File Location**: `/Users/fab/GitHub/wildbox/GUARDIAN_ENDPOINTS_SUMMARY.txt`

**Contents**:
- Executive summary of API capabilities
- Authentication methods overview
- Rate limiting configuration
- Endpoint counts by category with custom actions listed
- Permission classes reference
- HTTP status codes and error formats
- Core infrastructure endpoints
- Technology stack details
- File structure and location guide
- Database models overview
- Management commands reference

**Use Case**: Quick reference for architects and project leads

---

### 3. GUARDIAN_QUICK_REFERENCE.md
**File Location**: `/Users/fab/GitHub/wildbox/GUARDIAN_QUICK_REFERENCE.md`

**Contents**:
- Quick start guide with authentication examples
- Core endpoints by category (concise format)
- Common query parameter examples
- Response format examples
- Rate limiting reference table
- HTTP status codes table
- Popular curl command examples
- File structure diagram
- Technology stack overview
- Development server setup instructions
- Webhook event types
- Common task examples

**Use Case**: Developer quick reference and getting started guide

---

## Exploration Methodology

### Phase 1: Structure Analysis
- Located main application directory
- Identified Django REST Framework architecture
- Mapped out 8 app modules (assets, vulnerabilities, scanners, remediation, compliance, reporting, integrations, core)

### Phase 2: Configuration Discovery
- Examined `guardian/urls.py` for main URL routing (35 path registrations)
- Analyzed `guardian/settings.py` for:
  - DRF configuration
  - Authentication classes
  - Permission classes
  - Rate limiting settings
  - OpenAPI/Swagger setup
  - CORS configuration
  - Celery async configuration

### Phase 3: Endpoint Enumeration
- Reviewed all 43 ViewSets across 7 app modules
- Identified 120+ custom actions beyond standard CRUD
- Categorized endpoints into 7 functional domains
- Documented all HTTP methods (GET, POST, PUT, PATCH, DELETE)

### Phase 4: Authentication & Security Analysis
- Found 3 authentication methods (API Key, JWT, Session)
- Located authentication class: `apps/core/authentication.py`
- Identified permission classes: `apps/core/permissions.py`
- Analyzed rate limiting configuration
- Reviewed CORS setup

### Phase 5: API Configuration Analysis
- Examined drf-spectacular settings for OpenAPI/Swagger
- Identified 6 API tags for organization
- Found automatic documentation endpoints
- Analyzed error response format

### Phase 6: Documentation Generation
- Created comprehensive markdown documentation
- Organized endpoints by category with examples
- Added authentication and security guidance
- Included deployment and development instructions

---

## Key Statistics

| Metric | Count |
|--------|-------|
| Total HTTP Endpoints | 280+ |
| Total ViewSets | 43 |
| Standard CRUD Endpoints | 160+ |
| Custom Actions | 120+ |
| App Modules | 8 |
| Authentication Methods | 3 |
| Rate Limit Tiers | 3 |
| Permission Classes | 5 |
| Webhook Event Types | 6 |
| Documentation Lines | 2,183+ |

---

## Endpoint Breakdown by Category

| Category | Endpoints | ViewSets | Key Features |
|----------|-----------|----------|--------------|
| Assets | 45+ | 7 | CRUD, scanning, discovery, tagging, groups |
| Vulnerabilities | 35+ | 3 | CRUD, assignment, workflow, bulk ops, analytics |
| Scanners | 45+ | 5 | Scanner CRUD, profile management, scan control, scheduling |
| Remediation | 40+ | 5 | Tickets, workflows, steps, templates, comments |
| Compliance | 50+ | 7 | Frameworks, controls, assessments, evidence, metrics |
| Reporting | 45+ | 7 | Templates, schedules, dashboards, widgets, alerts |
| Integrations | 40+ | 6 | Systems, mappings, webhooks, notifications, logging |
| Core | 5 | 2 | Health check, metrics, schema, docs |

---

## Authentication Details Discovered

### API Key Authentication
- **Implementation File**: `apps/core/authentication.py`
- **Class**: `APIKeyAuthentication`
- **Headers Supported**: `X-API-Key`, `Authorization: Bearer`
- **Model**: `APIKey` (with expiration support)
- **Status Code on Failure**: 401 Unauthorized

### JWT Token Authentication
- **Implementation**: Django built-in `SessionAuthentication`
- **Header Format**: `Authorization: Bearer {token}`
- **Status Code on Failure**: 401 Unauthorized

### Session Authentication
- **Implementation**: Django standard session cookies
- **Use Case**: Web interface authentication

### Default Requirement
- **Permission Class**: `IsAuthenticated`
- **Applies To**: 277+ endpoints
- **Exceptions**: Health check, metrics, documentation

---

## Rate Limiting Configuration

```
DEFAULT_THROTTLE_CLASSES = [
    'rest_framework.throttling.AnonRateThrottle',
    'rest_framework.throttling.UserRateThrottle'
]

DEFAULT_THROTTLE_RATES = {
    'anon': '100/hour',      # Configurable via API_RATE_LIMIT env var
    'user': '1000/hour'      # Configurable via API_RATE_LIMIT env var
}
```

**API Key Users**: 5000/hour (custom implementation)

**Response Headers**:
- `X-RateLimit-Limit`: Request limit
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Unix timestamp for reset

---

## OpenAPI/Swagger Configuration

**Library**: drf-spectacular  
**Version**: Latest (auto-schema from DRF)

**Endpoints**:
- Schema: `/api/schema/` (JSON format)
- UI: `/docs/` (Swagger UI)
- Documentation: `/redoc/` (ReDoc)

**Configuration**:
```python
SPECTACULAR_SETTINGS = {
    'TITLE': 'Open Security Guardian API',
    'VERSION': '1.0.0',
    'DESCRIPTION': 'Proactive Vulnerability Management Platform',
    'TAGS': [
        {'name': 'Assets', 'description': 'Asset inventory management'},
        {'name': 'Vulnerabilities', 'description': 'Vulnerability tracking and management'},
        {'name': 'Scanners', 'description': 'Vulnerability scanner integrations'},
        {'name': 'Remediation', 'description': 'Remediation workflow management'},
        {'name': 'Compliance', 'description': 'Compliance framework support'},
        {'name': 'Reports', 'description': 'Reporting and analytics'},
    ]
}
```

---

## Source Code Files Examined

### Core Configuration
- `guardian/urls.py` - URL routing
- `guardian/settings.py` - Django & DRF configuration
- `guardian/wsgi.py` - WSGI application
- `guardian/asgi.py` - ASGI application

### Authentication & Security
- `apps/core/authentication.py` - API Key authentication
- `apps/core/permissions.py` - Permission classes
- `apps/core/middleware.py` - Custom middleware
- `apps/core/models.py` - APIKey and SystemConfiguration models

### Views & Endpoints
- `apps/assets/views.py` - 7 ViewSets
- `apps/vulnerabilities/views.py` - 3 ViewSets
- `apps/scanners/views.py` - 5 ViewSets
- `apps/remediation/views.py` - 5 ViewSets
- `apps/compliance/views.py` - 7 ViewSets
- `apps/reporting/views.py` - 7 ViewSets
- `apps/integrations/views.py` - 6 ViewSets

### URL Routing
- `apps/assets/urls.py` - Asset endpoint routing
- `apps/vulnerabilities/urls.py` - Vulnerability endpoint routing
- `apps/scanners/urls.py` - Scanner endpoint routing
- `apps/remediation/urls.py` - Remediation endpoint routing
- `apps/compliance/urls.py` - Compliance endpoint routing
- `apps/reporting/urls.py` - Reporting endpoint routing
- `apps/integrations/urls.py` - Integration endpoint routing

### Data Models
- Multiple `apps/*/models.py` files defining database schema
- `apps/*/serializers.py` files for request/response handling
- `apps/*/filters.py` files for filtering and search

---

## Error Response Format

**Standard Error Response**:
```json
{
    "error": "Error Type Name",
    "message": "Human-readable error message",
    "details": {
        "field_name": ["Field-specific error message"]
    },
    "code": "ERROR_CODE"
}
```

**HTTP Status Codes Used**:
- 200 OK - Successful GET, PUT, PATCH
- 201 Created - Successful POST
- 202 Accepted - Async operation submitted
- 204 No Content - Successful DELETE
- 400 Bad Request - Validation error
- 401 Unauthorized - Authentication required
- 403 Forbidden - Insufficient permissions
- 404 Not Found - Resource not found
- 429 Too Many Requests - Rate limited
- 500 Internal Server Error - Server error

---

## Filtering and Pagination

### Pagination Parameters
```
?page=1                    # Page number (1-indexed)
?page_size=50             # Items per page (max 100)
```

**Response Format**:
```json
{
    "count": 1000,
    "next": "http://localhost:8000/api/v1/assets/?page=2",
    "previous": null,
    "results": [...]
}
```

### Filter Types Supported

**1. Field Filtering** (DjangoFilterBackend)
```
?severity=critical&status=open
?asset_type=server&environment=production
```

**2. Text Search** (SearchFilter)
```
?search=web-server
?search=CVE-2024
```

**3. Ordering** (OrderingFilter)
```
?ordering=-created_at
?ordering=name,severity
```

**4. Date Range**
```
?discovered_after=2025-06-01&discovered_before=2025-06-30
```

---

## Webhook Support

**Registration Endpoint**: `POST /api/v1/integrations/webhooks/`

**Request Body**:
```json
{
    "url": "https://your-system.com/webhook",
    "events": ["vulnerability.created", "vulnerability.updated"],
    "secret": "webhook-signing-secret",
    "is_active": true
}
```

**Available Events**:
- vulnerability.created
- vulnerability.updated
- asset.created
- scan.completed
- compliance.assessment.completed
- remediation.ticket.created

---

## Technology Stack Summary

**Backend Framework**:
- Django 4.x
- Django REST Framework (DRF)

**API Documentation**:
- drf-spectacular (OpenAPI 3.0)

**Database**:
- PostgreSQL (via dj_database_url)

**Caching & Async**:
- Redis (django-redis)
- Celery + Django-Celery-Beat

**Filtering & Search**:
- django-filter
- DRF SearchFilter and OrderingFilter

**Additional Features**:
- django-cors-headers
- psutil (system monitoring)
- prometheus-client (metrics)
- sentry-sdk (optional)

---

## Usage Recommendations

### For API Consumers
1. Start with `GUARDIAN_QUICK_REFERENCE.md`
2. Review authentication methods in this document
3. Use Swagger UI at `/docs/` for interactive testing
4. Reference `GUARDIAN_API_ENDPOINTS.md` for detailed endpoint info

### For Backend Developers
1. Review `GUARDIAN_ENDPOINTS_SUMMARY.txt` for architecture overview
2. Examine ViewSet implementations in `apps/*/views.py`
3. Check serializers in `apps/*/serializers.py` for request/response handling
4. Use Django admin at `/admin/` for database management

### For DevOps/Infrastructure
1. Review technology stack in `GUARDIAN_ENDPOINTS_SUMMARY.txt`
2. Check environment variables section
3. Review deployment configuration
4. Use health check and metrics endpoints for monitoring

### For Integration Specialists
1. Review integrations section of `GUARDIAN_API_ENDPOINTS.md`
2. Check external system integrations documentation
3. Review webhook support and event types
4. Examine integration endpoints in detail

---

## Next Steps

1. **Testing the API**: Use the curl examples in `GUARDIAN_QUICK_REFERENCE.md`
2. **Integration**: Follow webhook setup and integration patterns
3. **Deployment**: Review environment variables and settings
4. **Monitoring**: Implement health check and metrics monitoring
5. **Documentation**: Share these files with stakeholders

---

## File Structure for Reference

```
/Users/fab/GitHub/wildbox/
├── GUARDIAN_API_ENDPOINTS.md           (1,661 lines - COMPREHENSIVE)
├── GUARDIAN_ENDPOINTS_SUMMARY.txt      (522 lines - SUMMARY)
├── GUARDIAN_QUICK_REFERENCE.md         (Quick reference)
├── GUARDIAN_EXPLORATION_INDEX.md       (This file)
│
└── open-security-guardian/
    ├── guardian/
    │   ├── urls.py                     (Main URL routing)
    │   ├── settings.py                 (Configuration)
    │   ├── authentication.py           (Auth classes)
    │   ├── middleware.py               (Custom middleware)
    │   ├── wsgi.py                     (WSGI app)
    │   └── asgi.py                     (ASGI app)
    │
    ├── apps/
    │   ├── core/                       (Shared utilities)
    │   ├── assets/                     (Asset management - 45+ endpoints)
    │   ├── vulnerabilities/            (Vulnerability - 35+ endpoints)
    │   ├── scanners/                   (Scanners - 45+ endpoints)
    │   ├── remediation/                (Remediation - 40+ endpoints)
    │   ├── compliance/                 (Compliance - 50+ endpoints)
    │   ├── reporting/                  (Reports - 45+ endpoints)
    │   └── integrations/               (Integrations - 40+ endpoints)
    │
    ├── requirements.txt                (Python dependencies)
    ├── manage.py                       (Django CLI)
    └── docker-compose.yml              (Container orchestration)
```

---

## Document Version
- **Created**: 2025-11-07
- **Service Version**: 1.0.0
- **API Version**: v1
- **Framework**: Django 4.x + DRF

---

**End of Index Document**

For detailed information, refer to the comprehensive documentation files generated during this exploration.
