# Open Security Guardian - Vulnerability Management

**Version:** 1.0  
**Framework:** Django 4.2 + Django REST Framework  
**Port:** 8013  
**Database:** PostgreSQL (guardian schema)

---

## Overview

Guardian is the centralized vulnerability management and asset tracking service for the Wildbox security platform. It provides comprehensive lifecycle management for security vulnerabilities, from discovery through remediation.

### Key Features

- **Asset Management**: Track servers, databases, cloud resources, and endpoints
- **Vulnerability Tracking**: CVE-based vulnerability lifecycle management
- **Risk Scoring**: Automatic risk calculation based on severity and asset criticality
- **Integration Ready**: RESTful API with Swagger documentation
- **Business Logic**: Database constraints prevent duplicate vulnerabilities

---

## First-Time Setup

### Prerequisites

- Docker and Docker Compose installed
- PostgreSQL 15 running (via main docker-compose.yml)
- Python 3.11+ (for local development)

### Quick Start (Docker)

```bash
# 1. Start the service (from main wildbox directory)
docker-compose up -d guardian

# 2. Wait for container to be ready
sleep 10

# 3. Create database migrations (REQUIRED on first run)
docker-compose exec guardian python manage.py makemigrations

# 4. Apply migrations to create database schema
docker-compose exec guardian python manage.py migrate

# 5. Create Django superuser for admin access
docker-compose exec guardian python manage.py createsuperuser
# Follow prompts to set username, email, password

# 6. Generate API key for service-to-service authentication
docker-compose exec guardian python manage.py shell << 'EOF'
from apps.core.models import APIKey
import secrets

# Generate a secure API key
key_value = f"wsk_grd.{secrets.token_hex(32)}"
api_key = APIKey.objects.create(
    name="Guardian Service Key",
    key=key_value,
    is_active=True
)
print(f"\n{'='*60}")
print(f"API Key Created Successfully!")
print(f"{'='*60}")
print(f"Name: {api_key.name}")
print(f"Key:  {key_value}")
print(f"\nSave this key - it won't be shown again!")
print(f"{'='*60}\n")
EOF

# 7. Verify service health
curl http://localhost:8013/health
```

### Expected Output

After successful setup, you should see:

```json
{
  "status": "healthy",
  "service": "guardian",
  "version": "1.0.0",
  "database": "connected"
}
```

---

## API Documentation

### Swagger UI

Interactive API documentation available at:
```
http://localhost:8013/docs
```

### Authentication

Guardian uses API key authentication. Include your key in requests:

```bash
curl -H "X-API-Key: wsk_grd.your-key-here" \
  http://localhost:8013/api/v1/assets/assets/
```

When accessed through the gateway (production):
```bash
curl -H "X-API-Key: wsk_your-key" \
  http://localhost/api/v1/guardian/assets/assets/
```

---

## Common Tasks

### Create an Asset

```bash
curl -X POST http://localhost:8013/api/v1/assets/assets/ \
  -H "X-API-Key: wsk_grd.your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production-web-server",
    "type": "server",
    "ip_address": "10.0.1.100",
    "criticality": "high",
    "owner": "DevOps Team",
    "tags": ["production", "web"]
  }'
```

### Track a Vulnerability

```bash
curl -X POST http://localhost:8013/api/v1/vulnerabilities/ \
  -H "X-API-Key: wsk_grd.your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "asset": 1,
    "cve_id": "CVE-2024-1234",
    "severity": "high",
    "status": "open",
    "port": 443,
    "service": "nginx",
    "description": "Nginx buffer overflow vulnerability"
  }'
```

### Update Vulnerability Status

```bash
# Mark as in progress
curl -X PATCH http://localhost:8013/api/v1/vulnerabilities/1/ \
  -H "X-API-Key: wsk_grd.your-key" \
  -H "Content-Type: application/json" \
  -d '{"status": "in_progress"}'

# Mark as resolved
curl -X PATCH http://localhost:8013/api/v1/vulnerabilities/1/ \
  -H "X-API-Key: wsk_grd.your-key" \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved"}'
```

### Get Asset with Risk Score

```bash
curl http://localhost:8013/api/v1/assets/assets/1/ \
  -H "X-API-Key: wsk_grd.your-key" | jq '{
    name,
    criticality,
    vulnerability_count,
    risk_score
  }'
```

---

## Data Models

### Asset

Represents a trackable security asset (server, database, endpoint, etc.)

**Key Fields:**
- `name`: Asset identifier
- `type`: server, database, endpoint, cloud_resource, network_device
- `criticality`: low, medium, high, critical
- `vulnerability_count`: Auto-calculated property
- `risk_score`: Weighted average of vulnerability severities

### Vulnerability

Represents a security vulnerability associated with an asset

**Key Fields:**
- `asset`: Foreign key to Asset
- `cve_id`: CVE identifier
- `severity`: info, low, medium, high, critical
- `status`: open, in_progress, resolved, false_positive
- `port`: Network port (optional)
- `resolved_at`: Auto-set timestamp when status changes to resolved

**Unique Constraint:** `(asset, cve_id, port)` - prevents duplicate tracking

---

## Database Schema

### Migrations

Guardian uses Django migrations for database schema management:

```bash
# Create new migration after model changes
docker-compose exec guardian python manage.py makemigrations

# Apply migrations
docker-compose exec guardian python manage.py migrate

# View migration status
docker-compose exec guardian python manage.py showmigrations

# Rollback last migration
docker-compose exec guardian python manage.py migrate apps.core <previous_migration_name>
```

### Database Access

```bash
# Django shell (Python ORM)
docker-compose exec guardian python manage.py shell

# Direct PostgreSQL access
docker exec -it wildbox-postgres psql -U postgres -d guardian
```

---

## Development

### Local Setup (without Docker)

```bash
cd open-security-guardian

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For testing/linting

# Configure environment
cp .env.example .env
# Edit .env with your database credentials

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Run development server
python manage.py runserver 0.0.0.0:8013
```

### Running Tests

```bash
# Run all tests
docker-compose exec guardian python manage.py test

# Run specific test file
docker-compose exec guardian python manage.py test apps.core.tests.test_models

# Run with coverage
docker-compose exec guardian coverage run --source='.' manage.py test
docker-compose exec guardian coverage report
```

### Code Quality

```bash
# Lint code
docker-compose exec guardian flake8 apps/

# Format code
docker-compose exec guardian black apps/

# Type checking
docker-compose exec guardian mypy apps/
```

---

## Troubleshooting

### Issue: Migrations Not Applied

**Symptom:** API returns errors about missing tables

**Solution:**
```bash
docker-compose exec guardian python manage.py migrate
```

### Issue: API Key Authentication Fails

**Symptom:** 401 Unauthorized on all requests

**Solution:**
```bash
# Verify API key exists
docker-compose exec guardian python manage.py shell
>>> from apps.core.models import APIKey
>>> APIKey.objects.all()

# Create new API key if needed
>>> import secrets
>>> key = APIKey.objects.create(
...     name="New Key",
...     key=f"wsk_grd.{secrets.token_hex(32)}",
...     is_active=True
... )
>>> print(key.key)
```

### Issue: Database Connection Refused

**Symptom:** `OperationalError: could not connect to server`

**Solution:**
```bash
# Ensure PostgreSQL is running
docker-compose ps postgres

# Check environment variables
docker-compose exec guardian env | grep DATABASE

# Restart guardian service
docker-compose restart guardian
```

### Issue: PATCH Returns Incomplete Object

**Known Issue:** PATCH endpoints may return `{"id": null}` after successful update

**Workaround:** Perform a GET request after PATCH to retrieve updated object

**Tracked In:** VALIDATION_COMPLETE.md (Fix in progress)

---

## Configuration

### Environment Variables

Key configuration options (see `.env.example`):

```bash
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/guardian

# Django
SECRET_KEY=your-secret-key-here
DEBUG=false
ALLOWED_HOSTS=localhost,127.0.0.1,guardian

# Cache
REDIS_URL=redis://localhost:6379/2

# API
API_RATE_LIMIT=100/hour
API_PAGE_SIZE=50
```

### Django Settings

Main settings file: `guardian/settings.py`

Key customizations:
- REST Framework configuration
- CORS settings (for frontend integration)
- Cache backends
- Logging configuration

---

## Integration with Other Services

### Gateway Routing

Production traffic flows through the gateway:

```
Client Request → Gateway (port 80)
  → Authentication Check (Identity Service)
  → Route: /api/v1/guardian/* → Guardian (port 8013)
  → Inject Headers: X-Wildbox-User-ID, X-Wildbox-Team-ID
  → Response
```

### Data Service Integration

Guardian can consume threat intelligence from the data service:

```bash
# Example: Check if vulnerability CVE is in threat database
curl http://data:8002/api/v1/indicators/search?q=CVE-2024-1234
```

### Dashboard Integration

Frontend accesses Guardian via gateway-aware client:

```typescript
// src/lib/api-client.ts
const guardianClient = new ApiClient(
  useGateway 
    ? `${getGatewayUrl()}/api/v1/guardian`
    : 'http://localhost:8013'
)
```

---

## Performance Considerations

### Query Optimization

- Assets and vulnerabilities use database indexes on foreign keys
- `vulnerability_count` and `risk_score` are calculated properties (not cached)
- For large datasets, consider adding Redis caching

### Scaling

For production deployments:
- Use connection pooling (configured in `settings.py`)
- Enable Redis caching for frequent queries
- Consider read replicas for reporting queries
- Use Celery for background vulnerability scanning

---

## Security Notes

### Authentication

- API keys stored hashed in database (not plain text)
- Gateway validates all external requests before forwarding
- Internal service-to-service calls trusted (no re-validation)

### Authorization

- Current version uses API key-based auth (no user-level permissions)
- Future: Integrate with Identity service for team-scoped access control

### Input Validation

- Django model validation prevents invalid data
- Database constraints enforce uniqueness
- DRF serializers validate API request payloads

---

## Monitoring & Logging

### Health Check

```bash
# Basic health check
curl http://localhost:8013/health

# Detailed health check (includes database connectivity)
curl http://localhost:8013/api/v1/health/detailed
```

### Logs

```bash
# View container logs
docker-compose logs -f guardian

# Filter for errors
docker-compose logs guardian | grep ERROR

# Export logs
docker-compose logs --no-color guardian > guardian-logs.txt
```

### Metrics

Prometheus metrics available at:
```
http://localhost:8013/metrics
```

Key metrics:
- `guardian_requests_total`: Total API requests
- `guardian_assets_total`: Total assets tracked
- `guardian_vulnerabilities_open`: Open vulnerabilities count

---

## Additional Resources

- **Full Documentation**: `/docs/guardian/` in main repository
- **API Reference**: `http://localhost:8013/docs` (Swagger)
- **Validation Report**: `VALIDATION_COMPLETE.md` in this directory
- **Issue Tracker**: GitHub Issues

---

## License

Part of the Wildbox Security Platform  
See main repository LICENSE file

---

## Support

For questions or issues:
1. Check this README and troubleshooting section
2. Review `VALIDATION_COMPLETE.md` for known issues
3. Check `/docs/guardian/` for detailed documentation
4. Open an issue on GitHub

---

**Last Updated:** 15 November 2025  
**Maintainer:** Wildbox Platform Team  
**Status:** Production Ready (see VALIDATION_COMPLETE.md for score breakdown)
