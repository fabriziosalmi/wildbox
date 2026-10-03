# Open Security Guardian - Vulnerability Management

**Version:** 1.0  
**Framework:** Django 5.2 LTS + Django REST Framework  
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

# 6. guardian has no API keys of its own: call it through the gateway with
#    a personal API key from identity (see Authentication below)

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

```text
http://localhost:8013/docs
```

### Authentication

Guardian accepts requests through the gateway only. The gateway
authenticates the caller, with a JWT or a personal API key created in
identity (`POST /api/v1/identity/api-keys`, or Settings > API keys in the
dashboard), and forwards the caller's identity, team and role to guardian:

```bash
curl -H "X-API-Key: $WILDBOX_API_KEY" \
  https://localhost/api/v1/guardian/assets/assets/
```

A request made directly to guardian's port answers 403
`GATEWAY_AUTH_REQUIRED`, whatever key it carries. guardian's own API keys
(`apps.core.models.APIKey`) were removed (#629): they authenticated beside
the gateway, as an administrator.

### Team isolation

Every request acts for the team the gateway names in `X-Wildbox-Team-ID`,
and reads and writes that team's data only (#642). The role decides what a
member of the team may do: a `member` reads, an `owner` or `admin` also
writes.

- **Each row belongs to one team.** Assets, environments, business
  functions, asset groups, discovery rules, scanners, compliance
  assessments, exceptions and metrics, external systems, notification
  channels, remediation tickets and templates, report templates,
  dashboards, widgets and alert rules store the team that created them in
  `team_id`. The API sets it from the gateway's header; a `team_id` in a
  request body is ignored. The other rows belong to the team of the row
  they hang off: a vulnerability to its asset's team, a scan to its
  scanner's, a report to its template's, a remediation workflow to its
  vulnerability's.
- **Another team's rows do not exist for you.** Lists leave them out, and
  a detail route or action on one of their ids answers 404, as an id that
  does not exist does. Statistics, summaries, trends, reports, widgets
  and alert rules count your team's rows only.
- **A reference to another team's row is refused.** A foreign key or a
  list of ids in a request body (an asset, a framework, a scanner, a
  template, a user) must name a row your team can see, or the request
  answers 400 with "object does not exist". A user can be named once they
  have made a request as a member of your team.
- **Shared reference data.** Compliance frameworks, their controls and
  vulnerability templates without a team are shared: every team reads them
  and builds on them (an assessment of a shared framework is the team's
  own), and no team changes or deletes them through the API. A team can
  also define its own.
- **Background work stays in the team.** A discovery rule creates assets
  for its team, an alert rule measures its team's data and notifies its
  own recipients, a scheduled report holds its template's team's data and
  is written under `MEDIA_ROOT/reports/<team id>/`.
  `GET /api/v1/tasks/<task_id>/` answers for the tasks your team dispatched
  and 404 for any other.
- **Rows written before guardian kept a team have none.** No team reaches
  them through the API until an operator gives them to one:

  ```bash
  docker compose exec guardian python manage.py assign_guardian_team --list
  docker compose exec guardian python manage.py assign_guardian_team --team <team UUID>
  ```

  `--dry-run` reports what it would change; `--include-shared` also gives
  the shared frameworks and vulnerability templates to that team. See
  [UPGRADING.md](../UPGRADING.md).

---

## Common Tasks

### Create an Asset

```bash
curl -X POST https://localhost/api/v1/guardian/assets/assets/ \
  -H "X-API-Key: $WILDBOX_API_KEY" \
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
curl -X POST https://localhost/api/v1/guardian/vulnerabilities/ \
  -H "X-API-Key: $WILDBOX_API_KEY" \
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
curl -X PATCH https://localhost/api/v1/guardian/vulnerabilities/1/ \
  -H "X-API-Key: $WILDBOX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status": "in_progress"}'

# Mark as resolved
curl -X PATCH https://localhost/api/v1/guardian/vulnerabilities/1/ \
  -H "X-API-Key: $WILDBOX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved"}'
```

### Get Asset with Risk Score

```bash
curl https://localhost/api/v1/guardian/assets/assets/1/ \
  -H "X-API-Key: $WILDBOX_API_KEY" | jq '{
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

### Issue: API Requests Are Refused

**Symptom:** 403 `GATEWAY_AUTH_REQUIRED` on every request

**Solution:** the request did not go through the gateway. Send it to
`https://<host>/api/v1/guardian/...` with a JWT or a personal API key from
identity; guardian has no API keys of its own. A 401 from the gateway means
the key is unknown, revoked or expired: create a new one in identity.

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

**Tracked In:** GitHub Issues

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

```text
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
curl https://localhost/api/v1/guardian/health/detailed
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

```text
http://localhost:8013/metrics
```

Key metrics:

- `guardian_requests_total`: Total API requests
- `guardian_assets_total`: Total assets tracked
- `guardian_vulnerabilities_open`: Open vulnerabilities count

---

## Additional Resources

- **Full Documentation**: [Guardian API reference](https://www.wildbox.io/api/guardian/endpoints/) (the older guides are kept for history in [docs/archive/guardian/](../docs/archive/guardian/))
- **API Reference**: `http://localhost:8013/docs` (Swagger)
- **Issue Tracker**: GitHub Issues

---

## License

Part of the Wildbox Security Platform  
See main repository LICENSE file

---

## Support

For questions or issues:

1. Check this README and troubleshooting section
2. Check the [Guardian API reference](https://www.wildbox.io/api/guardian/endpoints/)
3. Open an issue on GitHub

---

**Last Updated:** 15 November 2025  
**Maintainer:** Wildbox Platform Team  
**Status:** Production Ready
