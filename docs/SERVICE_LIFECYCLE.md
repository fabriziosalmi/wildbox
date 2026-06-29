# Service Lifecycle Documentation

**Purpose**: Document the operational lifecycle of Wildbox microservices from development to production.

## Service Architecture

Wildbox operates as a containerized microservices platform with the following core services:

### Active Production Services

1. **Gateway** (OpenResty/Nginx) - Port 80/443
   - API gateway with Lua-based authentication
   - Handles all external traffic routing
   - Rate limiting and request validation
   
2. **Identity** (FastAPI) - Port 8001
   - Authentication and authorization (JWT, API keys)
   - User and team management
   - Subscription handling

3. **Tools** (FastAPI) - Port 8000
   - 55+ security tools (port scanning, DNS enum, etc.)
   - API key authentication
   - Celery background workers

4. **Data** (Django) - Port 8002
   - Threat intelligence database
   - IOC (Indicators of Compromise) management
   - Integration with external feeds

5. **Guardian** (Django) - Port 8013
   - Vulnerability management
   - CVE tracking and remediation
   - Asset inventory

6. **Responder** (FastAPI) - Port 8018
   - Incident response automation
   - Playbook execution
   - SOAR (Security Orchestration) capabilities

7. **Agents** (FastAPI) - Port 8006
   - AI-powered security analysis (GPT-4o integration)
   - Automated threat hunting
   - Log analysis

8. **CSPM** (FastAPI) - Port 8019
   - Cloud Security Posture Management
   - 200+ cloud security checks (AWS, Azure, GCP)
   - Compliance reporting

9. **Sensor** (Rust) - Port 8004
   - Endpoint monitoring (osquery integration)
   - System telemetry collection
   - Certificate-based authentication

10. **Dashboard** (Next.js 14) - Port 3000
    - User interface (App Router, React Server Components)
    - Session + JWT authentication
    - Real-time updates via WebSockets (planned)

11. **Automations** (n8n) - Port 5678
    - Workflow automation
    - Integration orchestration
    - Basic authentication

### Shared Infrastructure

- **PostgreSQL 15**: Single instance, multiple databases (`identity`, `data`, `guardian`, etc.)
- **Redis 7**: Single instance, logical DB separation (DB 0-15)

## Service States

### Development State
Services under active development with incomplete features.

**Current Development Services**:
- **Sensor**: 50% complete, Rust implementation in progress
- **CSPM**: Feature complete, requires extensive testing (314 files)

### Deprecated Services
Previously active services that have been consolidated or replaced.

**Deprecated**:
- Standalone scripts in `scripts/debug/` (replaced by integrated testing)
- Legacy authentication endpoints (migrated to identity service)

### Disabled Services
Services configured in docker-compose but not active in production.

**Disabled**:
- Automations service (upstream marked `down` in gateway config)

## Service Startup Sequence

Proper startup order prevents dependency failures:

```bash
# Phase 1: Infrastructure (0-30s)
docker-compose up -d postgres wildbox-redis

# Phase 2: Core Services (30-60s)
docker-compose up -d identity

# Phase 3: Application Services (60-120s)
docker-compose up -d gateway data guardian tools responder agents cspm

# Phase 4: Frontend & Monitoring (120-180s)
docker-compose up -d dashboard sensor
```

**Critical**: Wait for health checks to pass before starting dependent services.

### Health Check Endpoints

All services expose `/health` endpoint:

```bash
# Check service health
curl http://localhost:8001/health  # Identity
curl http://localhost:8000/health  # Tools
curl http://localhost:8002/health  # Data
# etc.
```

**Expected Response**:
```json
{
  "status": "healthy",
  "service": "identity",
  "timestamp": "2025-11-24T12:00:00Z"
}
```

## Service Communication Patterns

### Gateway-Mediated (Production)
```
Client → Gateway (Lua auth) → Backend Service
```

All production traffic flows through gateway with authentication injection via `X-Wildbox-*` headers.

### Direct Access (Development Only)
```
Client → Backend Service (port 8000-8019)
```

Used for debugging and local development. **Never expose in production.**

## Database Migrations

### FastAPI Services (Alembic)
```bash
# Identity service example
docker-compose exec identity alembic upgrade head
docker-compose exec identity alembic revision -m "Add new column"
```

### Django Services (Django Migrations)
```bash
# Guardian service example
docker-compose exec guardian python manage.py migrate
docker-compose exec guardian python manage.py makemigrations
```

## Service Decommissioning Process

When removing a service:

1. **Mark as deprecated** in documentation (this file)
2. **Disable in gateway** by setting upstream `down`
3. **Update docker-compose.yml** with comment explaining deprecation
4. **Remove after 2 release cycles** (minimum 60 days)
5. **Archive code** to `archive/` directory
6. **Update dependent services** to handle missing service gracefully

### Example: Decommissioning a Service

```yaml
# docker-compose.yml
# ============================================================================
# DEPRECATED - Service removed as of v0.3.0 (2025-11-24)
# Functionality migrated to agents service
# Scheduled for complete removal in v0.5.0 (2026-01-24)
# ============================================================================
# legacy_analyzer:
#   build:
#     context: ./open-security-legacy-analyzer
#   ...
```

## Service Restoration

If a service needs to be brought back online:

1. **Review docker-compose.yml** for service definition
2. **Check for database migrations** that need to be run
3. **Update gateway configuration** to enable routing
4. **Run health checks** before declaring service active
5. **Update documentation** to remove deprecated status

## Monitoring and Observability

See `docs/OBSERVABILITY_ROADMAP.md` for detailed monitoring setup.

**Current State**:
- Health checks: ✅ Implemented
- Metrics endpoints: ⚠️ Partial (identity, tools)
- Prometheus integration: ❌ Planned
- Distributed tracing: ❌ Planned
- Centralized logging: ⚠️ Docker logs only

## Troubleshooting Service Issues

### Service Won't Start
```bash
# Check logs
docker-compose logs -f <service-name>

# Verify dependencies
docker-compose ps

# Check database connectivity
docker-compose exec <service-name> python -c "import psycopg2; print('DB OK')"
```

### Service Crashes on Startup
```bash
# Run migrations
docker-compose exec <service-name> alembic upgrade head

# Check environment variables
docker-compose exec <service-name> env | grep DATABASE

# Rebuild with fresh dependencies
docker-compose up -d --build --no-deps <service-name>
```

### Gateway Can't Reach Service
```bash
# Verify service is running
docker-compose ps <service-name>

# Check gateway logs for upstream errors
docker-compose logs -f gateway | grep "upstream"

# Restart gateway after service is healthy
docker-compose restart gateway
```

## Service Dependencies Graph

```
Gateway
  ├─> Identity (auth validation)
  ├─> Tools (security tools)
  ├─> Data (threat intel)
  ├─> Guardian (vulnerabilities)
  ├─> Responder (incidents)
  ├─> Agents (AI analysis)
  └─> CSPM (cloud security)

Identity
  ├─> PostgreSQL (user data)
  └─> Redis (session cache)

Tools
  ├─> PostgreSQL (tool results)
  ├─> Redis (rate limiting)
  └─> Celery (background jobs)

Dashboard
  └─> Gateway (all API calls)
```

## Release Checklist

Before releasing a new version:

- [ ] All service health checks pass
- [ ] Database migrations tested and documented
- [ ] Gateway routing configuration updated
- [ ] Environment variable changes documented
- [ ] Deprecated services marked in changelog
- [ ] New services added to this lifecycle documentation
- [ ] Integration tests pass for all active services
- [ ] Load testing completed for modified services

---

**Last Updated**: 2025-11-24  
**Maintainer**: DevOps Team  
**Related Docs**: 
- `docs/OBSERVABILITY_ROADMAP.md`
- `docs/GATEWAY_AUTHENTICATION_GUIDE.md`
- `TROUBLESHOOTING.md`
