# Service Lifecycle Documentation

**Purpose**: Document the operational lifecycle of Wildbox microservices from development to production.

## Service Architecture

The list below follows the `services:` section of `docker-compose.yml`. Host
ports are bound to `127.0.0.1` except the gateway's, so clients reach the
backends through the gateway (`https://<host>/api/v1/<service>/...`).

### Default Services

These start with a plain `docker compose up -d`.

| Compose service | Role | Stack | Host port |
| --- | --- | --- | --- |
| `gateway` | Only ingress: TLS, Lua authentication, routing, per-team rate limit | OpenResty (nginx + Lua) | 80, 443, 8080 |
| `identity` | Users, teams, JWT login, API keys | FastAPI | 127.0.0.1:8001 |
| `api` | Tools service: security tool catalog and execution | FastAPI | 127.0.0.1:8000 |
| `tools-worker` | Celery worker for tool runs | Celery (tools image) | none |
| `tools-flower` | Celery Flower UI, basic auth | Celery Flower (tools image) | 127.0.0.1:5555 |
| `data` | Threat intelligence and IOC storage | FastAPI | 127.0.0.1:8002 |
| `data-scheduler` | Feed collection scheduler (`python -m app.scheduler.main`) | Python (data image) | none |
| `guardian` | Vulnerabilities, assets, compliance, reports | Django REST Framework | 127.0.0.1:8013 |
| `guardian-worker` | Celery worker for guardian tasks | Celery (guardian image) | none |
| `guardian-beat` | Celery beat scheduler for guardian | Celery (guardian image) | none |
| `responder` | Incident response playbooks | FastAPI | 127.0.0.1:8018 |
| `cspm` | Cloud security posture checks (AWS only) | FastAPI | 127.0.0.1:8019 |
| `cspm-worker` | Celery worker that runs CSPM scans | Celery (cspm image) | none |
| `agents` | AI-assisted analysis through the Anthropic API (optional key) | FastAPI | 127.0.0.1:8006 |
| `sensor` | Host telemetry agent | Python with osquery | 127.0.0.1:8004 |
| `dashboard` | Web UI | Next.js | 127.0.0.1:3000 |
| `postgres` | PostgreSQL 15 (`identity`, `data`, `guardian` databases) | `postgres:15` | none |
| `wildbox-redis` | Redis 7, AOF on, `noeviction`, password required | `redis:7-alpine` | none |

### Profile Services

These start only when their Compose profile is named, for example
`docker compose --profile monitoring up -d`.

| Compose service | Profile | Role | Host port |
| --- | --- | --- | --- |
| `automations` | `automations` | n8n workflow automation (`n8nio/n8n:1.74.0`) | 127.0.0.1:5678 |
| `backup` | `backup` | Periodic PostgreSQL and Redis backup with `scripts/backup_postgres.sh` | none |
| `prometheus` | `monitoring` | Prometheus with `monitoring/prometheus.yml` (`prom/prometheus:v2.55.1`) | 127.0.0.1:9090 |
| `alertmanager` | `monitoring` | Alertmanager with `monitoring/alertmanager.yml`, which notifies nobody until a receiver is configured (`prom/alertmanager:v0.34.1`) | 127.0.0.1:9093 |

### Shared Infrastructure

- **PostgreSQL 15**: Single instance; the default database is `identity`
  (`POSTGRES_DB`), and `scripts/init-databases.sql` creates the
  `guardian` and `data` databases next to the default one.
- **Redis 7**: Single instance, logical databases: 0 identity, 1 guardian,
  2 tools and responder, 3 CSPM, 4 agents.

## Service States

### Not Routed by the Gateway

- **Sensor**: the gateway has no upstream for its local API (commented out
  in `open-security-gateway/nginx/conf.d/wildbox_gateway.conf`). The sensor
  is a client of the gateway instead: it sends its telemetry to
  `/api/v1/data/ingest` with a team member's API key, and the data service
  stores it per team.

### Optional Services

- **Automations (n8n)**: in the `automations` profile. The gateway does not
  route to it: its workflows call the API outbound, through the gateway, and
  its editor is published on `127.0.0.1:5678` of the host only. Create n8n's
  owner account right after the first start; see
  `open-security-automations/README.md`.

### Deprecated Services

Previously active services that have been consolidated or replaced.

**Deprecated**:

- Standalone scripts in `scripts/debug/` (replaced by integrated testing)
- Legacy authentication endpoints (migrated to identity service)

## Service Startup Sequence

`depends_on` with health conditions in `docker-compose.yml` orders startup, so
one command starts the stack:

```bash
docker compose up -d
docker compose ps   # the STATUS column shows each container's health
```

**Critical**: the gateway lists identity, guardian, responder, agents and api
in `depends_on`, and nginx refuses to start when an upstream host name does not
resolve. Starting the gateway alone, or with one of those backends stopped,
leaves it restarting.

### Health Checks

Every backend defines a Compose `healthcheck` that calls its `/health`
endpoint inside the container. Check them with `docker compose ps`, or
through the gateway for the routes that expose one, for example:

```bash
CA=open-security-gateway/ssl/wildbox.crt
curl --cacert "$CA" https://<host>/api/v1/data/health
```

## Service Communication Patterns

### Gateway-Mediated (Production)

```text
Client → Gateway (Lua auth) → Backend Service
```

All production traffic flows through gateway with authentication injection via `X-Wildbox-*` headers.

### Direct Access (Development Only)

```text
Client on the Docker host → 127.0.0.1:<backend port>
```

Backend ports are published on `127.0.0.1` only, for debugging on the Docker
host. **Never expose them on a public interface.**

## Database Migrations

### FastAPI Services (Alembic)

```bash
# Identity service example
docker compose exec identity alembic upgrade head
docker compose exec identity alembic revision -m "Add new column"
```

### Django Services (Django Migrations)

```bash
# Guardian service example
docker compose exec guardian python manage.py migrate
docker compose exec guardian python manage.py makemigrations
```

## Service Decommissioning Process

When removing a service:

1. **Mark as deprecated** in documentation (this file)
2. **Remove its gateway route** and upstream
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

- Health checks: implemented for every backend
- Metrics endpoints: services expose `/metrics` in Prometheus format
- Prometheus: `monitoring` profile; scrapes identity, tools, data, responder,
  CSPM and agents (guardian is not scraped)
- Distributed tracing: not implemented
- Centralized logging: Docker logs only

## Troubleshooting Service Issues

### Service Won't Start

```bash
# Check logs
docker compose logs -f <service-name>

# Verify dependencies
docker compose ps
```

### Service Crashes on Startup

```bash
# Check which database URL the container received (prints the value;
# do not paste the output anywhere public)
docker compose exec <service-name> env | grep DATABASE

# Rebuild with fresh dependencies
docker compose up -d --build --no-deps <service-name>
```

### Gateway Can't Reach Service

```bash
# Verify service is running
docker compose ps <service-name>

# Check gateway logs for upstream errors
docker compose logs -f gateway | grep "upstream"

# Restart gateway after service is healthy
docker compose restart gateway
```

## Service Dependencies Graph

```text
Gateway
  ├─> Identity (auth validation)
  ├─> Tools (security tools)
  ├─> Data (threat intel)
  ├─> Guardian (vulnerabilities)
  ├─> Responder (incidents)
  ├─> Agents (AI analysis)
  ├─> CSPM (cloud security)
  └─> Dashboard (web UI)

Identity
  ├─> PostgreSQL (user data)
  └─> Redis DB 0

Tools (api)
  ├─> Redis DB 2
  └─> tools-worker (Celery)

Guardian
  ├─> PostgreSQL (guardian database)
  ├─> Redis DB 1 (Celery tasks)
  └─> guardian-worker, guardian-beat

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

**Last Updated**: 2026-10-03  
**Related Docs**:

- `docs/OBSERVABILITY_ROADMAP.md`
- `docs/GATEWAY_AUTHENTICATION_GUIDE.md`
- `TROUBLESHOOTING.md`
