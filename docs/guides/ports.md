# Service Ports

This is the one place in the documentation that lists service ports. Other
guides link here instead of repeating them. The source of truth is
[`docker-compose.yml`](https://github.com/fabriziosalmi/wildbox/blob/main/docker-compose.yml):
if this page and that file disagree, the file is right and this page is a bug.

## How the Stack Is Exposed

- The **gateway** is the only service published on all interfaces. Clients
  use it over HTTPS on port 443. Ports 80 and 8080 answer `/health` and
  redirect everything else to HTTPS, so authentication never happens in clear.
- Every other published port is bound to `127.0.0.1`. Those addresses work on
  the machine running Docker and nowhere else; they are for health checks,
  debugging and the integration tests, not for clients.
- PostgreSQL and Redis publish no port at all.
- The gateway also listens on port **8081**, which is not published. Only
  containers on the Compose network reach it; identity calls it to drop a
  revoked token from the gateway's authorization cache
  (`/internal/gateway/purge-auth-cache`, which also requires the
  `GATEWAY_INTERNAL_SECRET`). Do not publish it.

## Ports

| Compose service | Container name | Host port | What it is | Health check |
| --- | --- | --- | --- | --- |
| `gateway` | `open-security-gateway` | `443`, `80`, `8080` (all interfaces); `8081` not published | OpenResty gateway: TLS, authentication, rate limiting, routing | `http://localhost/health` |
| `identity` | `open-security-identity` | `127.0.0.1:8001` | Users, JWT (JSON Web Token) login, API keys, teams | `http://localhost:8001/health` |
| `api` | (Compose default) | `127.0.0.1:8000` | Security tools API | `http://localhost:8000/health` |
| `data` | (Compose default) | `127.0.0.1:8002` | Threat intelligence and IOC (indicator of compromise) data | `http://localhost:8002/health` |
| `sensor` | `open-security-sensor` | `127.0.0.1:8004` | Endpoint telemetry. Its local API is not routed through the gateway; it sends telemetry to the gateway's `443` (`/api/v1/data/ingest`) | `http://localhost:8004/health` |
| `agents` | `open-security-agents` | `127.0.0.1:8006` | AI-assisted analysis | `http://localhost:8006/health` |
| `guardian` | `open-security-guardian` | `127.0.0.1:8013` | Vulnerability and asset management | `http://localhost:8013/health/` (with the slash; without it Django answers 301) |
| `responder` | `open-security-responder` | `127.0.0.1:8018` | Incident response playbooks | `http://localhost:8018/health` |
| `cspm` | (Compose default) | `127.0.0.1:8019` | Cloud security posture | `http://localhost:8019/health` |
| `dashboard` | `open-security-dashboard` | `127.0.0.1:3000` | Web dashboard | `http://localhost:3000/` |
| `tools-flower` | `open-security-tools-flower` | `127.0.0.1:5555` | Celery Flower for the tools workers | `http://localhost:5555/healthcheck` |
| `automations` | `open-security-automations` | `127.0.0.1:5678` | n8n; only with `--profile automations` | `http://localhost:5678/healthz` |
| `prometheus` | (Compose default) | `127.0.0.1:9090` | Prometheus; only with `--profile monitoring` | `http://localhost:9090/-/healthy` |
| `postgres` | `wildbox-postgres` | none | PostgreSQL 15 | `pg_isready` inside the container |
| `wildbox-redis` | `wildbox-redis` | none | Redis 7 | `redis-cli ping` inside the container |
| `tools-worker`, `guardian-worker`, `cspm-worker` | (Compose default) | none | Celery workers for tools, guardian and cspm | `celery ... inspect ping` inside the container |
| `data-scheduler` | `open-security-data-scheduler` | none | Collects the threat intelligence feeds on a schedule | scheduler process running |
| `backup` | (Compose default) | none | Scheduled PostgreSQL and Redis backups; only with `--profile backup` | - |
| `guardian-beat` | `open-security-guardian-beat` | none | Sends guardian's periodic tasks; exactly one instance | heartbeat file updated within 60 s |

`docker compose` commands take the **service name** from the first column
(`docker compose logs identity`, `docker compose exec api ...`), not the
container name.

The paths the gateway routes to each service are listed in the
[gateway routes table](https://www.wildbox.io/docs.html#gateway-routes).

## Checking the Stack

`make health` probes every URL in the Health check column and exits non-zero
when one is unhealthy, so it can gate a deployment step or a cron alert:

```bash
make health
```

A service is healthy when its URL answers 2xx. A redirect is not followed and
counts as unhealthy, as does any 4xx or 5xx and no answer at all. It also
checks that PostgreSQL accepts connections and holds the `identity`, `data`
and `guardian` databases, and that Redis answers. `automations` and
`prometheus` are skipped when they are not running, unless `COMPOSE_PROFILES`
names their profile. The URLs live in one table,
`scripts/lib/health_endpoints.sh`, which `scripts/wait-for-services.sh` uses
too; a test keeps it equal to the column above and to `docker-compose.yml`.

By hand:

```bash
docker compose ps
curl -s http://localhost/health
# guardian (8013) is a Django service: its path ends with a slash
for path in 8001/health 8000/health 8002/health 8004/health 8006/health \
            8013/health/ 8018/health 8019/health; do
  printf '%s ' "$path"
  curl -s -o /dev/null -w '%{http_code}\n' "http://localhost:$path"
done
```

## Metrics

identity, tools, data, responder, cspm and agents serve Prometheus metrics at
`/metrics` on their own port. The endpoint has **no authentication**. What
keeps it private is the network layout, not a credential:

- the ports are bound to `127.0.0.1`, so only the Docker host reaches them;
- the gateway does not route `/metrics` to any service.

Prometheus itself (`--profile monitoring`) listens on `127.0.0.1:9090`, also
without authentication, and scrapes the six services over the Compose network
using `monitoring/prometheus.yml`.

From the Docker host:

```bash
curl -s http://127.0.0.1:8001/metrics | head
curl -s 'http://127.0.0.1:9090/api/v1/query?query=up'
```

Do not publish these ports beyond localhost; put an authenticating proxy in
front if you need to reach them remotely.
