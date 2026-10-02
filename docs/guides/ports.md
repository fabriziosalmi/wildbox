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

## Ports

| Compose service | Container name | Host port | What it is | Health check |
| --- | --- | --- | --- | --- |
| `gateway` | `open-security-gateway` | `443`, `80`, `8080` (all interfaces) | OpenResty gateway: TLS, authentication, rate limiting, routing | `http://localhost/health` |
| `identity` | `open-security-identity` | `127.0.0.1:8001` | Users, JWT login, API keys, teams | `http://localhost:8001/health` |
| `api` | (Compose default) | `127.0.0.1:8000` | Security tools API | `http://localhost:8000/health` |
| `data` | (Compose default) | `127.0.0.1:8002` | Threat intelligence and IOC data | `http://localhost:8002/health` |
| `sensor` | `open-security-sensor` | `127.0.0.1:8004` | Endpoint telemetry (not routed through the gateway) | `http://localhost:8004/health` |
| `agents` | `open-security-agents` | `127.0.0.1:8006` | AI-assisted analysis | `http://localhost:8006/health` |
| `guardian` | `open-security-guardian` | `127.0.0.1:8013` | Vulnerability and asset management | `http://localhost:8013/health` |
| `responder` | `open-security-responder` | `127.0.0.1:8018` | Incident response playbooks | `http://localhost:8018/health` |
| `cspm` | (Compose default) | `127.0.0.1:8019` | Cloud security posture | `http://localhost:8019/health` |
| `dashboard` | `open-security-dashboard` | `127.0.0.1:3000` | Web dashboard | `http://localhost:3000/` |
| `tools-flower` | `open-security-tools-flower` | `127.0.0.1:5555` | Celery Flower for the tools workers | `http://localhost:5555/healthcheck` |
| `automations` | `open-security-automations` | `127.0.0.1:5678` | n8n; only with `--profile automations` | `http://localhost:5678/healthz` |
| `prometheus` | (Compose default) | `127.0.0.1:9090` | Prometheus; only with `--profile monitoring` | - |
| `postgres` | `wildbox-postgres` | none | PostgreSQL 15 | `pg_isready` inside the container |
| `wildbox-redis` | `wildbox-redis` | none | Redis 7 | `redis-cli ping` inside the container |
| `tools-worker`, `data-scheduler`, `backup` | - | none | Background workers; `backup` only with `--profile backup` | - |

`docker compose` commands take the **service name** from the first column
(`docker compose logs identity`, `docker compose exec api ...`), not the
container name.

The paths the gateway routes to each service are listed in the
[gateway routes table](https://www.wildbox.io/docs.html#gateway-routes).

## Checking the Stack

```bash
docker compose ps
curl -s http://localhost/health
for port in 8001 8000 8002 8004 8006 8013 8018 8019; do
  printf '%s ' "$port"
  curl -s -o /dev/null -w '%{http_code}\n' "http://localhost:$port/health"
done
```
