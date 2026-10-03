# Open Security Guardian

Guardian is the Wildbox vulnerability management service: an inventory of
assets and the vulnerabilities found on them, with remediation, compliance and
reporting records around them. It is a Django and Django REST Framework
application served by gunicorn on port 8013, with a Celery worker and a Celery
beat scheduler.

## Containers

The root `docker-compose.yml` runs three containers from this directory's
image:

| Service | Command | Role |
| --- | --- | --- |
| `guardian` | `gunicorn ... guardian.wsgi:application` on 8013 | The API; published on `127.0.0.1:8013` only |
| `guardian-worker` | `celery -A guardian worker -Q default,reporting,scanning,analytics` | Runs queued tasks |
| `guardian-beat` | `celery -A guardian beat --scheduler guardian.beat:HeartbeatDatabaseScheduler` | Sends periodic tasks; exactly one instance |

The image's entrypoint (`scripts/docker-entrypoint.sh`) runs
`python manage.py migrate --no-input` before the command, so `guardian`
applies the migrations shipped in `apps/*/migrations/` when it starts.
There is no `makemigrations` step. `guardian-worker` and `guardian-beat` wait
for `guardian` to be healthy, so their own `migrate` has nothing to do.

`guardian-worker` writes generated reports to the `guardian_media` volume,
which `guardian` also mounts to serve the downloads.

### Celery queues

Every task is routed by name in `guardian/celery.py` (`TASK_QUEUES`), and
`guardian-worker` consumes exactly those queues:

| Queue | Tasks |
| --- | --- |
| `scanning` | Asset discovery, discovery rules, asset port scans, remediation re-scans |
| `reporting` | Report generation and metrics, alert-rule checks, expired-report cleanup, compliance reports |
| `analytics` | Vulnerability risk-score recomputation, compliance metrics |
| `default` | Notifications, SLA checks, threat-intel enrichment, history cleanup, asset inventory, compliance reminders, the user-schedule dispatcher |

The threat-intel enrichment task reads `THREAT_INTEL_URLS`, which
`guardian/settings.py` does not define, so it currently changes nothing.
Guardian does not query the data service.

`tests/unit/test_celery_routing.py` fails when a registered task has no queue
or when the worker's `-Q` list differs from `TASK_QUEUES`.

The periodic schedule is in `guardian/schedule.py`. Each interval can be
overridden with a `GUARDIAN_SCHEDULE_*` variable on `guardian-beat` (see the
root `docker-compose.yml`); restart `guardian-beat` after changing one.

## Authentication

Guardian accepts only requests that come through the gateway. Clients
authenticate to the gateway on HTTPS port 443 with
`Authorization: Bearer <JWT>` or `X-API-Key: <key>`. The gateway checks the
credential with the identity service, strips client-supplied `X-Wildbox-*`
headers and forwards trusted ones (`X-Wildbox-User-ID`, `X-Wildbox-Team-ID`,
`X-Wildbox-Role`) with the shared `GATEWAY_INTERNAL_SECRET`.
`apps/core/gateway_middleware.py` rejects identity headers that arrive without
the matching secret (403) and answers 503 when `GATEWAY_INTERNAL_SECRET` is
unset. A request without gateway identity headers, whatever other header it
carries, answers 403 `GATEWAY_AUTH_REQUIRED`, as the other services do.
Guardian has no API keys of its own: the `APIKey` model was removed (#629,
migration `core.0002`), and DRF authenticates only with
`GatewayHeaderAuthentication`.

Reads are open to any authenticated caller; create, update, delete and the
other write actions need the `owner` or `admin` role
(`apps/core/permissions.py`, `IsGatewayAdminOrReadOnly`).

The gateway maps `/api/v1/guardian/<path>` to Guardian's `/api/v1/<path>` and
presents `open-security-guardian` as the Host, so Django's `ALLOWED_HOSTS`
check passes. The dashboard calls Guardian through `guardianClient` in
`open-security-dashboard/src/lib/api-client.ts`, whose base URL is the gateway
plus `/api/v1/guardian`.

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

## Quick start

From the repository root, after generating secrets as described in the root
[README](../README.md):

```bash
docker compose up -d guardian guardian-worker guardian-beat gateway
docker compose ps guardian guardian-worker guardian-beat
```

Health, from the host (the port is bound to loopback):

```bash
curl -fsS http://127.0.0.1:8013/health/
```

`/health/` checks the database and the cache and answers 200 with
`"status": "healthy"`, or 503 with `"status": "unhealthy"` and the failing
check under `checks`.

## API

Get a token as shown in the root [README](../README.md). Django routes end
with a slash; keep it.

```bash
CA=open-security-gateway/ssl/wildbox.crt
AUTH="Authorization: Bearer $TOKEN"
G=https://localhost/api/v1/guardian

# List assets
curl --cacert "$CA" -H "$AUTH" "$G/assets/assets/"

# Create an asset (owner or admin role)
curl --cacert "$CA" -H "$AUTH" -H "Content-Type: application/json" \
  -X POST "$G/assets/assets/" \
  -d '{
    "name": "web-01",
    "asset_type": "server",
    "ip_address": "10.0.1.100",
    "criticality": "high",
    "tags": ["production", "web"]
  }'

# Record a vulnerability on it (asset is the asset's UUID)
curl --cacert "$CA" -H "$AUTH" -H "Content-Type: application/json" \
  -X POST "$G/vulnerabilities/" \
  -d '{
    "asset": "<asset-uuid>",
    "title": "Outdated TLS configuration",
    "description": "TLS 1.0 is enabled.",
    "severity": "medium",
    "port": 443,
    "service": "nginx"
  }'

# Change its status, close it, reopen it
curl --cacert "$CA" -H "$AUTH" -H "Content-Type: application/json" \
  -X PATCH "$G/vulnerabilities/<vulnerability-uuid>/" -d '{"status": "in_progress"}'
curl --cacert "$CA" -H "$AUTH" -H "Content-Type: application/json" \
  -X POST "$G/vulnerabilities/<vulnerability-uuid>/close/" -d '{"reason": "patched"}'
curl --cacert "$CA" -H "$AUTH" -X POST "$G/vulnerabilities/<vulnerability-uuid>/reopen/"
```

Responses to create and update use the write serializers
(`VulnerabilityCreateSerializer`, `VulnerabilityUpdateSerializer`), which do
not include `id`; read the record back to get it.

The route prefixes (`guardian/urls.py`), each relative to `/api/v1/guardian/`
through the gateway:

| Prefix | Contents |
| --- | --- |
| `assets/` | `assets`, `environments`, `business-functions`, `groups`, `discovery-rules`, `software`, `ports` |
| `vulnerabilities/` | Vulnerabilities, plus `templates/` and `assessments/` |
| `scanners/` | `scanners`, `scan-profiles`, `scans`, `scan-results`, `scan-schedules` (records only, see [apps/README.md](apps/README.md)) |
| `remediation/` | `tickets`, `workflows`, `steps`, `comments`, `templates` |
| `compliance/` | `frameworks`, `controls`, `assessments`, `evidence`, `results`, `exceptions`, `metrics` |
| `integrations/` | `systems`, `mappings`, `sync-records`, `webhooks`, `logs`, `notifications` (records only) |
| `reports/` | `templates`, `schedules`, `reports`, `dashboards`, `widgets`, `metrics`, `alerts` |
| `tasks/<task_id>/` | State of a dispatched Celery task |

The OpenAPI schema and UIs (`/api/schema/`, `/docs/`, `/redoc/`) exist only
when `DEBUG` is true, and only on the service port, not through the gateway.

## Data model

### Asset

`apps/assets/models.py`:

- `asset_type`: `server`, `workstation`, `network_device`, `mobile_device`,
  `iot_device`, `cloud_instance`, `container`, `application`, `database`,
  `other` (default).
- `criticality`: `critical`, `high`, `medium`, `low`, `unknown` (default).
- `status`: `active`, `inactive`, `decommissioned`, `maintenance`, `unknown`.
- `risk_score` (computed): a criticality weight multiplied by the asset's
  environment and business-function weights.
- `vulnerability_count` (computed): the number of open vulnerabilities.

Creating an asset with an IP address and no known ports queues a TCP connect
port scan (`scan_asset_ports`, queue `scanning`). `POST .../assets/<id>/scan/`
queues the same scan on demand.

### Vulnerability

`apps/vulnerabilities/models.py`:

- `severity`: `critical`, `high`, `medium` (default), `low`, `info`.
- `status`: `open` (default), `in_progress`, `resolved`, `accepted`,
  `false_positive`, `duplicate`.
- `priority`: `p1` to `p4` (default `p3`).
- `resolved_at`: set by the `close` action and cleared by `reopen`; a plain
  `PATCH` of `status` does not set it.
- Unique together: `(asset, cve_id, port)`.

Within the team, users who lack the `view_all_vulnerabilities` permission see only the
vulnerabilities assigned to them or created by them.

## Configuration

Settings are in `guardian/settings.py`. The root compose file passes:

- `SECRET_KEY` from `GUARDIAN_SECRET_KEY` (required).
- `DATABASE_URL` from `GUARDIAN_DATABASE_URL`, falling back to `DATABASE_URL`
  (required; settings refuse to load without it).
- `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`: Redis database 1
  on `wildbox-redis` unless overridden by the `GUARDIAN_*` equivalents.
- `GATEWAY_INTERNAL_SECRET`, shared with the gateway.
- `DEBUG` (default `false`), `LOG_LEVEL`, `ALLOWED_HOSTS`.
- On `guardian-worker`: `GUARDIAN_BASE_URL` (prefix of links in e-mails) and
  `GUARDIAN_ALERT_RENOTIFY_INTERVAL`.

`API_RATE_LIMIT` sets the DRF throttle rate. `PROMETHEUS_ENABLED` (default
`true`) controls `/metrics/`.

## Monitoring

- `GET /health/`: database and cache check, no authentication. The compose
  health check calls it.
- `GET /metrics/`: Prometheus text format from `prometheus_client`'s default
  registry; 404 when `PROMETHEUS_ENABLED` is false.

Neither route is under `/api/v1/`, so the gateway does not expose them; reach
them on `127.0.0.1:8013` or from inside the Docker network.

```bash
docker compose logs -f guardian guardian-worker guardian-beat
```

## Development

Run the unit tests from this directory; `pytest.ini` selects
`guardian.settings_test`:

```bash
pytest
```

Django management commands run in the container:

```bash
docker compose exec guardian python manage.py showmigrations
docker compose exec guardian python manage.py shell
```

After changing a model, create the migration in your checkout
(`python manage.py makemigrations`) and commit it with the change; the
containers only apply migrations.

The Django applications are described in [apps/README.md](apps/README.md).

## License

See [LICENSE](../LICENSE) in the repository root.
