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
| `scanning` | Asset discovery, discovery rules, asset port scans |
| `reporting` | Report generation and metrics, alert-rule checks, expired-report cleanup, compliance reports |
| `analytics` | Vulnerability risk-score recomputation, compliance metrics |
| `default` | Notifications, SLA checks, history cleanup, asset inventory, compliance reminders, the user-schedule dispatcher |

Guardian does not query the data service: a vulnerability's `threat_level`
and `exploitability_score` are what the team records. The task that was to
fill them from threat-intelligence feeds read a `THREAT_INTEL_URLS` setting
that never existed, changed nothing, and was removed (#724).

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
With `DEBUG` false Guardian first redirects plain HTTP to HTTPS
(`SECURE_SSL_REDIRECT`; only `/health/` and
`/internal/team-memberships/revoke/` are exempt), so a request sent straight
to port 8013 answers `301` unless it carries `X-Forwarded-Proto: https`,
which the gateway sends; the 403 and 503 above are what such a request gets.
The gateway also forwards the credential's type and an API key's scopes
(`X-Wildbox-Auth-Type`, `X-Wildbox-Scopes`), and the middleware requires the
scope the gateway requires, again: `data:read` to read, `data:write` to
change, `data:delete` to delete. A key without it answers 403
`INSUFFICIENT_SCOPE`; a request that does not state its auth type, which a
gateway older than guardian does not, answers 403
`GATEWAY_AUTH_TYPE_REQUIRED`. Views get the credential as `request.auth`
(#637).
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

### Pagination links

Lists are paginated 50 rows to a page (`apps/core/pagination.py`);
`?page_size=N` asks for another size, up to 200 (#724). The `next`
and `previous` links are relative references under the gateway's path, such
as `/api/v1/guardian/assets/assets/?page=2`, with no scheme and no host: a
client resolves them against the URL it requested. They used to be absolute
URLs on `open-security-guardian`, the Host the gateway presents, without the
`/guardian` segment (#643).

Guardian learns the gateway's path from `X-Forwarded-Prefix`, a literal in
the guardian location of `wildbox_gateway.conf` that replaces any value a
client sends. It reads the header only on a request the gateway
authenticated, and only when it is a plain path; without it the links are
Guardian's own `/api/v1/...` paths. It never reads `X-Forwarded-Host` for a
link: that is the `Host` the client sent, and `USE_X_FORWARDED_HOST` stays
off. `tests/unit/test_gateway_links.py` fails when the header, the location
and Guardian's API root stop agreeing.

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
  answers 400 with "object does not exist". A user can be named while
  they are a member of your team (next point).
- **A user who left your team is no longer one of its users.** guardian
  does not own memberships; identity does. guardian records that a user
  acted in a team each time the gateway authenticates a request of theirs,
  and counts them as a member for `GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS`
  (30) from the last one. When identity removes a member from a team, or
  deletes an account, it tells guardian (`POST
  /internal/team-memberships/revoke/`, on the internal network, with the
  gateway-internal secret; the gateway does not route it): the user is
  refused at once wherever the team names a user, and the roles they held
  in the team are cleared (assignee, owner, technical contact, approver,
  assessor, dashboard shares). If that notice is lost, the user stops
  counting when the window runs out, because a user who left can make no
  request that renews it. A request the gateway authenticated just before
  the removal may still arrive just after the notice; guardian remembers
  a notice for ten minutes (`REVOCATION_GRACE`, `apps/core/memberships.py`)
  and in that time serves such a request without recording the membership
  again (#724). What a former member did stays on record: the
  rows they created, the exceptions they approved, the notes they wrote.
  The SLA and assignment e-mails go to an assignee only while they are a
  member of the vulnerability's team.
- **E-mail goes to the team's own people, at the address identity gives.**
  guardian keeps no e-mail address: it mirrors identity's users by id. When
  it is about to send, its worker asks identity (`POST
  /internal/team-contacts`, on the internal network, with a secret of its
  own, `GUARDIAN_CONTACTS_SECRET`) for the assignee's address or for the
  team's owners and admins, so a changed address, a lost role, a
  deactivated account or a removed member is not written to. A copy of the
  address kept from the member's last request was considered and not kept:
  it would have been as old as that request.
- **Shared reference data.** Compliance frameworks, their controls and
  vulnerability templates without a team are shared: every team reads them
  and builds on them (an assessment of a shared framework is the team's
  own), and no team changes or deletes them through the API. A team can
  also define its own.
- **Background work stays in the team.** A discovery rule creates assets
  for its team, an alert rule measures its team's data and notifies its
  own recipients, a scheduled report holds its template's team's data and
  is written under `MEDIA_ROOT/reports/<team id>/`. No notification has a
  platform-wide recipient: one without recipients of its own goes to the
  owners and admins of its team, and one nobody can be told of is recorded
  as not sent, with the reason
  (see the [deployment guide](../docs/guides/deployment.md#notification-recipients)).
  `GET /api/v1/tasks/<task_id>/` answers for the tasks your team dispatched
  and 404 for any other.
- **Rows written before guardian kept a team have none.** No team reaches
  them through the API until an operator gives them to one:

  ```bash
  docker compose exec guardian python manage.py assign_guardian_team --list
  docker compose exec guardian python manage.py assign_guardian_team --team <team UUID> --dry-run
  docker compose exec guardian python manage.py assign_guardian_team --team <team UUID>
  ```

  `--list` counts the rows without a team. `--team <team UUID> --dry-run`
  changes nothing and says what the same command without `--dry-run` would
  do: the team, how many rows of each model it would get, and the key and
  name of the first ten of each (`-v 2` names them all). `--include-shared`
  also gives the shared frameworks and vulnerability templates to that
  team. See [UPGRADING.md](../UPGRADING.md).

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

The answer to a create (`VulnerabilityCreateSerializer`) carries the new
record's `id`. The answer to a `PUT` or `PATCH`
(`VulnerabilityUpdateSerializer`) holds the fields an update can change,
without `id`.

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

An action answers `2xx` only for something it did. The actions that answered
`success` without doing anything (testing a connection to a scanner or an
external system, starting a scan, importing results, synchronizing, sending
a notification, and others) were removed in #644 and answer 404; the
[API reference](../docs/api/guardian/endpoints.md) lists each removed route
with what to use instead, and [apps/README.md](apps/README.md) says how the
tests keep a new one out.

Guardian stores no credential of a scanner or an external system. The
fields that took one (`api_key` and `password` on a scanner, `auth_config`
on an external system, `secret_token` on a webhook endpoint, `config` on a
notification channel) kept it as plain text for code that does not exist,
and were removed in #728 with the values they held; a request that sends
one answers 400 on that field.

The OpenAPI schema and UIs (`/api/schema/`, `/docs/`, `/redoc/`) exist only
when `DEBUG` is true, and only on the service port, not through the gateway.
So does Django REST framework's browsable API: with `DEBUG` false the API has
one renderer, JSON, and a request that accepts only `text/html` answers 406
(#724).

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
queues the same scan on demand. Neither scans an internal address: see
[Scan targets](#scan-targets).

### Vulnerability

`apps/vulnerabilities/models.py`:

- `severity`: `critical`, `high`, `medium` (default), `low`, `info`.
- `status`: `open` (default), `in_progress`, `resolved`, `accepted`,
  `false_positive`, `duplicate`.
- `priority`: `p1` to `p4` (default `p3`).
- `resolved_at`: when the status became `resolved`. It follows the status
  on every save (`apps/vulnerabilities/signals.py`): set when the status
  becomes `resolved`, by `close/`, a `PATCH`, a bulk action or a task, and
  cleared when it stops being so (#724).
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
- `CORS_ALLOWED_ORIGINS`, on `guardian` under the production overlay only,
  from `CORS_ORIGINS` in `.env`: the origins a browser may call guardian
  from, separated by commas or as a JSON list, read by the gateway's rules
  (`guardian/cors.py`). Empty or `[]` allows nobody; an entry that is not an
  origin stops guardian at start-up. When the variable is not set at all,
  as in the development stack, guardian allows eight local development
  origins.
- `GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS`, on all three containers: how many
  days a user stays one of a team's users without acting in it, 1 to 365, 30
  when empty. Any other value stops Guardian at start-up
  (`guardian/schedule.py`).
- `GUARDIAN_RATE_LIMIT_USER`, on `guardian` only: see
  [Rate limit](#rate-limit).
- `GUARDIAN_ALLOWED_INTERNAL_TARGETS`, on `guardian` and `guardian-worker`:
  see [Scan targets](#scan-targets).
- On `guardian-worker`: `GUARDIAN_ALERT_RENOTIFY_INTERVAL`, and what it
  needs to send e-mail (see [E-mail](../docs/guides/deployment.md#e-mail)):
  `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USE_TLS`, `EMAIL_USE_SSL`,
  `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD` and `DEFAULT_FROM_EMAIL` from the
  `GUARDIAN_EMAIL_*` and `GUARDIAN_DEFAULT_FROM_EMAIL` variables of `.env`,
  `GUARDIAN_CONTACTS_SECRET`, `GUARDIAN_TEAM_CONTACTS_URL` and
  `GUARDIAN_BASE_URL` (the address users open the dashboard at, for the
  links in e-mails). Without `EMAIL_HOST` no e-mail is sent, and each
  notification is recorded as not sent; `EMAIL_BACKEND` is not read. The
  worker is not given `GATEWAY_INTERNAL_SECRET`.

`PROMETHEUS_ENABLED` (default `true`) controls `/metrics/`.

### Rate limit

Guardian throttles each user to `GUARDIAN_RATE_LIMIT_USER` requests:
`1000/hour` unless set (`guardian/rate_limit.py`).

- The value is `<count>/<period>`, the period one of `second`, `minute`,
  `hour` or `day`, or `off` for no throttle in Guardian. An empty value means
  the default. Anything else stops Guardian when it starts, with the variable
  and the value in the error; it used to start and answer 500 to every
  request.
- The count is per user, on the user id the gateway forwards
  (`apps/core/throttling.py`), not per address: every request arrives from
  the gateway's address. It sits under the gateway's `RATE_LIMIT_PER_HOUR`,
  which is per team, so one member cannot use up Guardian for the others. A
  user over the rate gets 429 with `Retry-After`.
- There is no throttle for anonymous callers. Under `/api/` there are none,
  and the one Guardian had (100 an hour per address) met only `/health/`:
  the container's own probe, 120 an hour from `127.0.0.1`, was refused for
  the last ten minutes of every hour, and the container reported unhealthy
  (#645). `/health/` is not throttled.
- `API_RATE_LIMIT` is the variable's former name. The root compose file
  never passed it, so it had no effect there; a Guardian run from its own
  `.env` still reads it when `GUARDIAN_RATE_LIMIT_USER` is unset.

### Scan targets

Asset discovery and port scans connect to the addresses a team's owner or
admin names, from `guardian-worker`. The worker sits inside the stack's
networks: on the one `wildbox` network with every other service in
`docker-compose.yml`, and on `data` (PostgreSQL, Redis, identity) and `egress`
in the production overlay. Guardian therefore scans no internal address
unless the operator allows it (#748). Before, a discovery of the worker's own
loopback, of the stack's Docker network or of a cloud metadata address was
accepted and run.

- **The policy** is the tools service's, from the one implementation the two
  share (`open_security_shared.target_policy`): private, loopback, link-local,
  multicast, reserved, shared and cloud-metadata addresses are refused, IPv4
  and IPv6, an IPv4 address embedded in an IPv6 one included. A network with
  one such address in it is refused whole. One discovery sweeps at most 1,024
  addresses, allowed or not.
- **Where it applies** (`apps/assets/networks.py`): when a discovery is asked
  for, when a rule is saved and when a port scan is asked for (400, with the
  reason, and nothing queued), and again in the worker when the task runs, for
  a rule or an asset stored before the check. Guardian resolves no host name:
  it scans networks in CIDR notation and asset addresses.
- **An asset is recorded wherever it is.** An inventory lists internal hosts;
  an asset at an internal address is stored, and not port scanned.
- **`GUARDIAN_ALLOWED_INTERNAL_TARGETS`** (`guardian/scan_targets.py`) lists
  the internal ranges guardian may scan: CIDR ranges with their host bits zero
  and IP addresses, comma-separated. It is empty by default, so an upgraded
  deployment scans nothing internal until its operator names the ranges: no
  default can tell an operator's LAN from the stack, which Docker places in
  the same private ranges. A host name is not an entry. A bad entry stops
  `guardian` and `guardian-worker` when they start, with the variable and
  the entry in the error. `TOOLS_ALLOWED_INTERNAL_TARGETS` is the tools
  service's list and Guardian does not read it.

```bash
GUARDIAN_ALLOWED_INTERNAL_TARGETS=192.168.50.0/24,10.20.0.0/16
```

Nothing else in Guardian connects to an address a team supplies. The worker's
other connections go where the operator points them: identity
(`GUARDIAN_TEAM_CONTACTS_URL`) and the mail server (`EMAIL_HOST`).
`GUARDIAN_BASE_URL` is only written into e-mails. The URLs a team stores (a
scanner's or an external system's `base_url`, a ticket's `external_url`, a
framework's `website`) are records: nothing fetches them.

## Monitoring

- `GET /health/`: database and cache check, no authentication. The compose
  health check calls it.
- `GET /metrics/`: Prometheus text format from `prometheus_client`'s default
  registry; 404 when `PROMETHEUS_ENABLED` is false.

Neither route is under `/api/v1/`, so the gateway does not expose them; reach
them on `127.0.0.1:8013` or from inside the Docker network. `/health/`
answers over plain HTTP. `/metrics/` is not exempt from the HTTPS redirect:
with `DEBUG` false send `X-Forwarded-Proto: https`
(`curl -H 'X-Forwarded-Proto: https' http://127.0.0.1:8013/metrics/`), or the
answer is a `301`. No Prometheus job in `monitoring/` scrapes it.

```bash
docker compose logs -f guardian guardian-worker guardian-beat
```

## Development

Run the unit tests from this directory; `pytest.ini` selects
`guardian.settings_test`, which uses an in-memory SQLite database unless
`DATABASE_URL` is set:

```bash
pytest
```

Guardian is deployed on PostgreSQL, and the suite runs there too. A few
tests need it (JSON containment, which SQLite lacks, is skipped there), and
CI runs the whole suite on both (the `Guardian Unit Tests (PostgreSQL)` job
of `.github/workflows/test.yml`). Against a throwaway server of your own:

```bash
docker run -d --rm --name guardian-test-postgres -e POSTGRES_PASSWORD \
  -e POSTGRES_DB=guardian -p 127.0.0.1:55432:5432 postgres:15
DATABASE_URL="postgres://postgres:${POSTGRES_PASSWORD}@127.0.0.1:55432/guardian" pytest
docker rm -f guardian-test-postgres
```

`POSTGRES_PASSWORD` is a value of your choosing, exported in the shell
first. Django creates and drops its own `test_guardian` database on that
server.

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
