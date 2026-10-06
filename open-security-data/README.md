# Open Security Data

The Wildbox data service collects threat-intelligence indicators from public
feeds, stores them in PostgreSQL and serves them through a REST API. It is a
FastAPI application (`app/api/main.py`) with a separate collection scheduler
(`app/scheduler/main.py`).

## What it does

- Collects indicators (IP addresses, domains, URLs, file hashes and other
  types) from configured sources on a per-source interval.
- Validates and normalizes each indicator, then inserts it or updates the
  existing row for the same source, type and normalized value.
- Serves search, lookup, bulk lookup and an NDJSON feed of recent indicators.
- Scopes indicators and sources to the caller's team: a caller sees its own
  team's rows and the global rows (`team_id` empty).
- Stores the telemetry the sensor sends through the gateway
  (`POST /api/v1/data/ingest`) under the team of the sensor's API key, and
  serves it to that team only: telemetry has no global rows (#640, #660). See
  [Sending telemetry to Wildbox](../open-security-sensor/README.md#sending-telemetry-to-wildbox).

The service has no GraphQL, WebSocket or STIX interface.

## Architecture

```text
client --HTTPS--> gateway (443) --HTTP + identity headers--> data API (8002) --> PostgreSQL
                                                             data-scheduler   --> PostgreSQL
```

The root `docker-compose.yml` runs two containers from the same image:

- `data`: the API, `python -m app.api.main` (uvicorn) on port 8002, published
  on `127.0.0.1:8002` only.
- `data-scheduler`: `python -m app.scheduler.main`, which loads enabled sources
  from the database and runs each one when its `collection_interval` elapses.

The API applies the Alembic migrations in `alembic/versions/` at startup. Set
`RUN_MIGRATIONS_ON_STARTUP=false` to skip that when migrations run as a
separate deploy step. The scheduler waits for the schema instead of creating it.

## Authentication

The service accepts only requests that arrive through the gateway. Clients
authenticate to the gateway with `Authorization: Bearer <JWT>` or
`X-API-Key: <key>`; the gateway checks the credential with the identity
service and forwards `X-Wildbox-*` identity headers together with the shared
`GATEWAY_INTERNAL_SECRET`. The service verifies both through
`open_security_shared.gateway_auth` (`app/auth.py`) and rejects anything else.
Only `/health`, `/metrics` and the development-only API docs answer without
gateway headers.

The gateway requires an API-key scope of every request: `data:ingest` (or
`data:write`, or `write`) to post telemetry, `read` for every other `GET`
and `write` for every other method. The service checks the same scope
again, on the credential's type and scopes the gateway forwards
(`X-Wildbox-Auth-Type`, `X-Wildbox-Scopes`): a `data:ingest` key reaches
`/api/v1/ingest` and no other route, even if the gateway let it through. A
session is not limited by scopes. A request that carries the gateway's
secret without `X-Wildbox-Auth-Type` answers 403
`GATEWAY_AUTH_TYPE_REQUIRED`: rebuild the gateway together with this
service (#637).

## Running it

Start the data service as part of the Wildbox stack from the repository root;
see the root [README](../README.md) for secrets and first start:

```bash
docker compose up -d data data-scheduler gateway
```

### Seed the default sources

A fresh database has no sources, so the scheduler has nothing to collect.
`manage.py` adds a default set and manages it:

```bash
docker compose exec data python manage.py sources add-defaults
docker compose exec data python manage.py sources list
docker compose exec data python manage.py sources disable "PhishTank"
docker compose exec data python manage.py sources enable "PhishTank"
docker compose exec data python manage.py sources test "Feodo Tracker"
```

`manage.py` has no other commands besides `init` and `reset`. Both use
SQLAlchemy `create_all()` rather than Alembic, and `reset` drops every table;
with the full stack, let the API apply the migrations instead.

### No standalone compose file

There is no Compose file in this directory. The one that was here predated the
shared stack and could not start: it mounted an nginx, a Prometheus and a
Grafana configuration that are not in the repository, and ran the API in
production mode without the `SECRET_KEY` it requires. The service is reached
through the gateway, which authenticates the request and passes the team on,
so it runs from the root `docker-compose.yml`:

```bash
docker compose up -d data data-scheduler gateway
```

## Collectors

Collectors live in `app/collectors/`. The collector for a source is chosen by
its `source_type` through `CollectorRegistry`:

| `source_type` | Collector |
| --- | --- |
| `http`, `https`, `json`, `csv`, `txt` | `HTTPCollector` (generic) |
| `rss`, `atom` | `RSSCollector` |
| `malware_domain_list` | `MalwareDomainListCollector` |
| `abuseipdb` | `AbuseIPDBCollector` |
| `urlvoid` | `URLVoidCollector` |
| `phishtank` | `PhishTankCollector` |
| `feodo_tracker` | `FeodoTrackerCollector` |
| `malwarebazaar` | `MalwareBazaarCollector` |
| `threatfox` | `ThreatFoxCollector` |

The seven source-specific collectors are in `app/collectors/sources.py`.
`sources add-defaults` creates five sources (Malware Domain List, PhishTank,
Feodo Tracker, AbuseIPDB Blacklist, URLVoid Reputation) with `source_type`
`txt` or `json`, so they use the generic `HTTPCollector`. AbuseIPDB and
URLVoid need an API key in the source configuration.
`scripts/init_feeds.py` creates sources with `source_type` `api` or `feed`,
for which no collector is registered, so those sources fail to collect.

To add a source type, subclass `BaseCollector` or `HTTPCollector` in
`app/collectors/sources.py` and register it with
`CollectorRegistry.register_collector()`.

## API

Paths below are as the gateway exposes them: `/api/v1/data/<path>` is
forwarded to the service's `/api/v1/<path>`, and `/api/v1/data/health` to
`/health`.

| Method | Gateway path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/data/health` | Liveness |
| GET | `/api/v1/data/stats` | Indicator and source counts |
| GET | `/api/v1/data/indicators/search` | Search with filters and pagination |
| GET | `/api/v1/data/indicators/{id}` | One indicator by UUID |
| POST | `/api/v1/data/indicators/lookup` | Bulk lookup |
| GET | `/api/v1/data/ips/{ip}` | IP intelligence |
| GET | `/api/v1/data/domains/{domain}` | Domain intelligence |
| GET | `/api/v1/data/hashes/{hash}` | File hash intelligence |
| GET | `/api/v1/data/sources` | Configured sources |
| GET | `/api/v1/data/feeds/realtime` | NDJSON stream of recent indicators, up to 1000 |
| GET | `/api/v1/data/dashboard/threat-intel` | Dashboard summary |
| POST | `/api/v1/data/ingest` | Telemetry batch from a sensor; a key with the `data:ingest` scope is enough |
| GET | `/api/v1/data/telemetry/events` | The team's telemetry events |
| GET | `/api/v1/data/telemetry/stats` | The team's telemetry counts |
| GET | `/api/v1/data/sensors` | The team's sensors |
| GET | `/api/v1/data/sensors/{sensor_id}` | One of the team's sensors |

The OpenAPI UI (`/docs`, `/redoc`) and the schema (`/openapi.json`) are served
only when `ENVIRONMENT` is `development`, and only on the service port
(`http://127.0.0.1:8002/docs`), not through the gateway. Prometheus metrics are at `http://127.0.0.1:8002/metrics`.

The dashboard reaches the service through `dataClient` in
`open-security-dashboard/src/lib/api-client.ts`, whose base URL is the gateway
plus `/api/v1/data`.

### Examples

These use the gateway's certificate and a token obtained as in the root
[README](../README.md):

```bash
CA=open-security-gateway/ssl/wildbox.crt

curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/v1/data/indicators/search?indicator_type=ip_address&threat_types=malware&limit=50"

curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  https://localhost/api/v1/data/ips/203.0.113.10

curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://localhost/api/v1/data/indicators/lookup \
  -d '{"indicators": [{"indicator_type": "domain", "value": "example.com"}]}'

curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/v1/data/feeds/realtime?since_minutes=60"
```

Indicator types are `ip_address`, `domain`, `url`, `file_hash`, `email`,
`certificate`, `asn` and `vulnerability` (`app/models.py`).

## Configuration

Settings are read from environment variables in `app/config.py`;
`.env.example` lists them. In the root compose file the service receives:

- `DATABASE_URL`: from `DATA_DATABASE_URL`, falling back to `DATABASE_URL`.
- `SECRET_KEY`: from `DATA_SECRET_KEY`; required unless `ENVIRONMENT` is
  `development`, as are `DATABASE_URL` and `DEBUG=false`.
- `GATEWAY_INTERNAL_SECRET`: shared with the gateway.
- `ENVIRONMENT`, `DEBUG`, `LOG_LEVEL`, `CORS_ORIGINS`.

Collection settings such as `COLLECTION_INTERVAL`, `MAX_CONCURRENT_COLLECTORS`
and `COLLECTION_TIMEOUT` have defaults in `app/config.py`. Each source's own
`collection_interval` decides when the scheduler runs it. `REDIS_URL` is
configurable but the service does not use Redis.

## Development

```text
open-security-data/
├── alembic/            # Migrations (applied by the API at startup)
├── app/
│   ├── api/main.py     # FastAPI application and routes
│   ├── auth.py         # Gateway authentication dependency
│   ├── collectors/     # Collector base classes, registry, source collectors
│   ├── config.py       # Settings
│   ├── models.py       # SQLAlchemy models
│   ├── scheduler/      # Collection scheduler
│   ├── schemas/        # Pydantic request and response models
│   └── utils/          # Database, validation, normalization, rate limiting
├── manage.py           # Source management CLI
├── scripts/            # init_feeds.py (not used by the stack)
└── tests/unit/
```

Run the unit tests from this directory:

```bash
pytest
```

## License

MIT; see [LICENSE](../LICENSE).
