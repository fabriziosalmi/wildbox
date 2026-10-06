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
`manage.py` adds the default set and manages it:

```bash
docker compose exec data python manage.py sources add-defaults
docker compose exec data python manage.py sources list
docker compose exec data python manage.py sources test "Feodo Tracker"
docker compose exec data python manage.py sources disable "Feodo Tracker"
docker compose exec data python manage.py sources enable "Feodo Tracker"
```

The default set is the sources a fresh deployment can collect from as it
is (`app/collectors/defaults.py`): today one, Feodo Tracker, whose feed
needs no key. `sources add-defaults` leaves a source of that name alone
when it can be collected, and repairs it in place when it cannot: an
earlier release created "Feodo Tracker" with a `source_type` that had no
collector. `sources enable` refuses a source whose type has no collector,
and the scheduler disables such a source when it meets one, with the
reason in its `last_error`: a source that cannot be collected is not
offered as an enabled one.

The scheduler runs every enabled source it can collect, whatever the
`status` of its row, by one rule at start and at its reload of the sources
every ten minutes. It used to leave a source in `error` out at start and
add it at the first reload, so such a source was collected after a restart
all the same, up to ten minutes later than the others. A source that fails
is tried again at its own `collection_interval`, and is disabled when a
collection raises or times out with ten errors counted.

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

| `source_type` | Collector | What its feed needs (checked on 6 October 2026) |
| --- | --- | --- |
| `feodo_tracker` | `FeodoTrackerCollector` | Nothing: the default source |
| `threatfox` | `ThreatFoxCollector` | An abuse.ch key, as an `Auth-Key` header of the source |
| `malwarebazaar` | `MalwareBazaarCollector` | An abuse.ch key, as an `Auth-Key` header of the source |
| `abuseipdb` | `AbuseIPDBCollector` | An AbuseIPDB key, as `api_key` in the source's `config` |
| `urlvoid` | `URLVoidCollector` | A URLVoid key and a list of domains, as `api_key` and `domains` in the source's `config` |
| `phishtank` | `PhishTankCollector` | A URL with a registered application key; the collector's own default address answers 404 |
| `malware_domain_list` | `MalwareDomainListCollector` | The feed answers 403: the project has stopped |

The registry holds collectors that can run, and nothing else. It used to
register `http`, `https`, `json`, `csv` and `txt` to `HTTPCollector` and
`rss` and `atom` to `RSSCollector`: those are the base classes of the
collectors above, have no `parse_item` and cannot be instantiated, so a
source of one of those types failed every time it was tried. That was every
default source: `sources add-defaults` created five of type `txt` or
`json`, and `scripts/init_feeds.py`, which is removed, six of type `api`
or `feed`, for which nothing was registered at all. There is no command to
create a source of the six types that need a key; such a source is a row of
the `sources` table with that `source_type` and the key where the table
above says.

To add a source type, subclass `BaseCollector` or `HTTPCollector` in
`app/collectors/sources.py`, define `parse_item`, and register the class
with `CollectorRegistry.register_collector()`, which refuses a class that
cannot be instantiated.

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
  A PostgreSQL URL (`postgresql://...`): the tables use PostgreSQL types and
  the migrations are written for it. A URL of another database is refused
  when the engine is first asked for, by the name of its backend
  (`DATABASE_URL names a sqlite database; the data service needs
  PostgreSQL`).
- `SECRET_KEY`: from `DATA_SECRET_KEY`, which Compose requires in every
  environment, as it does `ENVIRONMENT`. The service itself refuses to start
  without `SECRET_KEY` and `DATABASE_URL`, or with `DEBUG=true`, unless
  `ENVIRONMENT` is `development`.
- `GATEWAY_INTERNAL_SECRET`: shared with the gateway.
- `ENVIRONMENT`, `DEBUG`, `LOG_LEVEL`, `CORS_ORIGINS`.

`MAX_CONCURRENT_COLLECTORS` (default 10) is how many sources the scheduler
collects at the same time. Each source's own `collection_interval` decides
when the scheduler runs it. The service uses no Redis and reads no
`REDIS_URL`. `.env.example` lists every variable `app/config.py` reads.

### What the logs hold of an error

A feed that cannot be fetched is logged, and stored with the run and the
source, by the class of the error and its HTTP status, not by its text,
which ends with the feed's URL (#755). A database error is logged the same
way: its class, its SQLSTATE and the constraint and table it names, with the
frames it went through, and not the message PostgreSQL wrote, which holds
values (`DETAIL: Key (...)=(...) already exists` for an indicator stored
twice, `invalid input syntax for type inet: "..."` with what was searched
for). That covers an error no route handles, whose answer is the same `500`,
an indicator the database refuses, and the collection that fails with it.

## Development

```text
open-security-data/
├── alembic/            # Migrations (applied by the API at startup)
├── app/
│   ├── api/main.py     # FastAPI application and routes
│   ├── auth.py         # Gateway authentication dependency
│   ├── collectors/     # Collector base classes, registry, source collectors, default sources
│   ├── config.py       # Settings
│   ├── models.py       # SQLAlchemy models
│   ├── scheduler/      # Collection scheduler
│   ├── schemas/        # Pydantic request and response models
│   └── utils/          # Database, validation, normalization, rate limiting
├── manage.py           # Source management CLI
└── tests/unit/
```

Run the unit tests from this directory, with the shared package installed as
CI does:

```bash
pip install ../open-security-shared
pip install -r requirements.txt
pytest
```

## License

MIT; see [LICENSE](../LICENSE).
