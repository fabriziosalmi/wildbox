# Open Security Sensor

An osquery-based endpoint agent that collects host telemetry and sends it,
through the Wildbox gateway, to the data service of its team (see
[Sending telemetry to Wildbox](#sending-telemetry-to-wildbox)).

## Overview

The sensor runs as a single Python process (`main.py`) that starts these
components (`sensor/core/agent.py`):

- **osquery manager** (`sensor/collectors/osquery_manager.py`): runs the osquery
  daemon with built-in query packs for process events, network connections, user
  events and system inventory, and runs one-off queries through `osqueryi`.
- **File monitor** (`sensor/collectors/file_monitor.py`): polls the configured
  paths and reports created, modified and deleted files, with a SHA-256 hash for
  files under 10 MB.
- **Log forwarder** (`sensor/collectors/log_forwarder.py`): off by default
  (`collection.log_forwarding: false`). Reads a fixed, per-platform set of log
  sources.
- **Data processor and forwarder** (`sensor/pipeline/`): normalize and enrich
  events, then batch them and send them over HTTPS to the gateway's
  `/api/v1/data/ingest` (`data_lake.endpoint`).
- **Local API** (`sensor/api/local_api.py`): an HTTP management API, described
  below.

## Architecture

```text
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Host System   │    │   Sensor Agent   │    │  Data Pipeline  │
│                 │    │                  │    │                 │
│ • Process Events│───▶│ • osquery Engine │───▶│ • TLS Transport │
│ • Network Conn. │    │ • Event Filters  │    │ • Data Batching │
│ • File Changes  │    │ • Log Parsers    │    │ • Queue Buffer  │
│ • User Activity │    │ • Config Manager │    │ • Retry Logic   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
                                               ┌─────────────────┐
                                               │ Security Data   │
                                               │ Lake Platform   │
                                               │                 │
                                               │ • Ingestion API │
                                               │ • Data Storage  │
                                               │ • Analytics     │
                                               └─────────────────┘
```

## Platform support

The code has Linux, macOS and Windows branches (default configuration paths,
osquery binary names, log sources). The only packaged and
exercised deployment is the Linux Docker image built from this directory's
`Dockerfile` (osquery 5.10.2, amd64 or arm64). There are no native installer
packages.

## Running the sensor

### With the full Wildbox stack

The root `docker-compose.yml` defines the `sensor` service. It mounts
`config.yaml.example` as `/etc/security-sensor/config.yaml`, publishes the local
API on `127.0.0.1:8004`, and requires `SENSOR_API_KEY` in `.env`:

```bash
docker compose up -d sensor
curl http://127.0.0.1:8004/health
```

It sends telemetry to `https://open-security-gateway`, trusting the
certificate the gateway publishes in the `gateway_cert` volume, once
`SENSOR_DATA_LAKE_API_KEY` is set (see
[In the Wildbox stack](#in-the-wildbox-stack)).

The gateway does not route requests to the sensor: its `/api/v1/sensor/` block
is commented out in `open-security-gateway/nginx/conf.d/wildbox_gateway.conf`.
Use the local API on the host loopback address.

### Standalone

`docker-compose.yml` in this directory builds the same image, mounts the same
`config.yaml.example`, publishes `127.0.0.1:8004`, and also starts a Redis
container (the sensor code does not use it). It attaches to the external
`security-suite` network, so create that network first:

```bash
docker network create security-suite
SENSOR_API_KEY=<key> docker compose up -d
curl http://127.0.0.1:8004/health
```

The build reads `../open-security-shared` as an additional build context, so
run it from a full repository checkout. This file starts no gateway: to send
telemetry, point `SENSOR_DATA_LAKE_ENDPOINT` at a Wildbox gateway and set
`SENSOR_DATA_LAKE_API_KEY` (and `SENSOR_DATA_LAKE_CA_BUNDLE` for a private
CA).

### Without Docker

```bash
pip install -r requirements.txt
pip install --no-deps ../open-security-shared
python main.py --config config.yaml
```

Without `--config`, the sensor reads the first file that exists among
`./config.yaml`, `./sensor-config.yaml`, `/etc/security-sensor/config.yaml`,
`/usr/local/etc/security-sensor/config.yaml` and
`~/.config/security-sensor/config.yaml` (on Windows,
`%PROGRAMFILES%\SecuritySensor\config.yaml` and
`%APPDATA%\SecuritySensor\config.yaml`).

## Command-line options

`main.py` accepts:

| Option | Effect |
| :--- | :--- |
| `--config`, `-c` | Path to the configuration file |
| `--validate-config` | Load and validate the configuration, then exit |
| `--test-connection` | Posts an empty batch with the configured key and prints the gateway's answer |
| `--status` | Prints a fixed "Running" message and exits; the sensor is not queried |
| `--debug` | Enable debug logging |
| `--version`, `-v` | Print the version and exit |

`setup.py` declares a `security-sensor` console script (and a shorter alias),
both pointing at `main:main`.

## Configuration

Edit the configuration file with your environment details. The
`data_lake` section is described in
[Sending telemetry to Wildbox](#sending-telemetry-to-wildbox).

```yaml
# Where telemetry goes: the Wildbox gateway, over HTTPS
data_lake:
  endpoint: "https://wildbox.example.com"
  api_key: ""        # set SENSOR_DATA_LAKE_API_KEY instead
  tls_verify: true
  ca_bundle: ""      # PEM file, if no public CA signed the gateway's certificate
  batch_size: 100
  flush_interval: 30

# Telemetry Collection
collection:
  process_events: true
  network_connections: true
  file_monitoring: true
  user_events: true
  system_inventory: true
  
# File Integrity Monitoring
fim:
  enabled: true
  paths:
    - "/etc"
    - "/bin"
    - "/usr/bin"
    - "/opt"
  exclude_patterns:
    - "*.tmp"
    - "*.log"

# Performance Tuning
performance:
  query_interval: 10
  max_memory_mb: 128
  max_cpu_percent: 5
```

The `network` section configures the local API:

```yaml
network:
  bind_address: "0.0.0.0"  # inside a container; 127.0.0.1 on a host
  bind_port: 8004
  enable_api: true
  api_key: null            # set it, or use SENSOR_API_KEY
```

| File | Purpose |
| :--- | :--- |
| `config.yaml.example` | Mounted by both compose files; binds `0.0.0.0:8004` |
| `config.yaml` | For running on a host; binds `127.0.0.1:8004` |
| `config.docker.yaml` | Alternative container template; binds `0.0.0.0:8004` |

### Environment variables

These override the configuration file (`sensor/core/config.py`):

| Variable | Configuration key |
| :--- | :--- |
| `SENSOR_DATA_LAKE_ENDPOINT` | `data_lake.endpoint` |
| `SENSOR_DATA_LAKE_API_KEY` | `data_lake.api_key` |
| `SENSOR_DATA_LAKE_TLS_VERIFY` | `data_lake.tls_verify` |
| `SENSOR_DATA_LAKE_CA_BUNDLE` | `data_lake.ca_bundle` |
| `SENSOR_DATA_LAKE_SENSOR_ID` | `data_lake.sensor_id` |
| `SENSOR_LOGGING_LEVEL` | `logging.level` |
| `SENSOR_LOGGING_FILE` | `logging.file` |
| `SENSOR_PERFORMANCE_MAX_MEMORY` | `performance.max_memory_mb` |
| `SENSOR_PERFORMANCE_MAX_CPU` | `performance.max_cpu_percent` |
| `SENSOR_API_KEY` | `network.api_key` |

`ENVIRONMENT=production` disables the HTML route list served at `/` and `/docs`.

## Sending telemetry to Wildbox

The sensor sends telemetry to the Wildbox gateway, never to the data service
directly:

```text
sensor --HTTPS, X-API-Key--> gateway /api/v1/data/ingest --> data service
                             (checks the key and its scope,  (stores the events
                              forwards the key's team)        under that team)
```

It authenticates with an identity personal API key. The gateway checks the
key at identity on every batch, refuses it once it is revoked or expired or
its member has left the team, and forwards the batch with the key's team; the
data service stores the events under that team and shows them to that team
only. A batch names no team, and one it claims is ignored.

### 1. Create a team member for the sensor

Give the sensor an account of its own in the team its telemetry belongs to,
so it can be revoked without touching anyone else's access. A team owner or
admin adds it in the dashboard under **Settings > Team > Add member**, or
through the API:

```bash
curl -X POST "https://<gateway>/api/v1/identity/admin/teams/<team-id>/members" \
  -H "Authorization: Bearer <admin session token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "sensor-web-1@example.com", "password": "<initial password>", "role": "member"}'
```

Sign in once as that member and change the initial password: until then
Wildbox refuses everything else the account does.

### 2. Create its API key, scoped to ingest

Signed in as the sensor's member, create a personal API key under
**Settings > API keys** with the **Telemetry Ingest** (`data:ingest`) scope
only, or:

```bash
curl -X POST "https://<gateway>/api/v1/identity/api-keys" \
  -H "Authorization: Bearer <the member's session token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "sensor web-1", "scopes": ["data:ingest"]}'
```

The key (`wsk_...`) is shown once. A `data:ingest` key can post telemetry to
`/api/v1/data/ingest` and nothing else: the gateway answers every other route
with 403 `insufficient_scope`. A key with the `write` or `data:write` scope can
ingest too, but can also write everything else that scope allows. The gateway
is where scopes are enforced: the data service only learns the key's user and
team, not its scopes (#637).

### 3. Configure the sensor

| Setting | Environment variable | Value |
| --- | --- | --- |
| `data_lake.endpoint` | `SENSOR_DATA_LAKE_ENDPOINT` | The gateway, `https://<gateway>`, or the full `https://<gateway>/api/v1/data/ingest`. HTTPS only. |
| `data_lake.api_key` | `SENSOR_DATA_LAKE_API_KEY` | The key from step 2. Prefer the variable to the file. |
| `data_lake.tls_verify` | `SENSOR_DATA_LAKE_TLS_VERIFY` | `true` (the default). Leave it on. |
| `data_lake.ca_bundle` | `SENSOR_DATA_LAKE_CA_BUNDLE` | A PEM file to trust for the gateway's certificate, when no public CA signed it (the development certificate the gateway generates). Unset: the system trust store. |
| `data_lake.sensor_id` | `SENSOR_DATA_LAKE_SENSOR_ID` | The sensor's name in Wildbox. Default: the hostname. Unique within the team. |

The sensor validates these when it starts and stops with a message naming the
setting that cannot work: an `http://` endpoint, the data service's old
`/api/v1/ingest` URL, a key that is not an identity key, a CA bundle that does
not exist. With no key at all it starts, logs that forwarding is disabled, and
discards events until a key is set and the sensor restarted: the key cannot
exist before the stack that issues it has started.

To check the connection without waiting for a batch:

```bash
python main.py --config /etc/security-sensor/config.yaml --test-connection
```

It posts an empty batch with the configured key and reports what the gateway
answered: 200 means the URL, the TLS trust, the key and its scope are right;
401 means the key is invalid, expired or revoked; 403 means it lacks the
`data:ingest` scope.

The sensor sends the key in the `X-API-Key` header only, does not follow
redirects with it, and never logs it. A batch the gateway refuses with 401 or
403 is not retried; network errors, 429 and 5xx answers are, with backoff.

### In the Wildbox stack

The sensor in `docker-compose.yml` is already pointed at the gateway,
`https://open-security-gateway`, and trusts the certificate the gateway
publishes into the `gateway_cert` volume (the certificate only, never its
key). Set the key and restart it:

```bash
# .env
SENSOR_DATA_LAKE_API_KEY=wsk_...

docker compose up -d sensor
```

In the production overlay the sensor is on the `frontend` network with the
gateway and the dashboard: it reaches the gateway's HTTPS listener and no
backend service, as a sensor on another host would.

### Reading the telemetry

Any member of the team reads it through the gateway:

```bash
curl -H "X-API-Key: <a key with the read scope>" \
  "https://<gateway>/api/v1/data/telemetry/events?sensor_id=web-1&limit=10"
```

`/api/v1/data/telemetry/stats` and `/api/v1/data/sensors` are scoped to the
team the same way. Each event keeps what the sensor collected in
`event_data`; its `event_type` is one of the data service's types
(`process_event`, `network_connection`, `file_change`, `user_event`,
`system_inventory`, `security_event` for logs and anything else), and the
collector's own type, such as `log.nginx_access`, is its first tag.

### Revoking a sensor

Revoke its key (**Settings > API keys**, or
`DELETE /api/v1/identity/api-keys/<prefix>`) or remove its member from the
team. The gateway refuses the key on the sensor's next batch, with no cache
delay.

## Local API

Every route except `/health` requires the API key, sent as
`Authorization: Bearer <key>` or `X-API-Key: <key>`. Without a configured key
those routes answer `503`; with a wrong key, `403`.

| Method | Path | Behavior |
| :--- | :--- | :--- |
| `GET` | `/health` | Liveness; no authentication |
| `GET` | `/status`, `/api/v1/status` | Agent status |
| `GET` | `/api/v1/config` | Current configuration, without secrets |
| `PUT` | `/api/v1/config` | Not implemented; returns `501` |
| `POST` | `/api/v1/config/reload` | Not implemented; returns `501` |
| `POST` | `/api/v1/config/validate` | Validate the loaded configuration |
| `POST` | `/api/v1/query` | Run an osquery query, body `{"query": "..."}` |
| `GET` | `/api/v1/queries` | Names of the loaded query packs and the query count |
| `GET` | `/api/v1/components` | Status of each component |
| `GET` | `/api/v1/stats` | Agent counters |
| `GET` | `/api/v1/dashboard/metrics` | Summary metrics for this endpoint |
| `POST` | `/api/v1/test-connection` | POST an empty test batch to `data_lake.endpoint` |

```bash
curl -H "X-API-Key: $SENSOR_API_KEY" http://127.0.0.1:8004/api/v1/status

curl -X POST http://127.0.0.1:8004/api/v1/query \
  -H "X-API-Key: $SENSOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT pid, name FROM processes LIMIT 5;"}'
```

## Security notes

- The container runs as the non-root `sensor` user with
  `no-new-privileges` and all capabilities dropped (`cap_drop: ALL`).
- Host access is limited to read-only mounts of `/proc/stat`, `/proc/meminfo`,
  the `/proc` load average file and `/sys/class/net`.
- The local API is published on `127.0.0.1` only, because it can read host
  telemetry and run osquery queries.
- Telemetry goes to the gateway over HTTPS only, verified against the system
  trust store or `data_lake.ca_bundle`; `data_lake.tls_verify: false` disables
  verification and logs a warning. The ingest key is sent in `X-API-Key` only,
  redirects are not followed and the key is never logged.

## Development

```bash
pip install -r requirements.txt
pytest tests/unit/
```

The test suite is `tests/unit/`.

## Related documentation

- [Docker deployment](DOCKER.md)
- [Contributing](../CONTRIBUTING.md)
- [License](../LICENSE)
