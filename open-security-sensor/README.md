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
  (`collection.log_forwarding: false`). Follows the log files and system logs
  listed under `log_sources`, or a per-platform default set when the
  configuration has no such section. See [Log forwarding](#log-forwarding).
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
  retry_delay: 5             # seconds before a failed batch is sent again
  retry_max_delay: 300       # the delay doubles up to this
  buffer_max_events: 5000    # what may wait for the gateway
  buffer_max_bytes: 16777216

# Telemetry Collection
collection:
  process_events: true
  network_connections: true
  file_monitoring: true
  user_events: true
  system_inventory: true
  log_forwarding: false   # what it reads: see "Log forwarding"

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

No environment variable sets `collection.log_forwarding` or `log_sources`:
what the sensor reads from the host is the configuration file's to say.

## Log forwarding

With `collection.log_forwarding: true`, the sensor follows the sources listed
under `log_sources` and sends each line as an event. It is off by default.

```yaml
collection:
  log_forwarding: true

log_sources:
  - name: nginx_access
    type: file
    path: /var/log/nginx/access.log
    format: nginx
  - name: app
    path: /srv/app/logs/*.log        # a pattern; type file, format raw
    enabled: false
  - name: journal
    type: journald
```

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `name` | Required | Unique; letters, digits, `_`, `.`, `-`, at most 64. The events' type is `log.<name>`, which is also their first tag |
| `type` | `file` | `file`, `journald` (Linux, runs `journalctl -f`), `windows_event` (Windows) or `unified_log` (macOS, runs `log stream`) |
| `path` | Required for `file` | Absolute path of a file, or a pattern with `*`, `?` and `[...]`. `**` is not supported, and a pattern must name the directory it reads (`/*.log` is refused) |
| `format` | `raw` | For `file`: `syslog`, `nginx`, `apache` or `raw`. A line the format does not match is forwarded as `raw_message` only |
| `enabled` | `true` | `false` keeps the entry and does not read it |
| `read_from` | `end` | For `file`, where to start in a file that exists when the sensor starts: `end` forwards only what is written afterwards, `beginning` also what it already holds |
| `log_name` | Required for `windows_event` | The event log's name, such as `Security` |

An entry takes no other key.

### Default sources

Without a `log_sources` key the forwarder reads the platform's defaults, which
is all it read before `log_sources` was honored:

| Platform | Sources |
| :--- | :--- |
| Linux | `/var/log/syslog` and `/var/log/auth.log` (format `syslog`), and the systemd journal |
| macOS | `/var/log/system.log` (format `syslog`) and the unified log |
| Windows | The `Security`, `System` and `Application` event logs |

With the key, it reads exactly the sources listed and none of the defaults;
`log_sources: []` forwards no log. In the Docker image the Linux defaults
read nothing: the image has no `/var/log/syslog`, no `/var/log/auth.log` and
no `journalctl`, and the forwarder says so in three log lines.

### What stops the sensor, and what is a warning

A `log_sources` section the sensor cannot understand stops it at start-up,
like an unusable `data_lake`, with a message that names every entry at fault
(`log_sources[1] ('app'): unknown type 'tcp'; ...`): an unknown key, type or
format, a missing or repeated name, a relative path, `**`, a value of
`enabled` that is not `true` or `false`, more than 64 entries, or the key
with no value under it (write `log_sources: []`, or remove the key). An
unknown key is refused because `enable: false`, ignored, would leave the
source forwarding its file. The same errors are reported by
`python main.py --config <file> --validate-config`.

What a path names can change while the sensor runs, so it never stops the
sensor. Each of these is a warning that names the source and the file,
logged once, and the source keeps being checked every second:

- the file does not exist yet, or no file matches the pattern;
- the sensor's user is not allowed to read it;
- it is not a regular file (a directory, a device, a pipe);
- it is a link that leads out of the source's directory (see below);
- it is the sensor's own log file (`logging.file`).

A source of a type this platform cannot read (`journald` on macOS) is skipped
with a warning. This matches the other collectors: the file monitor warns
about a path that does not exist and skips it, and the sensor stops for a
configuration it cannot use.

The sources, the files each one is reading and its current problems are in
`GET /api/v1/components` under `log_forwarder`; the configured list is in
`GET /api/v1/config`.

### How a file is followed

- A file that exists when the sensor starts is read from its end (or its
  beginning, with `read_from: beginning`). A file that appears later, alone
  or as a new match of a pattern, is read from its beginning. Patterns are
  expanded every 5 seconds, files are checked every second.
- **Rotation.** When the path names another file (`logrotate` renamed the old
  one), the old file is read to its end, including a last line without a
  newline, and then the new one from its beginning. If the pattern also
  matches the rotated name (`access.log*`), the file is followed under its
  new name and not sent again. A file truncated in place (`copytruncate`) is
  read again from its beginning; the sensor notices by its size or, when it
  has already grown past the old position, by its first 256 bytes.
- **Lines.** A line is forwarded when its newline is written, never in two
  parts. A line longer than 16 KiB is forwarded once, cut to 16 KiB, with
  `metadata.truncated: true`. Bytes that are not UTF-8, and NUL bytes, become
  U+FFFD. Empty lines are skipped.
- **Compressed rotations** a pattern matches (`.gz`, `.bz2`, `.xz`, `.zst`,
  `.zip`, `.lz4`, `.Z`) are not read. A source reads at most 64 files at a
  time and warns when its pattern matches more.
- **When Wildbox is unreachable.** The forwarder reads 64 KiB at a time and
  waits for the event queue (`performance.max_queue_size`) to take each line.
  When batches cannot be sent the sender's buffer and then the queues fill,
  the forwarder stops reading, and the file is the buffer: it continues from
  the same place, and no line is given up. See
  [When the gateway takes nothing](#when-the-gateway-takes-nothing).
- **Restarts.** Positions are kept in memory only. After a restart a
  `read_from: end` source continues from the file's end, so lines written
  while the sensor was down are not sent, and a `read_from: beginning` source
  sends the whole file again. `beginning` is for tests and one-off imports.

Each event carries the parsed line in `data` and, in `metadata`, the source's
name (`log_source`), the file the line came from (`log_file`: for a pattern,
the file that matched) and the `format`.

### What a source can read

Every line of every file a source matches is sent to Wildbox, where every
member of the sensor's team can read it. `log_sources` is therefore the list
of files the sensor may send, and the configuration file is the only place
that sets it: no environment variable does, and the local API cannot change
the configuration (`PUT /api/v1/config` answers 501).

A source is confined to the directory its path names, up to the first
wildcard: `/var/log/nginx` for `/var/log/nginx/*.log`, `/var/www` for
`/var/www/*/logs/access.log`. The forwarder resolves each file and reads it
only if it is a regular file inside that directory, then opens it without
following links, so a link placed in a log directory (`evil.log ->
/etc/shadow`, or a linked subdirectory) is reported and never read, whoever
the sensor runs as. A link to a file in the same directory (`current.log ->
app-1.log`) is read, once. Logs that are links to another directory, such as
Kubernetes' `/var/log/containers/*.log`, are not read: name the directory
they point to.

**In the container** a path is the container's, and the compose files mount
no host log. The sensor process, uid 999 and not root, can read:

- the image's own files, which hold no host log;
- its configuration, `/etc/security-sensor/config.yaml`, read-only;
- the `sensor_logs` volume (`/var/log/security-sensor`, its own log) and the
  `sensor_data` volume (`/var/lib/security-sensor`);
- `/host/proc/stat`, `/host/proc/meminfo`, the host's load average file under
  `/host/proc` and `/host/sys/class/net`, read-only;
- in the root `docker-compose.yml`, the gateway's certificate in
  `/etc/ssl/wildbox`, read-only.

To forward a host log, mount its directory read-only and name the mounted
path, in a `docker-compose.override.yml` next to the compose file:

```yaml
services:
  sensor:
    volumes:
      - /var/log/nginx:/host/var/log/nginx:ro
    # only if the files are not world-readable: the group that may read them
    # on the host (stat -c %g /var/log/nginx/access.log; adm is 4 on Debian)
    group_add:
      - "4"
```

```yaml
log_sources:
  - name: nginx_access
    path: /host/var/log/nginx/access.log
    format: nginx
```

Mount the narrowest directory that holds the logs: a source can only match
what is mounted, so the mount is the outer limit of what a mistaken pattern
can send. Do not mount `/var/log` whole unless everything in it may leave
the host, and never `/`.

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
redirects with it, and never logs it.

### When the gateway takes nothing

Processed events wait in the sender's buffer, serialized, until the gateway
answers for them. A batch is the oldest events: at most `batch_size` of them
and 8 MiB, which the gateway's 10 MiB request limit admits. It is sent when
it is full, or `flush_interval` seconds after its first event.

| The gateway answers | What happens to the batch |
| :--- | :--- |
| 200 or 201 | It leaves the buffer; `events_forwarded` counts its events |
| A network error, 429 or 5xx | It stays in the buffer, whole and in its place, and is sent again after `retry_delay` seconds, then twice as long after each further failure, up to `retry_max_delay` (each delay up to a fifth shorter, so that sensors do not return together). After a 429 the delay is at least the answer's `Retry-After`, or 10 seconds. No number of attempts gives it up |
| Any other 4xx, or a redirect | It is dropped, and `events_dropped_refused` counts its events: sent again it would get the same answer, and hold back everything collected after it |

The buffer holds at most `buffer_max_events` events and `buffer_max_bytes`
bytes of serialized events (5,000 and 16 MiB by default), and each of the two
queues before it at most `performance.max_queue_size` events. The sensor
drops nothing to make room: when the buffer is full it stops taking events,
the queues fill, and the collectors wait. It logs a warning when that
happens and when it ends, and `data_forwarder.buffer.full` says so
meanwhile. What waiting means for each collector:

- a log source goes on, later, from where it stopped: nothing is lost unless
  the log is rotated away meanwhile;
- the file monitor compares with what it last saw when it scans again, so a
  change is reported late, and a change undone meanwhile is not reported;
- osquery's periodic queries are not run meanwhile: what they would have
  shown is not collected.

An event leaves the sensor unsent, and is counted, in these cases only:

| Counter | When |
| :--- | :--- |
| `events_dropped_refused` | The gateway refused its batch, as above |
| `events_dropped_oversize` | Serialized, it is larger than a batch may be (8 MiB, or `buffer_max_bytes` if that is less) |
| `events_dropped_unserializable` | JSON cannot carry it (a value that is not text, a number, a list or a mapping; NaN) |
| `events_dropped_unconfigured` | No API key is set: everything collected is discarded |
| `events_dropped_shutdown` | It was still in the buffer when the sensor stopped. The sensor first spends up to 10 seconds sending what it holds |

`events_dropped` is their sum, and `events_received` equals
`events_forwarded` plus `events_dropped` plus the events in the buffer. The
counters, the buffer's fill and bounds and the time of the next attempt are
under `data_forwarder` in `GET /api/v1/components`. The sensor logs each
refused batch, each oversize or unserializable event, and once a minute the
number of events dropped since the last such line, by reason.

`data_lake.retry_attempts` is no longer read: the sensor says so at start-up
when the configuration still sets it.

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
  the `/proc` load average file and `/sys/class/net`. No host log is mounted:
  the log forwarder reads a host log only after its directory is mounted on
  purpose (see [What a source can read](#what-a-source-can-read)).
- The log forwarder reads the files `log_sources` lists and nothing else,
  regular files only, and follows no link out of a source's directory.
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
