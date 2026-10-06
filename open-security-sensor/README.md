# Open Security Sensor

An osquery-based endpoint agent that collects host telemetry and sends it,
through the Wildbox gateway, to the data service of its team (see
[Sending telemetry to Wildbox](#sending-telemetry-to-wildbox)).

## Overview

The sensor runs as a single Python process (`main.py`) that starts these
components (`sensor/core/agent.py`):

- **osquery manager** (`sensor/collectors/osquery_manager.py`): runs built-in
  query packs through `osqueryi` (the running processes, the open sockets, the
  logged-in users, system inventory) and one-off queries for the local API. See
  [What osquery collects](#what-osquery-collects).
- **File monitor** (`sensor/collectors/file_monitor.py`): polls the configured
  paths and reports created, modified and deleted files, with a SHA-256 hash for
  regular files under 10 MiB, against a baseline that outlives a restart. See
  [File integrity monitoring](#file-integrity-monitoring).
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
`Dockerfile` (osquery 5.23.1, amd64 or arm64). There are no native installer
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
`config.yaml.example` and publishes `127.0.0.1:8004`. The sensor is its only
service:

```bash
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
| `--status` | Asks the running sensor's local API and prints what it answers; see below |
| `--debug` | Enable debug logging |
| `--version`, `-v` | Print the version and exit |

`--status` asks the local API of the sensor this configuration describes
(`network.bind_address`, or the loopback address when that is every
address, and `network.bind_port`): `GET /health`, then, with
`network.api_key` set, `GET /api/v1/stats` for what it has collected,
delivered and dropped and whether it is delivering. Its exit status is the
answer:

| Exit status | Meaning |
| :--- | :--- |
| `0` | A sensor answers and is running. That it is `NOT delivering to the data service`, and since when, is printed, not signaled |
| `1` | No sensor answers, the one that answers is starting or stopping, or the configuration does not load |
| `2` | It cannot be told: the local API is off (`network.enable_api: false`), or what answers is not a sensor |

```bash
docker compose exec sensor python main.py --config /etc/security-sensor/config.yaml --status
```

The two requests go to that address only: no proxy from the environment is
used and no redirect is followed, and the key is not printed.

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
  rate_limit_share: 0.5      # of the team's request budget at the gateway

# Telemetry Collection
collection:
  process_events: true        # the processes running: see "What osquery collects"
  network_connections: true   # the sockets they hold open
  file_monitoring: true
  user_events: true           # the users logged in
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
  query_interval: 10        # seconds between two osquery cycles
  inventory_interval: 3600  # and between two runs of the inventory queries
  max_memory_mb: 128    # thresholds of a warning and of over_limits in the
  max_cpu_percent: 5    # statistics: nothing is limited or slowed down
```

The `logging` section configures the sensor's own log:

```yaml
logging:
  level: "INFO"      # DEBUG, INFO, WARNING, ERROR or CRITICAL
  file: null         # also write it to this file, rotated
  max_size: 10485760 # bytes before the file is rotated
  backup_count: 5    # rotated files kept
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

`format` is a %-style format of Python's `logging` module and must contain
`%(message)s`. The sensor checks these settings when it starts, by applying
the format to a record, and stops with a message naming the one at fault:
`format: json`, a field no log record has, or a level such as `VERBOSE`.

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
| `SENSOR_DATA_DIR` | `data_dir` |
| `SENSOR_PERFORMANCE_MAX_MEMORY` | `performance.max_memory_mb` |
| `SENSOR_PERFORMANCE_MAX_CPU` | `performance.max_cpu_percent` |
| `SENSOR_API_KEY` | `network.api_key` |

The HTML route list at `/` and `/docs` is served only when
`ENVIRONMENT=development`. `docker-compose.yml` in this directory sets no
`ENVIRONMENT`, so the two paths answer 404 there.

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
| `type` | `file` | `file`, `journald` (Linux, runs `journalctl --follow`), `windows_event` (Windows; see [Windows event logs](#windows-event-logs)) or `unified_log` (macOS, runs `log stream`); see [The journal and the unified log](#the-journal-and-the-unified-log) |
| `path` | Required for `file` | Absolute path of a file, or a pattern with `*`, `?` and `[...]`. `**` is not supported, and a pattern must name the directory it reads (`/*.log` is refused) |
| `format` | `raw` | For `file`: `syslog`, `nginx`, `apache` or `raw`. A line the format does not match is forwarded as `raw_message` only |
| `enabled` | `true` | `false` keeps the entry and does not read it |
| `read_from` | `end` | For `file`, where to start in a file that exists the first time the sensor sees the source: `end` forwards only what is written afterwards, `beginning` also what it already holds. Later starts go on from the saved position (see [Read positions and restarts](#read-positions-and-restarts)) |
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
about a path that does not exist, watches it once it appears, and says when
it watches nothing; and the sensor stops for a configuration it cannot use.

The sources, the files each one is reading, how far each file has been read
and accepted, and each source's current problems are in
`GET /api/v1/components` under `log_forwarder`; the configured list is in
`GET /api/v1/config`.

### How a file is followed

- The first time the sensor sees a source, a file that exists is read from
  its end (or its beginning, with `read_from: beginning`). A file that
  appears later, alone or as a new match of a pattern, is read from its
  beginning. Patterns are expanded every 5 seconds, files are checked every
  second. A source the sensor has seen before goes on where it stopped: see
  [Read positions and restarts](#read-positions-and-restarts).
- **Rotation.** When the path names another file (`logrotate` renamed the old
  one), the old file is read to its end, including a last line without a
  newline, and then the new one from its beginning. If the pattern also
  matches the rotated name (`access.log*`), the file is followed under its
  new name and not sent again. A file truncated in place (`copytruncate`) is
  read again from its beginning. The sensor notices by its size or, when it
  has already grown past the old position, by its content: its first 256
  bytes, or the 64 bytes before that position, are no longer what was read.
  A file rewritten to at least its old length with both unchanged (the same
  header, and the same 64 bytes at the same offset) cannot be told from one
  that was appended to: the sensor reads on from the old position.
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

Each event carries the parsed line in `data` and, in `metadata`, the source's
name (`log_source`), the file the line came from (`log_file`: for a pattern,
the file that matched) and the `format`.

### Read positions and restarts

With `data_dir` set, the sensor keeps, for every file of every file source,
the offset after the last line **the data service accepted**, and goes on
from there when it starts again:

```yaml
data_dir: /var/lib/security-sensor   # or SENSOR_DATA_DIR
```

- A line written while the sensor was down is sent when it starts; a line
  already accepted is not sent again. `read_from` applies only the first
  time the sensor sees a source: a name it has no saved position for, or a
  name whose `path` has changed.
- The offset moves when the gateway has answered for a line's batch, not
  when the line is read. Lines still in the sensor when it stops, or is
  killed, are read again at the next start: a gateway outage that outlasts
  the sensor loses nothing. A line the sensor dropped for good (its batch
  was refused with a 4xx, or no API key was set) counts as done.
- The position is written to `<data_dir>/log-positions.json` at most once a
  second while it moves, and when the sensor stops. A sensor that is killed
  therefore sends again the lines accepted since the last write: delivery is
  at least once, and after an orderly stop exactly once.
- An orderly stop is SIGTERM or SIGINT. The sensor then stops its
  collectors, gives what they had collected up to 2 seconds to reach the
  sender, spends up to 10 seconds sending what its buffer holds, writes the
  positions and only then exits. It does not wait the 2 seconds out: each
  of the two queues counts an event from the moment it is put there until
  its reader has finished with it, and the wait ends when both counts are
  at zero. An event that has not reached the sender by then (the buffer is
  full, or a reverse DNS lookup is still running) is not sent: the
  processor's workers are stopped with what they hold, and the last log
  lines say how many events that was, and how many of them will be read
  again from their log source. That count includes the event a collector
  was waiting to put on a full queue when it was stopped.
- The stop may be asked for at any moment, the sensor's start included.
  Before anything is started, nothing is, and the sensor says `not
  started: a stop was asked for while it was starting`; while it is
  starting (a first scan of the watched files, an `osqueryi` that takes
  its time), the start is abandoned and what it had started is stopped.
  The exit status is 0 in every case.
- In its container the sensor is process 1, to which the kernel delivers
  no signal it has no handler for. The handlers are the first thing
  `main.py` installs, before it imports anything else, and the image
  starts it with SIGTERM and SIGINT blocked (`env --block-signal` in its
  `CMD`), so that a stop sent earlier still, while Python itself is
  starting, is kept until then and obeyed. A `command:` or an image of
  your own that runs `python main.py` directly leaves those first
  milliseconds uncovered: a `docker stop` that falls in them is not
  received, and the container is killed when its grace period ends. Keep
  `env --block-signal=TERM --block-signal=INT` in front of it.
- Each part of the stop has a limit: 2 seconds for a start that was
  abandoned, 8 for the collectors to stop, the 2 above, 12 for the
  processor and the sender (10 of them for the last batches); then the
  positions and the baseline are written; then 2 for the process to end.
  That is 26 seconds at the very worst. A worker thread that is still busy when the sensor has stopped (a name
  lookup the resolver has not answered, a scan in a file system that does
  not answer) is not waited for beyond those last 2 seconds: the sensor
  says which threads, and the process ends. The compose files give the
  sensor 30 seconds (`stop_grace_period`), and the sensor's tests fail if
  that stops being enough; give it at least as much wherever else you run
  it (`docker run --stop-timeout 30`, `terminationGracePeriodSeconds` in
  Kubernetes). Under Docker's default of 10 it can be killed before it has
  finished, which costs a second sending of the last lines, never a line.
- The file holds, for each log file, its device and inode, the offset, and
  SHA-256 digests of its first 256 bytes and of the 64 bytes before the
  offset; no log content. It is written to a temporary file, flushed, and
  renamed over the old one. At most 128 files are remembered per source:
  those being read and the most recently read others.
- A saved position is used only for the file it was taken from: same device
  and inode, at least as long as the offset, same digests. Otherwise the
  file is read from its beginning, as a file that appeared: a log rotated,
  truncated or rewritten while the sensor was down is read whole. A file
  removed while the sensor runs leaves no position behind.
- The saved file itself is not trusted. It must be a regular file of the
  sensor's user, not a link, at most 4 MiB, and hold only values of the
  types and ranges the sensor writes; anything else and the whole file is
  ignored, with a warning that says why, and every source starts as its
  `read_from` says.

What a saved position cannot do:

- When a log is rotated while the sensor is down and the source does not
  match the rotated name, what was appended to the old file after the last
  accepted line is not read. A pattern that also matches it (`access.log*`)
  reads the rest of the old file and the new one.
- A file removed and created again while the sensor is down, under the same
  inode, at least as long as the saved offset and with the same bytes at
  both places compared, is taken for the old one.

`data_dir` must exist and be writable by the sensor's user, or the sensor
stops at start-up with a message that says so. One sensor per directory.
Without `data_dir` positions are kept in memory only, the sensor says so
when it starts, and after a restart every source starts as its `read_from`
says: `end` skips what was written meanwhile, `beginning` sends everything
again. The shipped container configurations set it to the `sensor_data`
volume; `config.yaml`, for a host, leaves it unset. If a write fails (a full
disk), the sensor logs it once, reports it under `log_forwarder.positions`
in `GET /api/v1/components`, and tries again every second.

### The journal and the unified log

A `journald` source runs `journalctl --follow --output=json` and a
`unified_log` source runs `log stream --style ndjson`; each line the command
prints is an entry, forwarded as an event of type `log.<name>` with the
entry's fields in `data`.

- **Long entries.** An entry up to 256 KiB is forwarded whole. A longer one
  is forwarded once, as the first 16 KiB of its text in `data.raw_message`,
  with `metadata.truncated: true`; the rest is discarded as it arrives, so
  the memory the reader holds does not depend on what is logged. A line that
  is not a JSON object is counted (`entries_unparsed`) and passed over.
- **The command's standard error** is read as it is written and its last 512
  bytes are kept: they are in the warning logged when the command ends, and
  in the source's `last_error`.
- **A command that ends** is started again after 1 second, then 2, 4 and so
  on up to 5 minutes; after a run of a minute or more the delay starts over
  from 1 second. A command that is not installed is reported once and not
  tried again (`state: unavailable`).
- **Where the journal is followed from.** The first time, from now on
  (`--lines=0`). When `journalctl` is started again, after the last entry
  read (`--after-cursor`), so nothing is skipped or read twice. With
  `data_dir` set, the cursor of the last entry the data service accepted is
  saved with the file positions, and a restarted sensor goes on from it. If
  `journalctl` fails three times in a row from a saved cursor (it refuses
  one it cannot parse), the sensor gives the cursor up, says so, and
  follows the journal from now on. Given a cursor the journal no longer
  holds, `journalctl` goes on from the nearest entry it has, which can send
  entries again. `journalctl` 257 follows the current boot only: after a
  reboot, what the previous boot logged after the sensor stopped is not
  read.
- **The unified log has no position.** `log stream` shows what is logged
  while it runs: entries logged while the sensor is stopped, or while the
  command is being started again, are not read, and an entry still in the
  sensor when it stops is counted under `events_dropped_shutdown`.

Each source that is not a file reports, under `log_forwarder` in
`GET /api/v1/components`, its `state` (`starting`, `running`, `restarting`,
`failing` for an event log whose last query failed, `unavailable`, `skipped`
on a platform that has no such log, `stopped`), `restarts`, `last_exit`,
`last_error` and the counters `entries_forwarded`, `entries_truncated` and
`entries_unparsed`; a `journald` source also its `accepted_cursor`, a
`windows_event` source its `read_record_id` and `accepted_record_id`.

The `journald` reader was checked against the real `journalctl` (systemd
257) in a container, on journal files written with `systemd-journal-remote`:
entries of 120 kB and 360 kB, the command killed, the sensor restarted, a
malformed cursor. It was not run against a live `systemd-journald`. The
`unified_log` reader was run against `log stream` on macOS 26. Neither runs
in CI, where a script plays the command, and the Docker image contains
neither command.

### Windows event logs

A `windows_event` source asks its log (`log_name`), every 30 seconds, for the
events after the last record id it read, oldest first, at most 50 at a time;
when a query returns 50 it asks again at once. Each event is forwarded once,
as an event of type `log.<name>` with `RecordId`, `Id`, `Level`,
`ProviderName`, `MachineName`, `TimeCreated` and `Message` in `data`; a
message longer than 16 KiB is cut and marked `metadata.truncated`.

- The first time, the log is followed from its newest event on. With
  `data_dir` set, the record id of the last event the data service accepted
  is saved with the other positions, and a restarted sensor goes on from it.
- The query is a PowerShell command (`Get-WinEvent`) run in a worker thread,
  with a 30-second limit: the rest of the sensor does not wait for it.
- A log whose newest record id is lower than the last one read was cleared:
  the sensor says so and reads it from its beginning.
- A query that fails, or prints anything but what the command is written to
  print, forwards nothing; the source's `state` is `failing`, its
  `last_error` says why, the failure is logged once, and the log is asked
  again every 30 seconds from the same record id.

**Not run on Windows.** The reader's logic (the record id kept, the order,
the cleared log, failures, the saved position) is tested with the query
replaced by a stand-in. The PowerShell text was run in PowerShell 7 on Linux
with a stand-in for `Get-WinEvent`, which checks its syntax, its handling of
an empty answer and the JSON it prints, and nothing more: what the real
`Get-WinEvent` returns, Windows PowerShell 5.1, the rights the sensor's
account needs to read the `Security` log, and how record ids behave when a
log is cleared were not checked on a Windows host.

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
  `sensor_data` volume (`/var/lib/security-sensor`, where it keeps its read
  positions);
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

## What osquery collects

Every `performance.query_interval` seconds (10 by default) the sensor runs
the queries of the enabled packs through `osqueryi`, one at a time, and sends
each answer that has rows as one event, of type `<pack>.<query>`. The
queries of the `system_inventory` pack run when the sensor starts and then
every `performance.inventory_interval` seconds (3600 by default), each
counted from its own last answer; one that fails is asked again at the next
cycle. Set it to 0 to run them at every cycle:

| Setting under `collection` | Pack | Queries |
| :--- | :--- | :--- |
| `process_events` | `process_events` | `process_tree`: the running processes, with their user |
| `network_connections` | `network` | `process_open_sockets`: the open sockets, with their process |
| `user_events` | `user_events` | `logged_in_users`; on Linux `sudoers` |
| `system_inventory` | `system_inventory` | `system_info`, `os_version`, `installed_applications`, `startup_items`, `system_services`; on Linux `kernel_info`, `kernel_modules` |

Each answer is a picture of the host at the moment of the query. The sensor
collects no stream of events from osquery, whatever the settings are called:
a process that starts and ends between two cycles, or a connection opened
and closed between two, is not seen. osquery's event tables
(`process_events`, `socket_events`, `user_events`) are not queried: through
`osqueryi`, in the sensor's image, they answer no row and say `is
event-based but events are disabled`. The sensor starts no `osqueryd`, and
its image has none to start: no `osqueryd` on the `PATH`, no `osqueryctl`,
no init script. The file `/opt/osquery/bin/osqueryd` is still there because
it is the one binary of the package, and `osqueryi` is a link to it. On
Windows the pack no longer has `logon_events`: it read `windows_events`,
which is an event table too, and filtered on a `channel` column that table
does not have. Read logons with a log source of type `windows_event` on the
`Security` log (see [Windows event logs](#windows-event-logs)).

The inventory is not asked at every cycle because it does not change at
that pace and is the bulk of what a cycle produces: in the sensor's image
its seven answers were 36.0 of a cycle's 36.9 kB, and six of them were
identical ten seconds later.

In the container the pictures are the container's: its own processes and
sockets (see [Security notes](#security-notes)).

Without `osqueryi` on its `PATH`, or with one that does not answer a first
query, the sensor does not start while any of the four settings is on.
`osquery_manager` in `GET /api/v1/components` reports the `osqueryi` found
and its `osquery_version`, the packs, and `queries_run`, `queries_failed`
and `last_error` since the sensor started.

## File integrity monitoring

With `collection.file_monitoring` and `fim.enabled` on, which is the default,
the file monitor scans the paths listed under `fim.paths` every 60 seconds
and reports what changed since the scan before: `file_created`,
`file_deleted`, and `file_modified` with the list of what changed (`size`,
`mtime`, `permissions`, `owner`, `group` and, for a regular file under 10
MiB that the sensor can read, `content`, from its SHA-256). The first scan
of a path is its baseline and reports nothing.

A scan walks the paths and reads the files in a worker thread, so the rest
of the sensor goes on meanwhile. It reads regular files only (a FIFO, a
socket or a device is watched by its mode, owner and times), never more
than 10 MiB of one, and it watches at most `fim.max_files` files, all paths
together (50,000 by default; about 700 bytes of memory each). Beyond that
number files are not watched: the monitor logs it once and reports
`files_over_limit`. A file that comes under watch when room is made is
reported as created.

```yaml
fim:
  enabled: true
  paths:
    - "/etc"
    - "/usr/bin"
  exclude_patterns:
    - "*.tmp"
  max_depth: 10
  max_files: 50000
```

`fim.paths` are the sensor's own paths, absolute; anything else stops the
sensor at start-up, and so do `exclude_patterns` that are not a list of
patterns, a `max_depth` that is not a whole number from 0 to 1000 and a
`max_files` that is not one from 1 to 1,000,000. Whether a path exists does
not:

- A path that does not exist is a warning that names it when the monitor
  starts. It is watched from the scan at which it appears, with what it
  holds then as its baseline.
- When none of the paths exists, the monitor logs `File integrity
  monitoring is enabled and none of the N paths in fim.paths exists: it is
  watching nothing`, and its status says `watching: false`.
- A watched path that disappears is a warning, once; when it is back, what
  changed meanwhile is reported.

`file_monitor` in `GET /api/v1/components` reports `watching`,
`configured_paths`, `monitored_paths`, `missing_paths`, `tracked_files`,
`unhashed_files`, `max_files`, `files_over_limit`, `scan_count`,
`last_scan_duration` and `baseline`.

### The baseline and restarts

With `data_dir` set, the monitor keeps its baseline in
`<data_dir>/fim-baseline.json`: for each watched file its size, times, mode,
owner, group and SHA-256, and no content. When the sensor starts it compares
the files with that baseline, so what was created, modified or deleted
while it was stopped is reported by its first scan, and the log says how
many changes that was. A path that is new to the configuration has no
baseline: what it holds is taken as it is.

The baseline is what the data service has been told, not what the monitor
last saw. A file's entry moves when the event that reports its change is
accepted by the gateway, or dropped for good and counted (see
[When the gateway takes nothing](#when-the-gateway-takes-nothing)). So:

- a change found while the gateway is away, and still unsent when the
  sensor stops, is found again by the next start and reported then;
- if the queue is full when the sensor starts (the gateway has been away
  for a while), the changes of that first scan are handed over as it
  empties: the sensor does not wait for room to finish starting;
- the changes a scan found stay in line until the event of each is queued.
  A sensor stopped while they wait says how many there were (`stopped with
  N changes found and not queued yet`): they are found again at the next
  start, and without `data_dir` they are not reported at all, which the
  line says too. A change no event can be made of is logged with its path
  and counted under `changes_failed` in the monitor's status; the changes
  behind it are queued, and it stays out of the saved baseline;
- a change delivered in the sensor's last seconds whose baseline was not
  written (a crash, a full disk) is reported again: the same change can
  arrive twice, and is never lost for that reason.

The file is written at most every 5 seconds while the baseline moves, and
when the sensor stops, the way the position file is (a temporary file,
flushed, renamed over the old one). It is read once, at start, and not
trusted: a file that is not a regular file of the sensor's user, that is
not what this sensor writes down to the type of each value, or that names a
file outside its own paths, is ignored whole, with a warning. So is a
baseline taken with other `exclude_patterns`, `max_depth` or `max_files`:
compared with it, every file that entered or left what is watched would be
a change that never happened. In both cases the monitor does what it does
without a file: it takes what it finds as the baseline, and what changed
meanwhile is not reported. `baseline` in the monitor's status says which
file is used, what became of the one found at start (`loaded`), when it was
last written, why it could not be (`problem`), and how many changes are
found and not delivered yet (`changes_not_delivered`).

Without `data_dir` the baseline is in memory only, as it always was: the
status says so, and what changes while the sensor is stopped is not
reported. The shipped container configurations set `data_dir` to the
`sensor_data` volume.

**In the container** the shipped configuration lists `/host/etc`,
`/host/bin`, `/host/usr/bin` and `/host/opt`, and no compose file mounts
them: as shipped, the monitor is on and it is watching nothing. That is
deliberate. A read-only mount of the host's `/etc` gives the sensor's
process, and whatever takes it over, every world-readable file of the
host's configuration, so it is the operator's choice. To watch host
directories, mount them read-only in a `docker-compose.override.yml` next to
the compose file:

```yaml
services:
  sensor:
    volumes:
      - /etc:/host/etc:ro
      - /usr/bin:/host/usr/bin:ro
```

and keep in `fim.paths` only what you mounted. The sensor runs as uid 999
with no capability, so it reads what that user may read:

- a file it cannot read, such as the host's `/etc/shadow`, is still watched
  by its size, modification time, mode and owner, but not hashed: a change
  that keeps the size and restores the time is not seen. `unhashed_files`
  counts them;
- do not add the sensor to a group to make such files readable: the group
  that reads `/etc/shadow` reads every password hash.

What the monitor does not do: it polls, so a file created and deleted
between two scans is never seen, and a file changed twice between two is one
change; and it does not go into a directory that a symbolic link points to.
A link to a file is watched as the file it points to, wherever that is. A
directory the sensor cannot list is skipped, and what it held is neither
changed nor deleted for the monitor until it can be listed again.

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
`data:ingest` scope. The running sensor reads the same answers the same way:
see [When the gateway takes nothing](#when-the-gateway-takes-nothing).

The sensor sends the key in the `X-API-Key` header only, does not follow
redirects with it, and never logs it.

### When the gateway takes nothing

Processed events wait in the sender's buffer, serialized, until the gateway
answers for them. A batch is the oldest events: at most `batch_size` of them
and 8 MiB, which the gateway's 10 MiB request limit admits. It is sent when
it is full, or `flush_interval` seconds after its first event, and the next
one as soon as the gateway has answered: see
[How fast a sensor delivers](#how-fast-a-sensor-delivers).

An answer is read for what it says. Only an answer about the events
themselves costs events; one that says the sensor is not allowed, not now,
or not at the right address keeps the batch, as an outage does.

| The answer | It means | What happens to the batch |
| :--- | :--- | :--- |
| 200 or 201 | Stored, every event of it: the data service stores a batch whole or answers an error | It leaves the buffer; `events_forwarded` counts the events the data service says it stored (`events_ingested`) |
| A network error, 5xx | The gateway, identity or the data service is unreachable, or the data service could not store the batch (`unavailable`) | It stays in the buffer, whole and in its place, and is sent again after `retry_delay` seconds, then twice as long after each further failure, up to `retry_max_delay` (each delay up to a fifth shorter, so that sensors do not return together). No number of attempts gives it up |
| 429 | The team's request budget, or nginx's limit per address (`rate_limited`) | Kept, as above; the delay is at least the answer's `Retry-After`, or 10 seconds |
| 401, or the gateway's 400 `invalid_token` | The key is invalid, expired or revoked (`unauthorized`) | Kept, as above |
| 403 | The key lacks the `data:ingest` scope, its member left the team or has not changed the initial password (`forbidden`) | Kept, as above |
| A redirect, 404, another 4xx | The request did not reach the ingest route (`misconfigured`) | Kept, as above |
| 413, 422, the data service's 400 | The payload is not acceptable: the batch is too large, or the data service refuses one of its events | The batch is split in halves, each sent in its turn, until the event at fault is alone: that one is dropped and counted in `events_dropped_refused`, the others are delivered. A batch refused for its size is delivered in parts and loses nothing |

The data service answers each of these for one reason, listed with the
route in the [data API reference](../docs/api/data/endpoints.md#post-apiv1dataingest),
and `tests/shared/ingest_answer_vectors.json` holds its answers for the
tests of both services. A data service of release 0.11 or earlier could also answer
200 for a batch it had stored a part of, or none of. The sensor still reads
the count: events such an answer does not count are counted as dropped,
and a 200 that stored nothing is taken for a refusal of the batch.

While batches are kept the sensor is **not delivering**, and says so:

- an error in its log when it begins, `Not delivering since <time> (HTTP 401
  invalid_token: ...)`, with what to do about it, and a line when it is
  over;
- `data_forwarder.delivery` in `GET /api/v1/components`: `state` (`ok`,
  `unavailable`, `rate_limited`, `unauthorized`, `forbidden`,
  `misconfigured`, or `unconfigured` without a key), `since` and `reason`;
- `delivery_state` and `delivery_since` in `GET /api/v1/stats`, and an alert
  in `GET /api/v1/dashboard/metrics`.

Nothing is dropped meanwhile, and no log position moves: with a revoked key
the sensor keeps what it collects, then stops collecting when its buffer is
full, and delivers every line once after it is restarted with a valid key.

Splitting a refused batch is bounded: after 64 requests spent on one batch,
what is left of it is dropped whole, with an error that says how many
events. Finding one unacceptable event among 100 takes about 14.

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
| `events_dropped_refused` | The data service refused the event itself, as above |
| `events_dropped_oversize` | Serialized, it is larger than a batch may be (8 MiB, or `buffer_max_bytes` if that is less) |
| `events_dropped_unserializable` | JSON cannot carry it (a value that is not text, a number, a list or a mapping; NaN), or making it into what is sent failed with any other error, which the log line names |
| `events_dropped_unconfigured` | No API key is set: everything collected is discarded |
| `events_dropped_shutdown` | It was still in the buffer when the sensor stopped. The sensor first spends up to 10 seconds sending what it holds. Events that had not reached the buffer by then (a full buffer kept them in the queues, in the processor's hands, or in a collector that was waiting for room on the first queue) are in no counter: the sensor's last log lines say how many there were |

`events_dropped` is their sum, and `events_received` equals
`events_forwarded` plus `events_dropped` plus the events in the buffer. The
counters, the buffer's fill and bounds and the time of the next attempt are
under `data_forwarder` in `GET /api/v1/components`. The sensor logs each
refused batch, each oversize or unserializable event, and once a minute the
number of events dropped since the last such line, by reason.

`data_lake.retry_attempts` is no longer read: the sensor says so at start-up
when the configuration still sets it.

### How fast a sensor delivers

The sender sends one batch at a time and the next one when the gateway has
answered, at least 20 ms after the previous request. What limits it is the
gateway:

- nginx admits 100 requests a second from one address; 20 ms between
  requests keeps a sensor at half of that.
- The gateway counts every request of a **team** against one budget,
  `RATE_LIMIT_PER_HOUR` (10,000 by default), enforced per minute: 166
  requests a minute for the team's dashboard sessions and all its keys
  together, after which all of them get 429 until the minute ends. Each
  answer states what is left (`X-RateLimit-Remaining`). The sensor uses
  `data_lake.rate_limit_share` of it, half by default: when what is left of
  the minute's budget falls to the other half, it waits for the next minute.
  Sensors of the same team share that half between them.

With the defaults a team's sensors deliver about 83 batches a minute:
**8,300 events a minute, about 140 a second**, with `batch_size: 100`. To
deliver more, raise `batch_size` (the data service takes up to 1,000 events
in a batch, about 1,400 events a second; a larger value is split by the
sender when the data service refuses it), raise `RATE_LIMIT_PER_HOUR` on the
gateway, or give the sensor a larger `rate_limit_share`.

Above that rate the buffer fills, the queues fill and the collectors wait.
A burst is delivered later, in order. A log that is written faster than the
sensor delivers for a long time falls further and further behind, and what
it has not read is lost when the log is rotated away: `log_forwarder` in
`GET /api/v1/components` shows, for each file, how many bytes are waiting
to be read (`behind`), and `data_forwarder.pacing` the budget the gateway
last stated and whether the sender is waiting for the next minute.

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

Before it sends an event the sensor adds to `data`, by the event's type and
nothing else: a `connection_category` and address information to the rows of
osquery's `network.*` queries; a `process_category`, `risk_indicators` and
the parsed command line to the rows of its `process_events.*` queries, from
which it also removes kernel threads and `systemd`, `dbus` and similar
processes; a `file_category` and `risk_level` to the file monitor's
`file_created`, `file_modified` and `file_deleted` events. A log line is
never changed, whatever its source is named.

### Revoking a sensor

Revoke its key (**Settings > API keys**, or
`DELETE /api/v1/identity/api-keys/<prefix>`) or remove its member from the
team. The gateway refuses the key on the sensor's next batch, with no cache
delay. The sensor then reports `unauthorized` (or `forbidden`), keeps what
it has collected and stops collecting when its buffer is full; it discards
nothing. To bring it back, give it a valid key and restart it.

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
| `POST` | `/api/v1/query` | Run an osquery query, body `{"query": "..."}`; see below |
| `GET` | `/api/v1/queries` | Names of the loaded query packs and the query count |
| `GET` | `/api/v1/components` | Status of each component |
| `GET` | `/api/v1/stats` | The sensor's counters; see [Statistics](#statistics) |
| `GET` | `/api/v1/dashboard/metrics` | A summary of this endpoint, from the same counters |
| `POST` | `/api/v1/test-connection` | POST an empty test batch to `data_lake.endpoint` |

An osquery query, from this route or from the sensor's own packs, is one
`osqueryi` child process the sensor waits for without stopping anything
else. Queries run one at a time. One may take 30 seconds and print 16 MiB:
past either it is killed, the sensor logs which, and the query yields no
rows.

```bash
curl -H "X-API-Key: $SENSOR_API_KEY" http://127.0.0.1:8004/api/v1/status

curl -X POST http://127.0.0.1:8004/api/v1/query \
  -H "X-API-Key: $SENSOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT pid, name FROM processes LIMIT 5;"}'
```

### Statistics

`GET /api/v1/stats` reads its counters from the components that count them,
since the sensor started:

| Field | Meaning |
| :--- | :--- |
| `events_collected` | Events the collectors produced |
| `events_processed` | Events the processor passed on to the sender |
| `events_filtered` | Events the processor filtered out (no data, noisy system processes) |
| `events_forwarded` | Events the gateway accepted |
| `events_dropped` | Events that left the sensor unsent; the reasons are counted under `data_forwarder` in `GET /api/v1/components` |
| `events_in_pipeline` | Events waiting in the queues and in the sender's buffer, and those in hand between them: the ones the processor is working on, and the one the sender holds while its buffer is full |
| `errors` | Errors of the processor and of the sender (network errors, error answers of the gateway) |
| `last_activity` | When the last event was collected; `null` before the first |
| `uptime_seconds` | Seconds since the sensor started |
| `memory_mb`, `cpu_percent`, `over_limits` | The sensor's own process, as measured every 5 seconds; absent until the first measurement. `over_limits` is true while it uses more than `performance.max_memory_mb` or `performance.max_cpu_percent`, and for 30 seconds after: the sensor logs a warning and slows nothing down |
| `timestamp` | When the answer was made |

`events_collected` equals `events_forwarded` + `events_dropped` +
`events_filtered` + `events_in_pipeline`. An event that failed in the
processor is in none of the four: it is logged, and counted under `errors`
with the sender's.

`GET /api/v1/dashboard/metrics` answers `online_endpoints`, `alerts` (1 for
errors, 1 more while the sensor is over its resource limits), `last_activity`
and, under `endpoint_details`, the host name, the operating system, the
uptime, `cpu_percent`, `memory_mb` and the three event counters. It no
longer answers `disk_usage`, `network_connections`, `process_count`,
`cpu_usage`, `memory_usage`, `agent_version` or `trends_change`: the sensor
never measured them, and they were always zero or a constant.

## Security notes

- The container runs as the non-root `sensor` user (uid 999) with
  `no-new-privileges` and all capabilities dropped (`cap_drop: ALL`), in the
  root `docker-compose.yml` as in the standalone one. No collector needs a
  capability: in the built image, as uid 999, every osquery table the sensor
  queries, the file monitor, the log forwarder and the data volume behave
  the same with the default capability set and with none. What
  the sensor cannot do is a matter of its user, not of capabilities: it sees
  only the processes and sockets of its own container (the container does
  not share the host's PID or network namespace), and it reads only the
  files uid 999 may read.
- Host access is limited to read-only mounts of `/proc/stat`, `/proc/meminfo`,
  the `/proc` load average file and `/sys/class/net`. No host log is mounted:
  the log forwarder reads a host log only after its directory is mounted on
  purpose (see [What a source can read](#what-a-source-can-read)). No host
  directory is mounted for the file monitor either, which therefore watches
  nothing until one is (see
  [File integrity monitoring](#file-integrity-monitoring)).
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
