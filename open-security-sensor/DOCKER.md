# Docker Deployment Guide

How to run the Open Security Sensor with Docker Compose.

## As part of the Wildbox stack

The root `docker-compose.yml` defines the `sensor` service. Set
`SENSOR_API_KEY` in the root `.env` (compose refuses to start without it), then:

```bash
docker compose up -d sensor
curl http://127.0.0.1:8004/health
```

The root compose file already points the sensor at the gateway and mounts the
gateway's certificate from the `gateway_cert` volume; set
`SENSOR_DATA_LAKE_API_KEY` to start sending telemetry (see
[Connect to Wildbox](#connect-to-wildbox)).

## Standalone

`docker-compose.yml` in this directory runs the sensor on its own; it is the
only service in the file.

1. Start the sensor with a key for its local API:

   ```bash
   SENSOR_API_KEY=<key> docker compose up -d
   ```

2. Verify:

   ```bash
   curl http://127.0.0.1:8004/health
   curl -H "X-API-Key: <key>" http://127.0.0.1:8004/status
   ```

The image build reads `../open-security-shared` as an additional build context,
so run it from a full repository checkout.

### Ports and configuration

Both compose files, this one and the root one, mount `config.yaml.example` as
`/etc/security-sensor/config.yaml`. It binds the local API to `0.0.0.0:8004`
inside the container, and compose publishes that port on `127.0.0.1:8004` only.
To change the configuration, edit `config.yaml.example` or use the
`SENSOR_*` environment variables listed in [README.md](README.md#environment-variables).

### No monitoring profile

The sensor does not expose a `/metrics` endpoint, so there is nothing for a
Prometheus to scrape, and this file starts none. The Prometheus and
Alertmanager of the Wildbox stack are in the root `docker-compose.yml`
(`--profile monitoring`); they watch the services that do export metrics.

## Environment variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `SENSOR_API_KEY` | None; required | Key for every local API route except `/health` |
| `SENSOR_DATA_LAKE_ENDPOINT` | `data_lake.endpoint` from the file | The Wildbox gateway, `https://...` |
| `SENSOR_DATA_LAKE_API_KEY` | None | Identity API key with the `data:ingest` scope; without it forwarding is disabled |
| `SENSOR_DATA_LAKE_CA_BUNDLE` | None (system trust store) | PEM file for a gateway certificate no public CA signed |
| `SENSOR_LOGGING_LEVEL` | `INFO` | Log level |
| `PYTHONPATH` | `/app` | Python module path |

The standalone compose file passes the `SENSOR_DATA_LAKE_*` variables through
only when they are set in the shell.

## Connect to Wildbox

The sensor sends telemetry to the Wildbox gateway over HTTPS, with an identity
API key scoped to `data:ingest`; the gateway stores it under the key's team.
It never connects to the data service directly. Update `config.yaml`:

```yaml
data_lake:
  endpoint: "https://wildbox.example.com"
  tls_verify: true
  ca_bundle: "/etc/ssl/wildbox/wildbox.crt"  # if no public CA signed it
```

and pass the key in the environment:

```yaml
environment:
  - SENSOR_DATA_LAKE_API_KEY=${SENSOR_DATA_LAKE_API_KEY}
```

How to create the sensor's member and key, and how to check the connection,
is in [README.md](README.md#sending-telemetry-to-wildbox). Inside the Wildbox
stack itself the root `docker-compose.yml` already wires all of this.

## Volumes

| Mount | Purpose |
| :--- | :--- |
| `./config.yaml.example:/etc/security-sensor/config.yaml:ro` | Configuration |
| `sensor_logs:/var/log/security-sensor` | Sensor log file |
| `sensor_data:/var/lib/security-sensor` | Sensor state: the log forwarder's read positions (`data_dir`), so that a recreated container goes on where the last one stopped |
| `/proc/stat`, `/proc/meminfo`, the `/proc` load average file, `/sys/class/net` (read-only, under `/host`) | Host metrics |

The root `docker-compose.yml` also mounts the gateway's certificate,
`gateway_cert:/etc/ssl/wildbox`, read-only. The compose files do not mount
the host's `/proc`, `/etc`, `/var/log` or the Docker socket: this table is
everything of the host the container can read.

## Watching host files

File integrity monitoring is on in the shipped configuration, and its paths,
`/host/etc`, `/host/bin`, `/host/usr/bin` and `/host/opt`, are not mounted
by the compose files: the sensor logs that it is watching nothing, and
`GET /api/v1/components` shows `file_monitor.watching: false` with the four
paths under `missing_paths`. To watch a host directory, mount it read-only
in a `docker-compose.override.yml`:

```yaml
services:
  sensor:
    volumes:
      - /etc:/host/etc:ro
```

and keep in `fim.paths` what you mounted. The sensor reads the mount as uid
999: what that user cannot read is watched without a hash. See
[README.md](README.md#file-integrity-monitoring).

## Forwarding host logs

The log forwarder (`collection.log_forwarding: true`) reads the files listed
under `log_sources` in the configuration. In the container those are the
container's paths, and no host log is mounted, so with the shipped
configuration it forwards nothing: the default sources, `/var/log/syslog`,
`/var/log/auth.log` and the systemd journal, do not exist in the image.

To forward a host log, mount its directory read-only and name the mounted
path. In a `docker-compose.override.yml` next to the compose file you start:

```yaml
services:
  sensor:
    volumes:
      - /var/log/nginx:/host/var/log/nginx:ro
```

and in `config.yaml.example`, the file mounted as the configuration:

```yaml
collection:
  log_forwarding: true

log_sources:
  - name: nginx_access
    type: file
    path: /host/var/log/nginx/access.log
    format: nginx
```

Then `docker compose up -d sensor` and check what it reads:

```bash
docker compose logs sensor | grep "Log source"
```

- Every line of every file a source matches is sent to Wildbox and can be
  read by the sensor's team. Mount the narrowest directory that holds the
  logs you want: the mount is the limit of what a pattern can match. Do not
  mount `/var/log` whole unless all of it may leave the host.
- The container runs as uid 999, not as root, so it reads only files that
  user may read. For logs that are not world-readable (`640 root:adm` on
  Debian and Ubuntu), add the owning group's ID to the service with
  `group_add` (`stat -c %g /var/log/nginx/access.log` prints it). A file it
  may not read is a warning in the sensor's log, not an error.
- A source follows no link out of the directory its path names, and reads
  regular files only.

- The position reached in each file is kept in the `sensor_data` volume:
  after `docker compose up -d` recreates the container, or a restart, the
  sensor goes on after the last line Wildbox accepted. `docker compose down
  -v` removes the volume, and with it the positions: each source then starts
  as its `read_from` says. Do not share the volume between sensors;
  `docker-compose.scale.yml` does, so do not enable log forwarding with it.

The keys of `log_sources`, rotation, restarts, and what is a start-up error
or a warning are in [README.md](README.md#log-forwarding).

## Management

```bash
docker compose logs -f sensor
docker compose restart sensor
docker compose exec sensor id
docker compose down
```

## Container security

- Runs as the non-root `sensor` user.
- `no-new-privileges:true` and `cap_drop: ALL`; no capabilities are added and
  the container does not share the host PID namespace.
- Host mounts are read-only and limited to the files listed above.
- The local API is published on `127.0.0.1` only.

## Troubleshooting

- `required variable SENSOR_API_KEY is missing a value`: export
  `SENSOR_API_KEY` or add it to `.env`.
- `503 API authentication is not configured on this sensor`: the container
  started without `SENSOR_API_KEY` and no `network.api_key` in the
  configuration.
- `Security Sensor not started: ... log_sources[0] ('name'): ...`: the
  `log_sources` section has an entry the sensor cannot understand; the
  message says which and why. See [README.md](README.md#log-forwarding).
- `File integrity monitoring is enabled and none of the 4 paths in fim.paths
  exists: it is watching nothing`: no host directory is mounted for it. See
  [Watching host files](#watching-host-files).
- `Log source 'name': <path> is not read: ...`: the file is not mounted, does
  not exist yet, or uid 999 may not read it. See
  [Forwarding host logs](#forwarding-host-logs).
