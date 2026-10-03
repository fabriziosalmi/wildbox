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

`docker-compose.yml` in this directory runs the sensor on its own.

1. Create the external network the compose file attaches to:

   ```bash
   docker network create security-suite
   ```

2. Start the sensor with a key for its local API:

   ```bash
   SENSOR_API_KEY=<key> docker compose up -d
   ```

3. Verify:

   ```bash
   curl http://127.0.0.1:8004/health
   curl -H "X-API-Key: <key>" http://127.0.0.1:8004/status
   ```

The image build reads `../open-security-shared` as an additional build context,
so run it from a full repository checkout.

### Ports and configuration

Both compose files mount `config.yaml.example` as
`/etc/security-sensor/config.yaml`. It binds the local API to `0.0.0.0:8004`
inside the container, and compose publishes that port on `127.0.0.1:8004` only.
To change the configuration, edit `config.yaml.example` or use the
`SENSOR_*` environment variables listed in [README.md](README.md#environment-variables).

### Monitoring profile

The `monitoring` profile adds Prometheus (port `9090`) and Grafana (port
`3000`), both published on all host interfaces. Grafana's admin password comes
from `GRAFANA_ADMIN_PASSWORD`:

```bash
GRAFANA_ADMIN_PASSWORD=<password> SENSOR_API_KEY=<key> \
  docker compose --profile monitoring up -d
```

The sensor does not expose a `/metrics` endpoint, so the Prometheus scrape job
for it in `monitoring/prometheus.yml` has no target to read.

## Environment variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `SENSOR_API_KEY` | None; required | Key for every local API route except `/health` |
| `SENSOR_DATA_LAKE_ENDPOINT` | `data_lake.endpoint` from the file | The Wildbox gateway, `https://...` |
| `SENSOR_DATA_LAKE_API_KEY` | None | Identity API key with the `data:ingest` scope; without it forwarding is disabled |
| `SENSOR_DATA_LAKE_CA_BUNDLE` | None (system trust store) | PEM file for a gateway certificate no public CA signed |
| `SENSOR_LOGGING_LEVEL` | `INFO` | Log level |
| `PYTHONPATH` | `/app` | Python module path |
| `GRAFANA_ADMIN_PASSWORD` | None; needed by the `monitoring` profile | Grafana admin password |

The standalone compose files pass the `SENSOR_DATA_LAKE_*` variables through
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
| `sensor_data:/var/lib/security-sensor` | Sensor state |
| `/proc/stat`, `/proc/meminfo`, the `/proc` load average file, `/sys/class/net` (read-only, under `/host`) | Host metrics |

The compose files do not mount the host's `/proc`, `/etc` or the Docker socket.

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
- `network security-suite declared as external, but could not be found`: run
  `docker network create security-suite`.
