# Open Security Sensor

A lightweight, high-performance, cross-platform endpoint agent for comprehensive security telemetry collection.

## Overview

The Open Security Sensor is a critical component of the Wildbox security suite that extends visibility from the network perimeter directly onto your endpoints. It provides real-time telemetry about host activity, acting as the nervous system for the entire security platform.

## Key Features

### 🔍 **Comprehensive Telemetry Collection**

- **Process Execution & Ancestry**: Track all process creations with command-line arguments and parent-child relationships
- **Network Connections**: Monitor all TCP/UDP connections with process association
- **File Integrity Monitoring**: Monitor critical system files and directories for unauthorized changes
- **User & Authentication Events**: Track logins, privilege escalations, and user activities
- **System Inventory**: Maintain live asset inventory including OS, software, and hardware details
- **Log Forwarding**: Forward system and application logs to central data lake

### ⚡ **High Performance**

- Built on osquery for efficient host telemetry collection
- Minimal resource consumption with intelligent query scheduling
- Data batching to reduce network overhead
- Low memory footprint

### 🌐 **Cross-Platform Support**

- Linux (Ubuntu, CentOS, RHEL, Debian)
- Windows (Windows 10, Windows Server 2016+)
- macOS (10.14+)

### 🔒 **Security & Reliability**

- TLS/HTTPS encrypted data transmission
- Certificate-based authentication
- Robust error handling and retry mechanisms
- Central configuration management

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

## Quick Start

### Installation

#### Linux (Ubuntu/Debian)

```bash
# Download and install
wget https://github.com/wildbox/open-security-sensor/releases/latest/download/sensor-linux-amd64.deb
sudo dpkg -i sensor-linux-amd64.deb

# Configure
sudo cp /etc/security-sensor/config.yaml.example /etc/security-sensor/config.yaml
sudo nano /etc/security-sensor/config.yaml

# Start service
sudo systemctl enable security-sensor
sudo systemctl start security-sensor
```

#### Windows

```powershell
# Download and install MSI package
Invoke-WebRequest -Uri "https://github.com/wildbox/open-security-sensor/releases/latest/download/sensor-windows-amd64.msi" -OutFile "sensor.msi"
Start-Process msiexec.exe -ArgumentList "/i sensor.msi /quiet" -Wait

# Configure
Copy-Item "C:\Program Files\SecuritySensor\config.yaml.example" "C:\Program Files\SecuritySensor\config.yaml"
notepad "C:\Program Files\SecuritySensor\config.yaml"

# Start service
Start-Service SecuritySensor
```

#### macOS

```bash
# Install via Homebrew
brew tap wildbox/security-sensor
brew install security-sensor

# Configure
sudo cp /usr/local/etc/security-sensor/config.yaml.example /usr/local/etc/security-sensor/config.yaml
sudo nano /usr/local/etc/security-sensor/config.yaml

# Start service
sudo brew services start security-sensor
```

#### Docker Compose (Recommended for Development & Testing)

```bash
# Clone repository
git clone https://github.com/wildbox/open-security-sensor.git
cd open-security-sensor

# Copy and configure
cp config.docker.yaml config.yaml
nano config.yaml  # Edit with your data lake endpoint and API key

# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f sensor

# Stop services
docker-compose down
```

For development with hot reload:

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# View development logs
docker-compose -f docker-compose.dev.yml logs -f sensor-dev
```

With monitoring stack (Prometheus + Grafana):

```bash
# Start with monitoring
docker-compose --profile monitoring up -d

# Access Grafana at http://localhost:3000 (admin:admin123)
# Access Prometheus at http://localhost:9090
```

### Configuration

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

## Docker Deployment

### Quick Start with Docker Compose

The easiest way to deploy the Open Security Sensor is using Docker Compose, which provides a complete containerized environment with all dependencies.

#### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 512MB available memory
- Network access to your security data platform

#### Basic Deployment

```bash
# Clone the repository
git clone https://github.com/wildbox/open-security-sensor.git
cd open-security-sensor

# Create configuration from template
cp config.docker.yaml config.yaml

# Edit configuration with your data lake details
nano config.yaml
```

Point it at your Wildbox gateway, and give it the sensor's API key through
the environment (see
[Sending telemetry to Wildbox](#sending-telemetry-to-wildbox)):

```yaml
data_lake:
  endpoint: "https://wildbox.example.com"
  tls_verify: true
  ca_bundle: ""  # the gateway's certificate, if no public CA signed it
```

```bash
export SENSOR_DATA_LAKE_API_KEY=wsk_...
```

```bash
# Start the sensor stack
docker-compose up -d

# Verify deployment
docker-compose ps
docker-compose logs sensor

# Check sensor health
curl http://localhost:8899/health
```

#### Development Environment

For development with hot code reloading and debugging:

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# The sensor will wait for debugger connection on port 5678
# Attach your IDE debugger to localhost:5678

# View development logs
docker-compose -f docker-compose.dev.yml logs -f sensor-dev
```

#### Production Deployment

For production use with monitoring:

```bash
# Start with monitoring stack (Prometheus + Grafana)
docker-compose --profile monitoring up -d

# Access monitoring
# Grafana: http://localhost:3000 (admin/admin123)
# Prometheus: http://localhost:9090
```

### Docker Configuration

#### Environment Variables

| Variable | Description | Default |
| ---------- | ------------- | --------- |
| `SENSOR_LOGGING_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `PYTHONPATH` | Python path | `/app` |
| `DEVELOPMENT` | Enable development mode | `false` |

#### Volume Mounts

The sensor requires several host mounts for system monitoring:

```yaml
volumes:
  # Configuration
  - ./config.yaml:/etc/security-sensor/config.yaml:ro
  
  # Data persistence
  - sensor_logs:/var/log/security-sensor
  - sensor_data:/var/lib/security-sensor
  
  # Host system monitoring (read-only)
  - /proc:/host/proc:ro
  - /sys:/host/sys:ro
  - /etc:/host/etc:ro
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

#### Security Configuration

The sensor container runs with minimal privileges:

```yaml
security_opt:
  - no-new-privileges:true

cap_add:
  - SYS_PTRACE      # Required for process monitoring
  - DAC_READ_SEARCH # Required for file system access

pid: host  # Required for host process monitoring
```

#### Network Configuration

```yaml
networks:
  - sensor-network      # Internal communication
  - security-suite      # Connect to other security components
```

### Container Management

#### Scaling

Scale the sensor for high-volume environments:

```bash
# Scale sensor instances
docker-compose up -d --scale sensor=3

# With load balancer
docker-compose -f docker-compose.yml -f docker-compose.scale.yml up -d
```

#### Updates

```bash
# Pull latest images
docker-compose pull

# Restart with new images
docker-compose up -d

# Clean up old images
docker image prune -f
```

#### Backup & Recovery

```bash
# Backup sensor data
docker run --rm -v sensor_data:/data -v $(pwd):/backup alpine tar czf /backup/sensor-data-backup.tar.gz -C /data .

# Restore sensor data
docker run --rm -v sensor_data:/data -v $(pwd):/backup alpine tar xzf /backup/sensor-data-backup.tar.gz -C /data
```

### Troubleshooting Docker Deployment

#### Common Issues

**Container fails to start:**

```bash
# Check container logs
docker-compose logs sensor

# Check system resources
docker stats

# Verify configuration
docker-compose config
```

**Permission denied errors:**

```bash
# Check file permissions
ls -la config.yaml

# Fix ownership
sudo chown $USER:$USER config.yaml
```

**Host monitoring not working:**

```bash
# Verify host mounts
docker-compose exec sensor ls -la /host/proc

# Check capabilities
docker-compose exec sensor capsh --print
```

**Network connectivity issues:**

```bash
# Test from container
docker-compose exec sensor curl -I https://your-data-lake.com

# Check DNS resolution
docker-compose exec sensor nslookup your-data-lake.com
```

#### Performance Optimization

**Resource limits:**

```yaml
services:
  sensor:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
```

**Optimize for high-volume:**

```yaml
# In config.yaml
performance:
  max_queue_size: 5000
  batch_size: 200
  flush_interval: 15
  worker_threads: 6
```

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/wildbox/open-security-sensor.git
cd open-security-sensor

# Install dependencies
pip install -r requirements.txt

# Build for current platform
python setup.py build

# Run tests
pytest tests/

# Create distribution packages
python setup.py sdist bdist_wheel
```

### Testing

```bash
# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Run performance tests
pytest tests/performance/

# Generate coverage report
pytest --cov=sensor --cov-report=html
```

## Deployment

### Fleet Management

The sensor supports centralized fleet management through the Open Security Dashboard:

- **Configuration Management**: Deploy configuration changes across entire fleet
- **Health Monitoring**: Real-time status of all deployed sensors
- **Query Deployment**: Push new detection queries to specific host groups
- **Upgrade Management**: Coordinate sensor updates across the organization

### Scaling

For large deployments:

- **Load Balancing**: Deploy multiple ingestion endpoints behind a load balancer
- **Message Queuing**: Use Kafka or RabbitMQ for high-volume environments
- **Regional Deployment**: Deploy regional collectors to reduce latency
- **Batch Processing**: Configure appropriate batch sizes for your environment

## Integration

### With Open Security Data

The sensor seamlessly integrates with the data lake platform, providing enriched telemetry that enhances:

- Threat hunting capabilities
- Historical analysis and forensics
- Real-time alerting and detection
- Compliance reporting and auditing

### With Open Security Agents

LLM agents gain access to endpoint context, enabling sophisticated correlation:

- Process-to-network connection mapping
- Behavioral analysis and anomaly detection
- Automated threat classification
- Context-aware response recommendations

### With Open Security Responder

Response playbooks can execute endpoint actions:

- Process termination
- Network isolation
- File quarantine
- Evidence collection

## API Reference

### Configuration API

```bash
# Get current configuration
curl -X GET http://localhost:8899/api/v1/config

# Update configuration
curl -X PUT http://localhost:8899/api/v1/config \
  -H "Content-Type: application/json" \
  -d @new-config.json

# Reload configuration
curl -X POST http://localhost:8899/api/v1/config/reload
```

### Query API

```bash
# Execute custom query
curl -X POST http://localhost:8899/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM processes WHERE name = '\''chrome'\'';"}'

# Get query schedule
curl -X GET http://localhost:8899/api/v1/queries

# Add scheduled query
curl -X POST http://localhost:8899/api/v1/queries \
  -H "Content-Type: application/json" \
  -d @query-pack.json
```

## Security Considerations

### Data Protection

- All data transmission is encrypted using TLS 1.3
- API keys are stored securely using OS keychain/credential manager
- Sensitive data is never logged or cached locally
- Certificate pinning prevents man-in-the-middle attacks

### Access Control

- Sensor runs with minimal required privileges
- File system access is restricted to monitored paths
- Network access is limited to configured endpoints
- Administrative functions require elevated privileges

### Privacy

- Personal data collection can be disabled via configuration
- Data retention policies are enforced at the data lake level
- GDPR and privacy compliance features available
- Audit logging for all sensor activities

## Troubleshooting

### Common Issues

**Sensor not starting**

```bash
# Check service status
sudo systemctl status security-sensor

# Check logs
sudo journalctl -u security-sensor -f

# Verify configuration
security-sensor --validate-config
```

**High resource usage**

```bash
# Check current resource usage
security-sensor --status

# Adjust performance settings
# Edit performance section in config.yaml

# Restart sensor
sudo systemctl restart security-sensor
```

**Connection issues**

```bash
# Post an empty batch with the configured key and show the answer
python main.py --config /etc/security-sensor/config.yaml --test-connection

# Check the gateway's certificate against the bundle the sensor trusts
openssl s_client -connect wildbox.example.com:443 -CAfile /path/to/ca_bundle.pem

# Check the key: 200 with an empty batch means it is valid and has data:ingest
curl --cacert /path/to/ca_bundle.pem -X POST \
  -H "X-API-Key: $SENSOR_DATA_LAKE_API_KEY" -H "Content-Type: application/json" \
  -d '{"events": []}' https://wildbox.example.com/api/v1/data/ingest
```

The forwarder's log says why a batch was refused: 401, the key is invalid,
expired or revoked; 403 `insufficient_scope`, it lacks `data:ingest`; a
certificate error, the gateway's certificate is not trusted (set
`data_lake.ca_bundle`).

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run quality checks
6. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [docs/](docs/)
- **Docker Guide**: [DOCKER.md](DOCKER.md)
- **Issues**: [GitHub Issues](https://github.com/wildbox/open-security-sensor/issues)
- **Security**: security@wildbox.com
