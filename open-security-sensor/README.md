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

```
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

Edit the configuration file with your environment details:

```yaml
# Data Lake Connection
data_lake:
  endpoint: "https://your-security-data-platform.com/api/v1/ingest"
  api_key: "your-api-key-here"
  tls_verify: true
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

Update the configuration with your data lake endpoint:
```yaml
data_lake:
  endpoint: "https://your-security-data-platform.com/api/v1/ingest"
  api_key: "your-api-key-here"
  tls_verify: true
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
|----------|-------------|---------|
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
# Test connectivity
security-sensor --test-connection

# Check TLS certificate
openssl s_client -connect your-data-lake.com:443

# Verify API key
curl -H "Authorization: Bearer YOUR-API-KEY" https://your-data-lake.com/api/v1/health
```

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
