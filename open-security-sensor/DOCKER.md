# Docker Deployment Guide

This guide provides comprehensive instructions for deploying the Open Security Sensor using Docker and Docker Compose.

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 512MB+ available memory
- Network access to security data platform

### Basic Deployment

1. **Clone and configure:**
   ```bash
   git clone https://github.com/wildbox/open-security-sensor.git
   cd open-security-sensor
   cp config.docker.yaml config.yaml
   ```

2. **Edit configuration:**
   ```bash
   nano config.yaml
   # Update data_lake.endpoint and data_lake.api_key
   ```

3. **Deploy:**
   ```bash
   docker-compose up -d
   ```

4. **Verify:**
   ```bash
   curl http://localhost:8899/health
   ```

## Deployment Options

### Development Environment

For development with hot reload and debugging:

```bash
# Start development stack
docker-compose -f docker-compose.dev.yml up -d

# Attach debugger to port 5678
# View logs
docker-compose -f docker-compose.dev.yml logs -f sensor-dev
```

### Production with Monitoring

Deploy with Prometheus and Grafana:

```bash
# Start production stack with monitoring
docker-compose --profile monitoring up -d

# Access monitoring
# Grafana: http://localhost:3000 (admin/admin123)
# Prometheus: http://localhost:9090
```

### High Availability / Scaling

Deploy multiple sensor instances with load balancing:

```bash
# Scale sensor instances
docker-compose -f docker-compose.yml -f docker-compose.scale.yml up -d

# View scaled deployment
docker-compose ps
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SENSOR_LOGGING_LEVEL` | Log level | `INFO` |
| `PYTHONPATH` | Python module path | `/app` |
| `DEVELOPMENT` | Development mode | `false` |

### Volume Mapping

Required volumes for system monitoring:

- `/proc:/host/proc:ro` - Process information
- `/sys:/host/sys:ro` - System information  
- `/etc:/host/etc:ro` - Configuration files
- `/var/run/docker.sock:/var/run/docker.sock:ro` - Docker socket

### Network Configuration

Networks used:
- `sensor-network` - Internal communication
- `security-suite` - External security components

## Management

### Service Control

```bash
# Start services
docker-compose up -d

# Stop services  
docker-compose down

# Restart specific service
docker-compose restart sensor

# View logs
docker-compose logs -f sensor

# Execute commands in container
docker-compose exec sensor /bin/bash
```

### Updates

```bash
# Pull latest images
docker-compose pull

# Recreate containers with new images
docker-compose up -d --force-recreate

# Clean up old images
docker image prune -f
```

### Backup & Restore

```bash
# Backup sensor data
docker run --rm \
  -v sensor_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/sensor-backup.tar.gz -C /data .

# Restore sensor data
docker run --rm \
  -v sensor_data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/sensor-backup.tar.gz -C /data
```

## Monitoring

### Health Checks

```bash
# Check container health
docker-compose ps

# Check sensor API health
curl http://localhost:8899/health

# Check sensor status
curl http://localhost:8899/status
```

### Resource Monitoring

```bash
# View resource usage
docker stats

# View container processes
docker-compose top

# Check disk usage
docker system df
```

### Logs

```bash
# View all logs
docker-compose logs

# Follow specific service logs
docker-compose logs -f sensor

# View last N lines
docker-compose logs --tail=100 sensor

# Filter by timestamp
docker-compose logs --since="2024-01-01T00:00:00Z" sensor
```

## Troubleshooting

### Common Issues

#### Container Won't Start

```bash
# Check container status
docker-compose ps

# View startup logs
docker-compose logs sensor

# Check configuration
docker-compose config
```

#### Permission Errors

```bash
# Check file permissions
ls -la config.yaml

# Fix ownership
sudo chown $USER:$USER config.yaml

# Check container user
docker-compose exec sensor id
```

#### Host Monitoring Issues

```bash
# Verify host mounts
docker-compose exec sensor ls -la /host/proc

# Check process access
docker-compose exec sensor ps aux

# Test capabilities
docker-compose exec sensor capsh --print
```

#### Network Connectivity

```bash
# Test external connectivity
docker-compose exec sensor curl -I https://your-data-lake.com

# Check DNS resolution
docker-compose exec sensor nslookup your-data-lake.com

# Test internal connectivity
docker-compose exec sensor curl http://redis:6379
```

### Performance Tuning

#### Resource Limits

Add to docker-compose.yml:

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

#### Configuration Optimization

For high-volume environments:

```yaml
# config.yaml
performance:
  max_queue_size: 5000
  batch_size: 200
  flush_interval: 15
  worker_threads: 6
  max_memory_mb: 384
```

## Security Considerations

### Container Security

- Runs as non-root user (`sensor`)
- No-new-privileges security option
- Minimal required capabilities
- Read-only host mounts

### Network Security

- Internal network isolation
- TLS encrypted data transmission
- API key authentication
- Optional nginx SSL termination

### Host Integration

- PID namespace sharing for process monitoring
- Minimal host filesystem access
- Docker socket access (read-only)

## Integration with Security Suite

### Connect to Data Lake

Update `config.yaml`:

```yaml
data_lake:
  endpoint: "https://your-data-lake.com/api/v1/ingest"
  api_key: "your-api-key"
```

### Multi-Component Deployment

Deploy with other security components:

```bash
# Create shared network
docker network create security-suite

# Deploy data lake
cd ../open-security-data
docker-compose up -d

# Deploy sensor
cd ../open-security-sensor  
docker-compose up -d
```

### Service Discovery

Components communicate via Docker networks:

```yaml
networks:
  security-suite:
    external: true
    name: security-suite
```

## Advanced Configuration

### Custom osquery Packs

Mount custom query packs:

```yaml
volumes:
  - ./custom-packs:/etc/security-sensor/packs:ro
```

### Log Forwarding

Configure log shipping:

```yaml
# config.yaml
collection:
  log_forwarding: true

log_sources:
  - name: "application_logs"
    type: "file"
    path: "/var/log/app/*.log"
```

### High Availability

Deploy across multiple hosts:

```bash
# docker-compose.ha.yml
version: '3.8'
services:
  sensor:
    deploy:
      replicas: 3
      placement:
        constraints:
          - node.role == worker
```

For questions or issues, see the main README.md or open an issue on GitHub.
