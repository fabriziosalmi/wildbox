# Redis Consolidation Guide

## Overview

The Wildbox platform has been optimized to use a single, shared Redis instance instead of multiple individual Redis containers. This consolidation improves resource efficiency, simplifies deployment, and maintains isolation through database separation.

## Architecture Changes

### Before Consolidation
- **8 individual Redis containers** running across services
- Each service on different ports (6379-6385)
- Separate memory allocation per service
- Complex port management

### After Consolidation
- **1 shared Redis container** (`wildbox-redis`)
- **Logical database separation** using Redis databases 0-15
- **Unified memory management** (512MB total)
- **Simplified networking** (single port 6379)

## Database Allocation

| Service | Redis Database | URL |
|---------|----------------|-----|
| Identity | 0 | `redis://wildbox-redis:6379/0` |
| Guardian | 1 | `redis://wildbox-redis:6379/1` |
| Responder | 2 | `redis://wildbox-redis:6379/2` |
| CSPM | 3 | `redis://wildbox-redis:6379/3` |
| Agents | 4 | `redis://wildbox-redis:6379/4` |
| Gateway | 5 | `redis://wildbox-redis:6379/5` |
| API | 6 | `redis://wildbox-redis:6379/6` |
| Data | 7 | `redis://wildbox-redis:6379/7` |

## Configuration

### Main Stack (docker-compose.yml)
The main docker-compose.yml uses a single Redis instance:

```yaml
wildbox-redis:
  image: redis:7-alpine
  container_name: wildbox-redis
  command: redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru --databases 16
  volumes:
    - wildbox_redis_data:/data
```

### Individual Service Files
Each service's standalone `docker-compose.yml` has been updated with:
1. **Documentation** explaining the consolidation
2. **Local Redis** for standalone development
3. **Comments** showing main stack integration URLs

## Benefits

### Resource Efficiency
- **Memory usage reduced** from ~2GB to 512MB
- **Container overhead eliminated** (7 fewer containers)
- **Simplified monitoring** (single Redis instance)

### Operational Benefits
- **Simplified backup** (single Redis data volume)
- **Unified configuration** (shared memory policies)
- **Easier debugging** (centralized cache inspection)
- **Reduced complexity** in deployment scripts

### Development Benefits
- **Consistent environment** across all services
- **Simplified local testing** with shared state
- **Better resource utilization** on development machines

## Usage Instructions

### Main Stack Deployment
```bash
# Deploy the full Wildbox stack with consolidated Redis
docker-compose up -d

# All services will automatically connect to wildbox-redis
# with their assigned database numbers
```

### Individual Service Development
```bash
# Each service can still be developed standalone
cd open-security-agents
docker-compose up -d

# This uses a local Redis instance for development
```

### Redis Monitoring
```bash
# Connect to the shared Redis instance
docker-compose exec wildbox-redis redis-cli

# Check specific database
redis-cli -n 0  # Identity service data
redis-cli -n 1  # Guardian service data
redis-cli -n 2  # Responder service data
# etc.
```

## Migration Notes

### Automatic Migration
- **No data migration needed** - services start fresh with new database assignments
- **Environment variables updated** to point to shared instance
- **Legacy Redis containers removed** from main compose file

### Backward Compatibility
- **Individual service compose files preserved** for standalone development
- **Development workflows unchanged** for single-service testing
- **Production deployment simplified** via main docker-compose.yml

## Performance Considerations

### Memory Management
- **512MB total allocation** with LRU eviction policy
- **Database 0-15 available** for service separation
- **Persistence enabled** with appendonly logging

### Monitoring
Monitor Redis performance:
```bash
# Memory usage
docker exec wildbox-redis redis-cli info memory

# Database sizes
docker exec wildbox-redis redis-cli info keyspace

# Connection counts
docker exec wildbox-redis redis-cli info clients
```

## Troubleshooting

### Common Issues

#### Service Can't Connect to Redis
```bash
# Check Redis is running
docker-compose ps wildbox-redis

# Check network connectivity
docker-compose exec identity ping wildbox-redis

# Verify environment variables
docker-compose exec identity env | grep REDIS_URL
```

#### Redis Out of Memory
```bash
# Check memory usage
docker exec wildbox-redis redis-cli info memory

# Increase memory limit if needed (edit docker-compose.yml)
# --maxmemory 1024mb
```

#### Database Collision
Each service uses a different database number (0-7), preventing data collision.

## Files Modified

### Main Compose File
- `/docker-compose.yml` - Consolidated Redis configuration

### Individual Service Files
- `/open-security-agents/docker-compose.yml`
- `/open-security-tools/docker-compose.yml`
- `/open-security-automations/docker-compose.yml`
- `/open-security-cspm/docker-compose.yml`
- `/open-security-data/docker-compose.yml`
- `/open-security-gateway/docker-compose.yml`
- `/open-security-guardian/docker-compose.yml`
- `/open-security-identity/docker-compose.yml`
- `/open-security-responder/docker-compose.yml`
- `/open-security-sensor/docker-compose.yml`

## Testing

### Verify Consolidation
```bash
# Start the stack
docker-compose up -d

# Should see only one Redis container
docker-compose ps | grep redis

# Should show: wildbox-redis (not multiple Redis containers)
```

### Verify Service Connectivity
```bash
# Check all services can reach Redis
./comprehensive_health_check.sh

# Should show all services healthy with no Redis connection errors
```

This consolidation maintains the same functionality while significantly improving resource efficiency and operational simplicity.
