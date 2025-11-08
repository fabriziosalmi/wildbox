# 🔧 Wildbox Troubleshooting Guide

This guide helps you diagnose and resolve common issues with Wildbox.

---

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Installation Issues](#installation-issues)
- [Service Startup Problems](#service-startup-problems)
- [Database Issues](#database-issues)
- [Network & Connectivity](#network--connectivity)
- [Authentication & Authorization](#authentication--authorization)
- [Performance Issues](#performance-issues)
- [Docker Issues](#docker-issues)
- [Development Issues](#development-issues)
- [Getting Help](#getting-help)

---

## Quick Diagnostics

Before diving into specific issues, run these diagnostic commands:

```bash
# Check service health
make health

# View service status
docker-compose ps

# Check logs for errors
docker-compose logs

# Check Docker resources
docker system df
docker stats --no-stream
```

---

## Installation Issues

### Problem: `docker-compose` command not found

**Symptoms:**
```
bash: docker-compose: command not found
```

**Solution:**
```bash
# Install Docker Compose
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install docker-compose

# macOS
brew install docker-compose

# Verify installation
docker-compose --version
```

### Problem: Permission denied when running Docker commands

**Symptoms:**
```
Got permission denied while trying to connect to the Docker daemon socket
```

**Solution:**
```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Log out and back in, then verify
docker ps

# Or use newgrp to activate the group immediately
newgrp docker
```

### Problem: Insufficient disk space

**Symptoms:**
```
Error: No space left on device
```

**Solution:**
```bash
# Check disk space
df -h

# Clean up Docker resources
docker system prune -a --volumes

# Remove unused images
docker image prune -a

# Remove stopped containers
docker container prune
```

### Problem: Port already in use

**Symptoms:**
```
Error: bind: address already in use
```

**Solution:**
```bash
# Find what's using the port (e.g., 8000)
sudo lsof -i :8000

# Kill the process (replace PID with actual process ID)
kill -9 <PID>

# Or modify docker-compose.yml to use different ports
# Change "8000:8000" to "8001:8000"
```

---

## Service Startup Problems

### Problem: Services keep restarting

**Symptoms:**
```
Container is in "Restarting" status
```

**Diagnostic Steps:**
```bash
# Check specific service logs
docker-compose logs <service-name>

# Check if service is waiting for dependencies
docker-compose logs | grep -i "waiting"

# Inspect container
docker inspect <container-name>
```

**Common Causes & Solutions:**

1. **Missing environment variables:**
   ```bash
   # Check .env file exists
   ls -la .env

   # Verify required variables are set
   grep -E "JWT_SECRET_KEY|DATABASE_URL|API_KEY" .env
   ```

2. **Database not ready:**
   ```bash
   # Check PostgreSQL is running
   docker-compose logs postgres

   # Verify database connection
   docker-compose exec postgres psql -U postgres -c "SELECT 1;"
   ```

3. **Health check failing:**
   ```bash
   # Check health status
   docker ps --format "table {{.Names}}\t{{.Status}}"

   # Test health endpoint manually
   curl http://localhost:8000/health
   ```

### Problem: Services fail to start with exit code 1

**Symptoms:**
```
Exited with code 1
```

**Solution:**
```bash
# View full error logs
docker-compose logs <service-name> --tail=100

# Common issues:
# 1. Missing Python dependencies
docker-compose exec <service-name> pip install -r requirements.txt

# 2. Database migration failed
docker-compose exec identity alembic upgrade head

# 3. Permission issues
docker-compose exec <service-name> ls -la
```

### Problem: Frontend (dashboard) shows blank page

**Symptoms:**
- Dashboard loads but shows white/blank screen
- Browser console shows errors

**Solution:**
```bash
# Check dashboard logs
docker-compose logs dashboard

# Rebuild frontend
docker-compose build dashboard --no-cache

# Check if API is accessible
curl http://localhost:8000/health

# Verify environment variables
docker-compose exec dashboard env | grep NEXT_PUBLIC
```

---

## Database Issues

### Problem: Database connection refused

**Symptoms:**
```
could not connect to server: Connection refused
psycopg2.OperationalError: could not connect to server
```

**Solution:**
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check PostgreSQL logs
docker-compose logs postgres

# Restart PostgreSQL
docker-compose restart postgres

# Wait for PostgreSQL to be ready
docker-compose exec postgres pg_isready -U postgres
```

### Problem: Database migration failed

**Symptoms:**
```
alembic.util.exc.CommandError: Can't locate revision identified by 'xxxxx'
```

**Solution:**
```bash
# Check current migration status
docker-compose exec identity alembic current

# List all migrations
docker-compose exec identity alembic history

# Downgrade and re-upgrade
docker-compose exec identity alembic downgrade -1
docker-compose exec identity alembic upgrade head

# If migrations are completely broken, reset database (CAUTION: data loss!)
docker-compose down -v
docker-compose up -d postgres
sleep 10
docker-compose exec identity alembic upgrade head
```

### Problem: Database authentication failed

**Symptoms:**
```
FATAL: password authentication failed for user "postgres"
```

**Solution:**
```bash
# Check DATABASE_URL in .env
grep DATABASE_URL .env

# Ensure password matches docker-compose.yml
grep POSTGRES_PASSWORD docker-compose.yml

# Reset PostgreSQL password
docker-compose exec postgres psql -U postgres -c "ALTER USER postgres PASSWORD 'newpassword';"

# Update .env with new password
# DATABASE_URL=postgresql+asyncpg://postgres:newpassword@postgres:5432/wildbox
```

---

## Network & Connectivity

### Problem: Cannot access dashboard at localhost:3000

**Symptoms:**
- Browser shows "This site can't be reached"
- Connection timeout

**Solution:**
```bash
# Check if dashboard container is running
docker-compose ps dashboard

# Check if port is mapped correctly
docker port <dashboard-container-name>

# Check if port 3000 is listening
netstat -tuln | grep 3000  # Linux
lsof -i :3000              # macOS

# Try accessing via container IP
docker inspect <dashboard-container-name> | grep IPAddress
curl http://<container-ip>:3000
```

### Problem: Services cannot communicate with each other

**Symptoms:**
```
requests.exceptions.ConnectionError: HTTPConnectionPool
Failed to establish a new connection
```

**Solution:**
```bash
# Check Docker network
docker network ls
docker network inspect wildbox

# Verify all containers are on the same network
docker-compose ps --format "table {{.Name}}\t{{.Networks}}"

# Recreate network
docker-compose down
docker network rm wildbox
docker network create wildbox
docker-compose up -d

# Test connectivity between containers
docker-compose exec dashboard ping postgres
docker-compose exec identity ping redis
```

### Problem: API Gateway returns 502 Bad Gateway

**Symptoms:**
- Gateway returns "502 Bad Gateway"
- Services work when accessed directly

**Solution:**
```bash
# Check gateway logs
docker-compose logs gateway

# Verify upstream services are healthy
curl http://localhost:8001/health  # Identity
curl http://localhost:8002/health  # Tools
curl http://localhost:8003/health  # Data

# Check gateway configuration
docker-compose exec gateway cat /etc/nginx/nginx.conf

# Restart gateway
docker-compose restart gateway
```

---

## Authentication & Authorization

### Problem: Cannot log in with default credentials

**Symptoms:**
- "Invalid credentials" error
- 401 Unauthorized

**Solution:**
```bash
# Check if admin user was created
docker-compose logs identity | grep -i "admin"

# Verify CREATE_INITIAL_ADMIN is set
grep CREATE_INITIAL_ADMIN .env

# Create admin user manually
docker-compose exec identity python -c "
from app.core.database import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash

db = SessionLocal()
admin = User(
    email='admin@wildbox.local',
    hashed_password=get_password_hash('admin123'),
    is_active=True,
    is_superuser=True
)
db.add(admin)
db.commit()
print('Admin user created')
"
```

### Problem: JWT token expired or invalid

**Symptoms:**
```
{"detail": "Could not validate credentials"}
{"detail": "Token has expired"}
```

**Solution:**
```bash
# Check JWT configuration
grep JWT_ .env

# Verify JWT_SECRET_KEY is consistent across services
docker-compose exec identity env | grep JWT_SECRET_KEY
docker-compose exec gateway env | grep JWT_SECRET_KEY

# Clear browser cache and cookies
# Try logging in again
```

### Problem: API key authentication failed

**Symptoms:**
```
{"detail": "Invalid API key"}
```

**Solution:**
```bash
# Check API_KEY in .env
grep API_KEY .env

# Generate new API key
openssl rand -hex 32

# Update .env and restart services
docker-compose restart
```

---

## Performance Issues

### Problem: Services are slow or unresponsive

**Diagnostic Steps:**
```bash
# Check resource usage
docker stats

# Check CPU and memory
docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Check disk I/O
docker stats --format "table {{.Name}}\t{{.BlockIO}}"
```

**Solutions:**

1. **Increase Docker resources:**
   - Docker Desktop → Settings → Resources
   - Increase CPU, Memory allocation

2. **Optimize database:**
   ```bash
   # Check database size
   docker-compose exec postgres psql -U postgres -c "\l+"

   # Vacuum and analyze
   docker-compose exec postgres psql -U postgres -d wildbox -c "VACUUM ANALYZE;"
   ```

3. **Clear Redis cache:**
   ```bash
   docker-compose exec redis redis-cli FLUSHALL
   ```

4. **Check logs for slow queries:**
   ```bash
   docker-compose logs | grep -i "slow"
   ```

### Problem: High memory usage

**Symptoms:**
- Container using excessive RAM
- System becomes sluggish

**Solution:**
```bash
# Identify memory-hungry containers
docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}"

# Restart specific service
docker-compose restart <service-name>

# Limit container memory (add to docker-compose.yml)
# services:
#   identity:
#     mem_limit: 512m

# Clean up unused resources
docker system prune -a
```

---

## Docker Issues

### Problem: Docker daemon not running

**Symptoms:**
```
Cannot connect to the Docker daemon
```

**Solution:**
```bash
# Start Docker service
# Linux
sudo systemctl start docker
sudo systemctl enable docker

# macOS
# Open Docker Desktop application

# Verify Docker is running
docker info
```

### Problem: Docker build fails with network timeout

**Symptoms:**
```
Could not fetch URL
Temporary failure resolving
```

**Solution:**
```bash
# Use different DNS for Docker
# Edit /etc/docker/daemon.json (Linux)
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}

# Restart Docker
sudo systemctl restart docker

# Or use build args
docker-compose build --build-arg http_proxy=http://your-proxy
```

### Problem: Volume mount issues

**Symptoms:**
- Changes to files not reflected in container
- Permission denied errors

**Solution:**
```bash
# Check volume mounts
docker inspect <container-name> | grep -A 10 Mounts

# Fix permissions (Linux)
sudo chown -R $USER:$USER .

# Recreate volumes
docker-compose down -v
docker-compose up -d
```

---

## Development Issues

### Problem: Hot reload not working in development

**Symptoms:**
- Code changes not reflected
- Need to rebuild container for changes

**Solution:**
```bash
# Verify volume mounts in docker-compose.override.yml
cat docker-compose.override.yml

# For Python services, ensure --reload flag
# For Next.js, ensure NODE_ENV=development

# Restart in development mode
make dev
```

### Problem: Tests failing in container

**Symptoms:**
```
pytest errors
Test suite fails
```

**Solution:**
```bash
# Run tests with verbose output
docker-compose exec <service-name> pytest -v

# Check test database
docker-compose exec <service-name> env | grep TEST_

# Install test dependencies
docker-compose exec <service-name> pip install -r requirements.txt

# Clear pytest cache
docker-compose exec <service-name> rm -rf .pytest_cache
```

---

## Getting Help

If you're still experiencing issues:

1. **Check logs:**
   ```bash
   # Get logs from all services
   docker-compose logs > logs.txt

   # Share logs when reporting issues
   ```

2. **Search existing issues:**
   - Visit [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues)
   - Search for your error message

3. **Report a bug:**
   - Create a new issue with:
     - Description of the problem
     - Steps to reproduce
     - Error messages and logs
     - Environment details (OS, Docker version)
     - Output of `docker-compose ps`

4. **Join the community:**
   - [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions)
   - Share your experience and get help

5. **Check documentation:**
   - [Quick Start Guide](docs/guides/quickstart.md)
   - [Deployment Guide](docs/guides/deployment.md)
   - [Security Documentation](docs/security/policy.md)
   - [Online Docs](https://www.wildbox.io)

---

## Common Error Messages Reference

| Error Message | Common Cause | Quick Fix |
|--------------|--------------|-----------|
| `Connection refused` | Service not running | `docker-compose up -d` |
| `Address already in use` | Port conflict | Change port or kill process |
| `No space left on device` | Disk full | `docker system prune -a` |
| `Permission denied` | File/directory permissions | `sudo chown -R $USER:$USER .` |
| `Could not validate credentials` | Invalid/expired token | Clear cache and re-login |
| `Database connection failed` | DB not ready | Wait or `docker-compose restart postgres` |
| `Module not found` | Missing dependencies | `pip install -r requirements.txt` |
| `502 Bad Gateway` | Upstream service down | Check service health |
| `Network not found` | Missing Docker network | `docker network create wildbox` |

---

## Health Check Checklist

Use this checklist to verify everything is working:

- [ ] All containers are running: `docker-compose ps`
- [ ] PostgreSQL is healthy: `docker-compose exec postgres pg_isready`
- [ ] Redis is responding: `docker-compose exec redis redis-cli ping`
- [ ] Identity service: `curl http://localhost:8001/health`
- [ ] Tools service: `curl http://localhost:8002/health`
- [ ] Data service: `curl http://localhost:8003/health`
- [ ] Gateway: `curl http://localhost:8080/health`
- [ ] Dashboard: `curl http://localhost:3000`
- [ ] No errors in logs: `docker-compose logs --tail=50`
- [ ] Network connectivity: All services can ping each other
- [ ] Authentication works: Can log in to dashboard

---

## Environment Variables Checklist

Ensure these are properly set in your `.env` file:

```bash
# Required variables
DATABASE_URL=postgresql+asyncpg://postgres:PASSWORD@postgres:5432/wildbox
REDIS_URL=redis://redis:6379/0
JWT_SECRET_KEY=your-secure-32-char-secret
API_KEY=your-secure-api-key

# Optional but recommended
OPENAI_API_KEY=sk-your-key (for AI features)
STRIPE_SECRET_KEY=sk_your_key (for billing)
CREATE_INITIAL_ADMIN=true
INITIAL_ADMIN_EMAIL=admin@wildbox.local
INITIAL_ADMIN_PASSWORD=changeme
```

---

*Last updated: 2025-11-08*
