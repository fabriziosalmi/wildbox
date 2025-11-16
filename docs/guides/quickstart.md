#  Wildbox Quick Start Guide

**Get Wildbox running in 5 minutes**

> **📢 Early Evaluation Phase**: Wildbox is actively seeking community feedback, bug reports, and feature suggestions. [Report issues](https://github.com/fabriziosalmi/wildbox/issues) and [share feedback](https://github.com/fabriziosalmi/wildbox/discussions) to help us build the mature platform the community needs.

---

## ⚡ Prerequisites

Before starting, ensure you have installed:

- **Docker**: [Install Docker](https://docs.docker.com/get-docker/) (Desktop or Server)
- **Docker Compose**: [Install Docker Compose](https://docs.docker.com/compose/install/)
- **Git**: [Install Git](https://git-scm.com/)
- **Minimum Resources**: 8GB RAM, 20GB disk space

**Check installations:**
```bash
docker --version
docker-compose --version
git --version
```

---

## 📥 1. Clone the Repository

```bash
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox
```

---

##  2. Configure Environment

Create environment files for each service:

```bash
# Copy example environment files
cp .env.example .env

# For sensitive data, use secure values:
# Edit .env and add your actual credentials
nano .env
```

**Essential environment variables:**
```env
# Database
DATABASE_URL=postgresql+asyncpg://postgres:secure_password@postgres:5432/wildbox

# API Gateway
API_KEY=your-secure-api-key-here

# OpenAI (for AI-powered features)
OPENAI_API_KEY=sk-your-actual-key

# JWT Security
JWT_SECRET_KEY=your-secure-jwt-secret-min-32-chars

# Redis
REDIS_URL=redis://redis:6379/0

# Stripe (if using billing)
STRIPE_SECRET_KEY=sk_test_your_stripe_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
```

---

## 🐳 3. Start All Services

### Option A: Run Everything (Recommended for First-Time Users)

```bash
# Start all services in the background
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f

# Stop everything
docker-compose down
```

### Option B: Run Specific Services

```bash
# Start only the dashboard and API
docker-compose up -d postgres redis nginx open-security-identity open-security-tools

# Or start individual services
docker-compose up -d postgres redis

# Wait for databases to be ready
sleep 10

# Then start application services
docker-compose up -d open-security-identity open-security-tools
```

---

##  4. Verify Installation

Once services are running, verify they're healthy:

```bash
# Check API health
curl http://localhost:8000/health
curl http://localhost:8001/health
curl http://localhost:8006/health

# Expected response:
# {"status":"healthy","timestamp":"2024-11-07T...","version":"1.0.0"}
```

---

## 🌐 5. Access the Dashboard

Open your browser and navigate to:

| Service | URL | Default Credentials |
|---------|-----|-------------------|
| **Dashboard** | http://localhost:3000 | See `QUICKSTART_CREDENTIALS.md` |
| **API Docs** | http://localhost:8000/docs | N/A |
| **Prometheus** | http://localhost:9090 | N/A |
| **Grafana** | http://localhost:3001 | admin / admin |

---

## 🔑 6. First-Time Login

### Dashboard Access
```bash
# Get initial admin token
curl -X POST http://localhost:8001/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@wildbox.local",
    "password": "your-admin-password"
  }'

# Use the returned token for API requests
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/v1/dashboard
```

### Reset Admin Password (if needed)
```bash
# Access the identity service shell
docker-compose exec open-security-identity bash

# Reset password
python -c "
from app.models import User
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=['bcrypt'])
hashed = pwd_context.hash('new-password-here')
# Update in database manually or through admin script
"
```

---

##  7. Common Tasks

### View Service Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f open-security-identity
docker-compose logs -f open-security-agents

# Last 100 lines
docker-compose logs --tail=100 open-security-identity
```

### Run Database Migrations
```bash
# For PostgreSQL-based services
docker-compose exec open-security-identity \
  alembic upgrade head

docker-compose exec open-security-data \
  alembic upgrade head
```

### Execute Commands in Running Containers
```bash
# Access a service shell
docker-compose exec open-security-identity bash
docker-compose exec open-security-agents bash

# Run a specific command
docker-compose exec -T postgres psql -U postgres -d wildbox -c "SELECT COUNT(*) FROM users;"
```

### Test API Endpoints
```bash
# Get authentication token
TOKEN=$(curl -s -X POST http://localhost:8001/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=your-password" | jq -r '.access_token')

# Make authenticated requests
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/v1/indicators
curl -H "Authorization: Bearer $TOKEN" http://localhost:8006/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "ip", "value": "8.8.8.8"}}'
```

---

##  8. Monitoring & Health Checks

### Dashboard Status
```bash
# Get overall health
curl http://localhost:8000/health | jq .

# Get detailed service status
curl http://localhost:8000/stats | jq .
```

### Database Connectivity
```bash
# Check PostgreSQL
docker-compose exec postgres pg_isready -U postgres

# Check Redis
docker-compose exec redis redis-cli ping
```

### Memory & Disk Usage
```bash
# Check container resource usage
docker stats

# Check disk usage
docker system df
```

---

##  9. Troubleshooting

### Services Won't Start
```bash
# Check error logs
docker-compose logs open-security-identity

# Rebuild images
docker-compose build --no-cache

# Restart services
docker-compose restart

# Full reset (WARNING: Deletes data)
docker-compose down -v
docker-compose up -d
```

### Can't Connect to API
```bash
# Verify services are running
docker-compose ps

# Check if ports are open
netstat -an | grep 8000
lsof -i :8000

# Test connectivity
curl -v http://localhost:8000/health
```

### Database Connection Issues
```bash
# Check PostgreSQL logs
docker-compose logs postgres

# Verify database exists
docker-compose exec postgres psql -U postgres -l

# Check Redis connection
docker-compose exec redis redis-cli info
```

### Out of Memory or Disk Space
```bash
# Clean up unused images/volumes
docker system prune -a

# Check disk usage
du -sh ./*

# Reduce log retention
docker-compose down
# Edit docker-compose.yml and adjust volumes
```

---

##  10. Next Steps

After successful deployment:

1. **Security Hardening**: Review [SECURITY_REMEDIATION_CHECKLIST.md](SECURITY_REMEDIATION_CHECKLIST.md)
2. **Full Documentation**: See [README.md](README.md) for comprehensive information
3. **API Documentation**: Visit http://localhost:8000/docs for interactive API docs
4. **Monitoring Setup**: Configure Grafana dashboards and alerting rules
5. **Integration**: Set up external integrations (Slack, email, webhooks, etc.)
6. **Custom Playbooks**: Create YAML-based automation playbooks in [open-security-responder](open-security-responder)

---

##  11. Production Deployment

For production use:

```bash
# 1. Secure all credentials in .env.production
cp .env .env.production
nano .env.production

# 2. Use production docker-compose
docker-compose -f docker-compose.yml \
               -f docker-compose.prod.yml \
               up -d

# 3. Enable SSL/TLS in nginx
# Edit nginx-config.conf and enable HTTPS

# 4. Set up monitoring and alerting
# Configure Prometheus retention and Grafana alerts

# 5. Enable backups
# Set up automated PostgreSQL and Redis backups

# 6. Security hardening
# Review and implement SECURITY_REMEDIATION_CHECKLIST.md
```

---

## 🆘 Support & Troubleshooting

- **Documentation**: [README.md](../../README.md)
- **Security Issues**: [Security Policy](../security/policy.md)
- **API Docs**: http://localhost:8000/docs (when running)
- **GitHub Issues**: https://github.com/fabriziosalmi/wildbox/issues

---

##  Quick Reference

| Command | Purpose |
|---------|---------|
| `docker-compose up -d` | Start all services |
| `docker-compose down` | Stop all services |
| `docker-compose logs -f` | View live logs |
| `docker-compose ps` | Show running services |
| `docker-compose exec <service> bash` | Access service shell |
| `docker-compose restart <service>` | Restart specific service |
| `docker-compose build` | Rebuild images |

---

**Happy Securing! **

For questions or issues, refer to the comprehensive [README.md](README.md) or open an issue on GitHub.
