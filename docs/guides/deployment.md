# 🚀 Deployment Guide

**For Wildbox Security Platform**

**Status**: Ready for Evaluation & Community Testing
**Maturity**: Early Evaluation Phase - Suitable for Testing, Staging, and Community Deployments

This guide covers deploying Wildbox in various environments. As the platform enters the evaluation phase, real-world deployment feedback is crucial for refining production-grade procedures.

> **📢 Community Feedback Welcome**: Encountered deployment challenges? Found a configuration that works well? [Share your experiences](https://github.com/fabriziosalmi/wildbox/discussions) and [report issues](https://github.com/fabriziosalmi/wildbox/issues). Your real-world insights help us build better deployment procedures.

---

## 📋 Table of Contents

1. [Pre-Deployment](#pre-deployment)
2. [Infrastructure Setup](#infrastructure-setup)
3. [Secret Management](#secret-management)
4. [Database Setup](#database-setup)
5. [Service Deployment](#service-deployment)
6. [SSL/TLS Configuration](#ssltls-configuration)
7. [Monitoring & Logging](#monitoring--logging)
8. [Backup & Recovery](#backup--recovery)
9. [Post-Deployment](#post-deployment)
10. [Troubleshooting](#troubleshooting)

---

## ✅ Pre-Deployment

### 1. Requirements Checklist

- [ ] Linux server (Ubuntu 22.04 LTS or CentOS 8+)
- [ ] Docker Engine 20.10+
- [ ] Docker Compose 2.0+
- [ ] Minimum 8GB RAM
- [ ] Minimum 50GB SSD storage
- [ ] Static IP address
- [ ] Domain name with DNS configured
- [ ] SSL certificate (Let's Encrypt or commercial)
- [ ] Backup storage (AWS S3, GCS, or on-premise)

### 2. Pre-Flight Checks

```bash
# Verify system requirements
docker --version
docker-compose --version
uname -a

# Check resources
free -h
df -h
nproc

# Verify network
ping 8.8.8.8
curl -I https://example.com
```

### 3. Security Review

```bash
# Review security documentation
cat SECURITY.md
cat SECURITY_REMEDIATION_CHECKLIST.md

# Verify no secrets in git
git log -S "password" --all
git log -S "secret" --all
git log -S "api_key" --all
```

---

## 🏗️ Infrastructure Setup

### 1. System Hardening

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install security tools
sudo apt install -y ufw fail2ban certbot python3-certbot-nginx

# Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH (restrict to specific IPs if possible)
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Enable fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 2. Create Application User

```bash
# Create non-root user
sudo useradd -m -s /bin/bash wildbox
sudo usermod -aG docker wildbox

# Set up home directory
sudo mkdir -p /home/wildbox/data
sudo chown wildbox:wildbox /home/wildbox/data
sudo chmod 750 /home/wildbox/data

# Switch to new user
sudo -u wildbox -i
```

### 3. Clone Repository

```bash
cd /home/wildbox
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox
```

---

## 🔐 Secret Management

### 1. Generate Secure Secrets

```bash
#!/bin/bash
# Generate all required secrets

echo "Generating secrets..."

# JWT Secret (32+ characters)
JWT_SECRET=$(openssl rand -hex 32)
echo "JWT_SECRET=$JWT_SECRET"

# API Key
API_KEY=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
echo "API_KEY=$API_KEY"

# Database Password
DB_PASSWORD=$(openssl rand -base64 32)
echo "DB_PASSWORD=$DB_PASSWORD"

# Gateway Secret
GATEWAY_SECRET=$(openssl rand -hex 32)
echo "GATEWAY_SECRET=$GATEWAY_SECRET"

# Stripe Keys (from Stripe dashboard)
# STRIPE_SECRET_KEY=sk_live_XXXXX
# STRIPE_PUBLIC_KEY=pk_live_XXXXX

# Save to .env.production (NEVER commit this!)
cat > .env.production << ENV
# Database
DATABASE_URL=postgresql+asyncpg://postgres:${DB_PASSWORD}@postgres:5432/wildbox
DATA_DATABASE_URL=postgresql://secdata:${DB_PASSWORD}@postgres:5432/data
POSTGRES_PASSWORD=${DB_PASSWORD}

# Redis
REDIS_URL=redis://redis:6379/0

# Security
JWT_SECRET_KEY=${JWT_SECRET}
API_KEY=${API_KEY}
GATEWAY_INTERNAL_SECRET=${GATEWAY_SECRET}

# OpenAI (if using AI features)
OPENAI_API_KEY=sk_your_actual_key

# Stripe (if using billing)
STRIPE_SECRET_KEY=sk_live_your_key
STRIPE_PUBLIC_KEY=pk_live_your_key

# Environment
ENVIRONMENT=production
LOG_LEVEL=INFO
DEBUG=false

# CORS (set to your domain)
CORS_ORIGINS=https://your-domain.com,https://app.your-domain.com

# Admin Account
INITIAL_ADMIN_EMAIL=admin@your-domain.com
INITIAL_ADMIN_PASSWORD=$(openssl rand -base64 24)

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 24)
ENV

chmod 600 .env.production
echo ".env.production created successfully"
```

### 2. Store Secrets Securely

```bash
# Option 1: Use environment variable file (secure)
source .env.production
export $(cat .env.production | xargs)

# Option 2: Use secret management system
# AWS Secrets Manager
# HashiCorp Vault
# Kubernetes Secrets

# Verify secrets are NOT in shell history
history -c
```

---

## 🗄️ Database Setup

### 1. Prepare PostgreSQL

```bash
# Create data directory
sudo mkdir -p /data/postgres
sudo chown wildbox:wildbox /data/postgres
sudo chmod 700 /data/postgres

# Create backup directory
sudo mkdir -p /data/backups
sudo chown wildbox:wildbox /data/backups
```

### 2. Initialize Databases

```bash
# Start PostgreSQL service
docker-compose up -d postgres

# Wait for startup
sleep 10

# Create databases
docker-compose exec postgres psql -U postgres -c "CREATE DATABASE wildbox;"
docker-compose exec postgres psql -U postgres -c "CREATE DATABASE data;"

# Create dedicated users
docker-compose exec postgres psql -U postgres << SQL
CREATE USER wildbox_app WITH PASSWORD '${DB_PASSWORD}';
CREATE USER data_app WITH PASSWORD '${DB_PASSWORD}';

GRANT CONNECT ON DATABASE wildbox TO wildbox_app;
GRANT CONNECT ON DATABASE data TO data_app;
SQL

# Run migrations
docker-compose exec open-security-identity alembic upgrade head
docker-compose exec open-security-data alembic upgrade head
```

### 3. Configure Backups

```bash
# Create backup script
cat > /home/wildbox/backup.sh << 'SCRIPT'
#!/bin/bash

BACKUP_DIR=/data/backups
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_PASSWORD=${DATABASE_PASSWORD}

# Backup PostgreSQL
docker-compose exec postgres pg_dump -U postgres wildbox | \
  gzip > ${BACKUP_DIR}/wildbox_${TIMESTAMP}.sql.gz

docker-compose exec postgres pg_dump -U postgres data | \
  gzip > ${BACKUP_DIR}/data_${TIMESTAMP}.sql.gz

# Backup Redis (if persistent)
docker-compose exec redis redis-cli BGSAVE
docker cp $(docker-compose ps -q redis):/data/dump.rdb ${BACKUP_DIR}/redis_${TIMESTAMP}.rdb

# Upload to cloud storage (AWS S3 example)
aws s3 cp ${BACKUP_DIR}/ s3://your-backup-bucket/$(hostname)/ --recursive

# Keep last 30 days of local backups
find ${BACKUP_DIR} -mtime +30 -delete

echo "Backup completed: ${BACKUP_DIR}/wildbox_${TIMESTAMP}.sql.gz"
SCRIPT

chmod +x /home/wildbox/backup.sh

# Schedule daily backups
(crontab -l 2>/dev/null; echo "0 2 * * * /home/wildbox/backup.sh") | crontab -
```

---

## 🚀 Service Deployment

### 1. Prepare Environment

```bash
# Go to application directory
cd /home/wildbox/wildbox

# Load environment variables
export $(cat .env.production | xargs)

# Verify secrets are set
env | grep JWT_SECRET
env | grep API_KEY
```

### 2. Build and Start Services

```bash
# Build images
docker-compose build

# Start services (in background)
docker-compose up -d

# Wait for services to be healthy
sleep 30

# Check service status
docker-compose ps

# Verify health checks
curl http://localhost:8000/health
curl http://localhost:8001/health
curl http://localhost:8006/health
```

### 3. Initialize Admin User

```bash
# Create admin user if not auto-created
docker-compose exec open-security-identity python << PYTHON
from app.models import User
from app.db import SessionLocal
from app.auth import get_password_hash

db = SessionLocal()
admin_email = os.getenv("INITIAL_ADMIN_EMAIL")
admin_password = os.getenv("INITIAL_ADMIN_PASSWORD")

if not db.query(User).filter(User.email == admin_email).first():
    admin = User(
        email=admin_email,
        hashed_password=get_password_hash(admin_password),
        is_active=True,
        is_admin=True
    )
    db.add(admin)
    db.commit()
    print(f"Admin user created: {admin_email}")
else:
    print(f"Admin user already exists: {admin_email}")
PYTHON
```

---

## 🔒 SSL/TLS Configuration

### 1. Obtain Certificate

```bash
# Using Let's Encrypt with Certbot
sudo certbot certonly --standalone -d your-domain.com -d app.your-domain.com

# Certificate locations:
# /etc/letsencrypt/live/your-domain.com/fullchain.pem
# /etc/letsencrypt/live/your-domain.com/privkey.pem
```

### 2. Configure Nginx

```bash
# Update nginx configuration
cat > /home/wildbox/wildbox/nginx-config.conf << 'NGINX'
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # Strong SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # CORS
    add_header Access-Control-Allow-Origin "https://your-domain.com" always;
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX
```

### 3. Enable Auto-Renewal

```bash
# Set up cron for certificate renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Test renewal
sudo certbot renew --dry-run
```

---

## 📊 Monitoring & Logging

### 1. Configure Logging

```bash
# Create logging directory
sudo mkdir -p /var/log/wildbox
sudo chown wildbox:wildbox /var/log/wildbox

# Docker logging
cat > /home/wildbox/wildbox/docker-compose.yml << 'YAML'
version: '3.9'
services:
  # ... services ...
  logging:
    driver: "json-file"
    options:
      max-size: "10m"
      max-file: "3"
YAML
```

### 2. Set Up Monitoring

```bash
# Prometheus is already configured in docker-compose
# Access at: http://localhost:9090

# Grafana is configured
# Access at: http://localhost:3001
# Default: admin/admin (change immediately!)

# Create dashboards
# - Service health
# - API response times
# - Error rates
# - Resource usage
```

### 3. Alerting

```yaml
# Configure Prometheus alerts
groups:
  - name: Wildbox Alerts
    rules:
      - alert: ServiceDown
        expr: up{job="wildbox"} == 0
        for: 5m
        annotations:
          summary: "Service {{ $labels.job }} is down"

      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 10m
        annotations:
          summary: "High error rate detected"

      - alert: HighDiskUsage
        expr: node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.1
        annotations:
          summary: "Disk usage critical"
```

---

## 💾 Backup & Recovery

### 1. Test Backups

```bash
# Run backup
/home/wildbox/backup.sh

# Verify backup
ls -lh /data/backups/

# Test restore (on separate server)
gunzip < wildbox_TIMESTAMP.sql.gz | psql -U postgres wildbox
```

### 2. Recovery Procedure

```bash
# 1. Stop services
docker-compose down

# 2. Restore database
gunzip < /data/backups/wildbox_TIMESTAMP.sql.gz | docker-compose exec -T postgres psql -U postgres wildbox

# 3. Restart services
docker-compose up -d

# 4. Verify health
docker-compose ps
curl http://localhost:8000/health
```

---

## ✅ Post-Deployment

### 1. Verify All Services

```bash
# Health checks
for port in 3000 8000 8001 8002 8006 8013 8018; do
  echo "Checking port $port..."
  curl -s http://localhost:$port/health | jq .
done
```

### 2. Security Verification

```bash
# Verify SSL/TLS
openssl s_client -connect your-domain.com:443

# Check security headers
curl -I https://your-domain.com
# Should show HSTS, X-Frame-Options, etc.

# Test CORS
curl -H "Origin: https://your-domain.com" https://your-domain.com/health
```

### 3. Documentation

```bash
# Document deployment
cat > /home/wildbox/DEPLOYMENT_NOTES.md << 'NOTES'
# Deployment Notes

## Date: $(date)
## Server: $(hostname)
## IP: $(hostname -I)

### Deployed Services
- Frontend: https://your-domain.com
- API: https://api.your-domain.com
- Admin: https://admin.your-domain.com

### Credentials Stored
- Admin credentials: [Location]
- Database backups: /data/backups
- SSL certificates: /etc/letsencrypt

### Maintenance Tasks
- [ ] Backup verification (weekly)
- [ ] Security updates (monthly)
- [ ] Certificate renewal (automatic)
- [ ] Log rotation (automatic)
- [ ] Performance review (monthly)
NOTES
```

---

## 🔧 Troubleshooting

### Service Not Starting

```bash
# Check logs
docker-compose logs service-name

# Common issues:
# 1. Port already in use
sudo lsof -i :8000

# 2. Database not ready
docker-compose logs postgres

# 3. Memory issues
free -h
```

### Database Connection Issues

```bash
# Test connection
docker-compose exec postgres psql -U postgres -c "SELECT 1"

# Check password
docker-compose exec postgres psql -U wildbox_app -d wildbox -c "SELECT 1"

# Verify network
docker network ls
docker network inspect wildbox_wildbox
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Check slow queries
docker-compose exec postgres psql -U postgres << SQL
SELECT query, calls, mean_time FROM pg_stat_statements
ORDER BY mean_time DESC LIMIT 10;
SQL

# Monitor real-time
watch -n 1 docker stats
```

---

## 📞 Support

- **Documentation**: SECURITY.md, QUICKSTART.md
- **Issues**: https://github.com/fabriziosalmi/wildbox/issues
- **Security**: security@wildbox.security

---

**Deployment Guide Version**: 1.0
**Last Updated**: November 7, 2024
**Next Review**: February 7, 2025
