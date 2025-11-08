---
sidebar_position: 1
---

# Quick Start Guide

Get Wildbox running in 5 minutes with Docker Compose!

:::info Early Evaluation Phase
Wildbox is actively seeking community feedback, bug reports, and feature suggestions. [Report issues](https://github.com/fabriziosalmi/wildbox/issues) and [share feedback](https://github.com/fabriziosalmi/wildbox/discussions) to help us build the platform the community needs.
:::

## Prerequisites

Before starting, ensure you have:

- **Docker**: [Install Docker](https://docs.docker.com/get-docker/) (Desktop or Server)
- **Docker Compose**: [Install Docker Compose](https://docs.docker.com/compose/install/)
- **Git**: [Install Git](https://git-scm.com/)
- **Minimum Resources**: 8GB RAM, 20GB disk space

**Check your installations:**
```bash
docker --version
docker-compose --version
git --version
```

## Step 1: Clone the Repository

```bash
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox
```

## Step 2: Configure Environment

Create environment files for services:

```bash
# Copy example environment file
cp .env.example .env

# Edit with your secure values
nano .env
```

**Essential environment variables:**

```env title=".env"
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

:::warning Security Note
Never use default credentials in production! Generate secure random values for all secrets.
:::

## Step 3: Start All Services

### Option A: Run Everything (Recommended)

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
# Start only core services
docker-compose up -d postgres redis nginx open-security-identity open-security-tools

# Or start individual services
docker-compose up -d postgres redis
sleep 10  # Wait for databases
docker-compose up -d open-security-identity open-security-tools
```

## Step 4: Verify Installation

Once services are running, verify they're healthy:

```bash
# Check API health
curl http://localhost:8000/health
curl http://localhost:8001/health
curl http://localhost:8006/health

# Expected response:
# {"status":"healthy","timestamp":"2024-11-08T...","version":"1.0.0"}
```

## Step 5: Access the Dashboard

Open your browser and navigate to:

| Service | URL | Default Credentials |
|---------|-----|-------------------|
| **Dashboard** | http://localhost:3000 | See [Credentials Guide](./credentials) |
| **API Docs** | http://localhost:8000/docs | N/A |
| **Prometheus** | http://localhost:9090 | N/A |
| **Grafana** | http://localhost:3001 | admin / admin |

## Step 6: First-Time Login

### Get Admin Token

```bash
curl -X POST http://localhost:8001/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@wildbox.local",
    "password": "your-admin-password"
  }'
```

Use the returned token for API requests:

```bash
export TOKEN="your-token-here"

curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/tools
```

## Quick Test

Run a quick security scan to test the platform:

```bash
# List available tools
curl http://localhost:8000/api/v1/tools

# Execute a simple tool
curl -X POST http://localhost:8000/api/v1/tools/whois/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"domain": "example.com"}'
```

## Next Steps

Now that Wildbox is running:

1. 📖 **[Explore Components](../components/overview)** - Learn about each service
2. 🏗️ **[Understand Architecture](../architecture/overview)** - See how it all fits together
3. 🔌 **[Browse API Reference](../api-reference/overview)** - Integrate with your tools
4. 🛡️ **[Review Security Guide](../security/policy)** - Harden your deployment
5. 🚀 **[Production Deployment](./deployment)** - Deploy to production

## Troubleshooting

### Services Won't Start

```bash
# Check logs for specific service
docker-compose logs [service-name]

# Verify port availability
netstat -tulpn | grep [port]

# Check system resources
docker system df
docker stats
```

### Database Connection Issues

```bash
# Test database connectivity
docker exec -it wildbox-postgres psql -U wildbox -d wildbox -c "SELECT 1;"

# Check database logs
docker-compose logs postgres
```

### Authentication Problems

```bash
# Verify API key configuration
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8001/api/v1/auth/verify

# Reset authentication if needed
docker-compose exec identity python manage.py reset-auth
```

## Getting Help

- 💬 [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions) - Ask questions
- 🐛 [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues) - Report bugs
- 📧 [Email Support](mailto:fabrizio.salmi@gmail.com) - Security issues only

---

**🎉 Congratulations!** Wildbox is now running. Happy hunting! 🛡️
