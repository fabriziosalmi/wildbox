# 🔐 Wildbox Default Credentials & Setup

**⚠️ WARNING**: Default credentials are for development only. Change them immediately for any non-development environment.

---

## 📋 Default Credentials

### Dashboard & Web UI
| Service | URL | Username | Password | Notes |
|---------|-----|----------|----------|-------|
| **Grafana** | http://localhost:3001 | admin | admin | Change immediately |
| **Prometheus** | http://localhost:9090 | N/A | N/A | No auth (local only) |

### API Services
| Service | Port | Default API Key | Purpose |
|---------|------|-----------------|---------|
| **API Gateway** | 8000 | `dev-api-key-123` | Tools & Intelligence APIs |
| **Identity Service** | 8001 | N/A | Authentication & Users |
| **Threat Intel** | 8002 | `dev-threat-key` | Threat Intelligence |
| **Sensor Gateway** | 8004 | N/A | Endpoint Agent Communication |
| **Agents Service** | 8006 | `dev-agents-key` | AI-Powered Analysis |
| **Responder** | 8018 | N/A | Incident Response |
| **CSPM** | 8019 | N/A | Cloud Security |

### Database Credentials
| Database | Host | Port | Username | Password | Database |
|----------|------|------|----------|----------|----------|
| **PostgreSQL** | postgres | 5432 | postgres | postgres | wildbox |
| **Redis** | redis | 6379 | N/A | N/A | N/A |

---

## 🔧 Environment Variable Template

Create a `.env` file in the project root:

```env
# ============================================
# DATABASE CONFIGURATION
# ============================================
DATABASE_URL=postgresql+asyncpg://postgres:postgres@postgres:5432/wildbox
DATABASE_HOST=postgres
DATABASE_PORT=5432
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres
DATABASE_NAME=wildbox

# ============================================
# REDIS CONFIGURATION
# ============================================
REDIS_URL=redis://redis:6379/0
REDIS_HOST=redis
REDIS_PORT=6379

# ============================================
# SECURITY & API KEYS
# ============================================
# JWT Secret (minimum 32 characters, change for production)
JWT_SECRET_KEY=your-secure-jwt-secret-key-min-32-chars-change-this

# API Keys (change for production)
API_KEY=dev-api-key-123
THREAT_INTEL_API_KEY=dev-threat-key
AGENTS_API_KEY=dev-agents-key
SENSOR_API_KEY=dev-sensor-key

# ============================================
# OPENAI CONFIGURATION (OPTIONAL)
# ============================================
# Set to enable AI-powered features
OPENAI_API_KEY=sk-your-actual-openai-key-or-leave-empty
OPENAI_MODEL=gpt-4o-mini
OPENAI_TEMPERATURE=0.7

# ============================================
# STRIPE INTEGRATION (OPTIONAL)
# ============================================
# Leave empty or set to test keys for development
STRIPE_SECRET_KEY=sk_test_your_stripe_test_key
STRIPE_PUBLIC_KEY=pk_test_your_stripe_test_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# ============================================
# APPLICATION SETTINGS
# ============================================
ENVIRONMENT=development
LOG_LEVEL=INFO
CORS_ORIGINS=http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000
FRONTEND_URL=http://localhost:3000

# ============================================
# MONITORING & OBSERVABILITY
# ============================================
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
GRAFANA_ADMIN_PASSWORD=admin

# ============================================
# CELERY / TASK QUEUE
# ============================================
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2
CELERY_WORKER_CONCURRENCY=4
```

---

## 👤 Default User Accounts

### Admin User (Initial Setup)
```
Email: admin@wildbox.local
Password: (generated during first run)
Role: Administrator
```

### Test User (Demo Account)
```
Email: demo@wildbox.local
Password: demo-password-123
Role: Analyst
```

---

## 🔑 API Authentication Examples

### 1. Get JWT Token (Bearer Token)

```bash
# Request authentication token
curl -X POST http://localhost:8001/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@wildbox.local&password=your-password"

# Response:
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}

# Export token for use in subsequent requests
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 2. Use Bearer Token in API Requests

```bash
# Example: Query threat intelligence
curl -X GET http://localhost:8002/v1/indicators \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# Example: Submit analysis task
curl -X POST http://localhost:8006/v1/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc": {"type": "ip", "value": "8.8.8.8"},
    "priority": "high"
  }'
```

### 3. Use API Key (for service-to-service)

```bash
# Example with API key header
curl -X GET http://localhost:8000/v1/tools \
  -H "X-API-Key: dev-api-key-123" \
  -H "Content-Type: application/json"
```

---

## 🔐 Secure Your Deployment

### 1. Change Default Passwords Immediately

```bash
# Change PostgreSQL password
docker-compose exec postgres \
  psql -U postgres -c "ALTER USER postgres WITH PASSWORD 'new-secure-password';"

# Update .env
sed -i 's/DATABASE_PASSWORD=postgres/DATABASE_PASSWORD=new-secure-password/' .env

# Restart services
docker-compose restart
```

### 2. Generate Secure JWT Secret

```bash
# Generate random 32+ character secret
openssl rand -hex 32

# Update .env with the output
JWT_SECRET_KEY=<paste-output-here>
```

### 3. Generate Secure API Keys

```bash
# Generate random API key
openssl rand -hex 32

# Use for API_KEY in .env
API_KEY=<paste-output-here>
```

### 4. Update CORS Origins (Production)

```env
# For production, specify exact allowed origins
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

### 5. Enable HTTPS/TLS

See `nginx-config.conf` for SSL certificate configuration.

---

## 🆔 Account Management

### Create New User

```bash
# Access identity service
docker-compose exec open-security-identity bash

# Run user creation script
python -c "
from app.db import SessionLocal
from app.models import User
from passlib.context import CryptContext

db = SessionLocal()
pwd_context = CryptContext(schemes=['bcrypt'])

new_user = User(
    email='newuser@wildbox.local',
    hashed_password=pwd_context.hash('initial-password'),
    is_active=True,
    role='analyst'
)
db.add(new_user)
db.commit()
print(f'User created: {new_user.email}')
"
```

### Reset User Password

```bash
# Access identity service
docker-compose exec open-security-identity bash

# Run password reset script
python -c "
from app.db import SessionLocal
from app.models import User
from passlib.context import CryptContext

db = SessionLocal()
pwd_context = CryptContext(schemes=['bcrypt'])

user = db.query(User).filter(User.email == 'admin@wildbox.local').first()
if user:
    user.hashed_password = pwd_context.hash('new-password-here')
    db.commit()
    print(f'Password updated for {user.email}')
"
```

### List All Users

```bash
# Access identity service
docker-compose exec open-security-identity bash

# Query users
python -c "
from app.db import SessionLocal
from app.models import User

db = SessionLocal()
users = db.query(User).all()
for user in users:
    print(f'{user.email} - Role: {user.role} - Active: {user.is_active}')
"
```

---

## 🔄 Token Management

### JWT Token Structure

Wildbox uses JWT (JSON Web Tokens) for authentication:

```
Header: {"alg": "HS256", "typ": "JWT"}
Payload: {
  "sub": "admin@wildbox.local",
  "iat": 1699365600,
  "exp": 1699369200,  # Expires in 1 hour
  "scope": ["read", "write"]
}
Signature: HMACSHA256(header.payload, secret)
```

### Token Expiration & Refresh

```bash
# Tokens expire after 1 hour by default
# To get a new token, authenticate again
curl -X POST http://localhost:8001/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@wildbox.local&password=password"
```

### Revoke Tokens

```bash
# Logout (invalidates token)
curl -X POST http://localhost:8001/logout \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🚨 Security Best Practices

### ✅ DO:
- ✓ Change all default credentials before production use
- ✓ Use strong passwords (min 16 characters, mix of cases/numbers/symbols)
- ✓ Store API keys securely (use secrets manager)
- ✓ Rotate credentials regularly (monthly recommended)
- ✓ Enable HTTPS/TLS in production
- ✓ Use environment variables for all secrets
- ✓ Implement rate limiting on authentication endpoints
- ✓ Enable audit logging for user actions
- ✓ Use separate credentials for each environment

### ❌ DON'T:
- ✗ Hardcode credentials in code or config files
- ✗ Commit .env files to git
- ✗ Use same credentials across environments
- ✗ Share credentials via email or chat
- ✗ Use default/demo passwords in production
- ✗ Run with debug mode enabled in production
- ✗ Expose sensitive logs publicly
- ✗ Store passwords in plaintext
- ✗ Use HTTP without TLS in production

---

## 🆘 Troubleshooting

### Cannot login with default credentials

```bash
# Check if user exists
docker-compose exec postgres \
  psql -U postgres -d wildbox -c "SELECT email, is_active FROM users;"

# Create admin user if missing
docker-compose exec open-security-identity python -c "
from app.db import SessionLocal
from app.models import User
from passlib.context import CryptContext

db = SessionLocal()
pwd_context = CryptContext(schemes=['bcrypt'])

admin = User(
    email='admin@wildbox.local',
    hashed_password=pwd_context.hash('admin-password-123'),
    is_active=True,
    role='admin'
)
db.add(admin)
db.commit()
print('Admin user created')
"
```

### API Key not working

```bash
# Verify API key is set in environment
docker-compose exec open-security-tools env | grep API_KEY

# Update .env and restart
echo "API_KEY=dev-api-key-123" >> .env
docker-compose restart open-security-tools
```

---

## 📞 Support

For credential-related issues:
1. Check this file first
2. Review [Quick Start Guide](quickstart.md)
3. Check [README.md](../../README.md)
4. Open an issue on GitHub

---

**Remember**: Always change default credentials before using in any environment!
