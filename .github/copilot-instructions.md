# Wildbox Security Platform - AI Agent Instructions

**Version:** 1.0 | **Last Updated:** October 2025

## 🏗️ Architecture Overview

Wildbox is a microservices-based security operations platform with **11 containerized services** orchestrated through Docker Compose. The gateway acts as the intelligent entry point, routing all requests through OpenResty/Nginx with Lua-based authentication and rate limiting.

### Service Communication Pattern

```
Browser/API Client → Gateway (port 80/443) → Backend Services
                         ↓
                   Identity Service (8001) ← Authentication/Authorization
```

**Critical**: All production traffic MUST flow through the gateway. Direct service access (ports 8000-8019) is for development only.

### Core Services & Ports

| Service | Port | Purpose | Auth Method |
|---------|------|---------|-------------|
| **gateway** | 80/443 | OpenResty API gateway with Lua auth | JWT + API Key |
| **identity** | 8001 | FastAPI auth service (JWT, teams, subscriptions) | JWT internally |
| **api** (tools) | 8000 | FastAPI security tools (55+ tools) | API Key |
| **data** | 8002 | Django threat intelligence & IOCs | API Key |
| **guardian** | 8013 | Django vulnerability management | API Key |
| **responder** | 8018 | FastAPI incident response & playbooks | API Key |
| **agents** | 8006 | FastAPI AI-powered analysis (GPT-4o) | API Key |
| **cspm** | 8019 | FastAPI cloud security (200+ checks) | API Key |
| **sensor** | 8004 | Rust endpoint monitoring (osquery) | Certificate |
| **dashboard** | 3000 | Next.js 14 frontend (App Router) | Session + JWT |
| **automations** | 5678 | n8n workflow automation | Basic Auth |

### Shared Infrastructure

- **postgres**: Single PostgreSQL 15 instance with separate databases (`identity`, `data`, `guardian`, etc.)
- **wildbox-redis**: Single Redis 7 instance with logical database separation (DB 0-15)
  - DB 0: Identity cache
  - DB 1: Guardian cache
  - DB 5: Gateway auth cache
  - etc.

## 🔐 Authentication Architecture

### Gateway-Based Authentication Flow

1. **Request arrives** at gateway with Bearer token or API key
2. **Gateway Lua script** (`/nginx/lua/auth_handler.lua`) extracts token
3. **Identity service validates** via internal `/internal/authorize` endpoint
4. **Gateway injects headers** to backend: `X-Wildbox-User-ID`, `X-Wildbox-Team-ID`, `X-Wildbox-Plan`, `X-Wildbox-Role`
5. **Backend services trust** these headers (never exposed externally)

### API Key Format

```
wsk_<4-char-prefix>.<64-char-hex>
Example: wsk_a3f4.e7d2c8b1...
```

- Generated in identity service via `generate_api_key()` in `app/auth.py`
- Stored as SHA256 hash in database
- Team-scoped with plan-based permissions

### Frontend API Client Pattern

**Dashboard uses gateway-aware clients** (see `src/lib/api-client.ts`):

```typescript
// CORRECT: Uses gateway when NEXT_PUBLIC_USE_GATEWAY=true
const response = await identityClient.get('/auth/me')
// Transforms to: http://gateway/api/v1/identity/auth/me

// INCORRECT: Direct service access in production
const response = await fetch('http://localhost:8001/api/v1/auth/me')
```

**Path transformation rules:**
- Identity: `/api/v1/auth/*` → Gateway: `/auth/*`
- Data: `/api/v1/data/*` → Gateway: `/api/v1/data/*`
- Guardian: `/api/v1/vulnerabilities/*` → Gateway: `/api/v1/guardian/*`

## 🚀 Developer Workflows

### Starting the Platform

```bash
# Full stack (recommended)
docker-compose up -d

# Wait for initialization (critical for first run)
sleep 180

# Verify health
./comprehensive_health_check.sh
```

**First-time setup creates**:
- Default admin user: `admin@wildbox.security` / `CHANGE-THIS-PASSWORD`
- API keys for inter-service communication
- Database schemas via migrations

### Debugging Services

```bash
# View logs for specific service
docker-compose logs -f [service-name]

# Check authentication flow
docker-compose logs -f gateway | grep "auth_handler"

# Monitor gateway routing decisions
docker-compose logs -f gateway | grep "proxy_pass"

# Test service directly (bypassing gateway)
curl http://localhost:8001/health
```

### Common Issues & Fixes

**"Gateway upstream host not found"**: Services starting in wrong order
```bash
docker-compose restart gateway
```

**"Browser cache showing old data"**: Frontend caching issue
```bash
# Clear browser cache or use incognito mode
```

**"Database does not exist"**: Migration not run
```bash
docker-compose exec postgres createdb -U postgres [db-name]
docker-compose restart [service-name]
```

## 📦 Adding New Features

### Creating a New API Endpoint

1. **Backend** (FastAPI example in `identity`):
   ```python
   # app/api_v1/endpoints/new_feature.py
   @router.get("/new-endpoint")
   async def new_endpoint(
       current_user: User = Depends(current_active_user)
   ):
       # Gateway already validated auth
       # Trust X-Wildbox-* headers from gateway
       return {"data": "response"}
   ```

2. **Gateway routing** (add to `nginx/conf.d/wildbox_gateway.conf`):
   ```nginx
   location /api/v1/new-feature/ {
       access_by_lua_block {
           local auth_handler = require "auth_handler"
           auth_handler.authenticate()
       }
       proxy_pass http://identity_service;
   }
   ```

3. **Frontend client** (update `src/lib/api-client.ts`):
   ```typescript
   const newFeatureClient = new ApiClient(
     useGateway 
       ? `${getGatewayUrl()}/api/v1/new-feature`
       : 'http://localhost:8001'
   )
   ```

### Database Migrations

**Identity Service** (Alembic):
```bash
# Create migration
docker-compose exec identity alembic revision -m "description"

# Apply migration
docker-compose exec identity alembic upgrade head
```

**Django Services** (Guardian, Data):
```bash
# Create migration
docker-compose exec guardian python manage.py makemigrations

# Apply migration
docker-compose exec guardian python manage.py migrate
```

## 🧪 Testing Patterns

### Integration Tests

**Location**: `tests/integration/test_*.py`

**Pattern**: Service-specific test classes with health checks first
```python
class ServiceTester:
    def __init__(self, base_url: str = "http://localhost:8002"):
        self.base_url = base_url
        self.test_results = []
    
    async def test_service_health(self) -> bool:
        # Always test health endpoint first
        response = requests.get(f"{self.base_url}/health")
        return response.status_code == 200
```

### E2E Tests (Frontend)

**Location**: `open-security-dashboard/tests/e2e/`

**Framework**: Playwright with Page Object Model

```typescript
// tests/e2e/page-objects/login-page.ts
export class LoginPage {
  async login(email: string, password: string) {
    await this.emailInput.fill(email)
    await this.passwordInput.fill(password)
    await this.loginButton.click()
  }
}

// tests/e2e/feature.spec.ts
test('Complete workflow', async ({ page }) => {
  const loginPage = new LoginPage(page)
  await loginPage.goto()
  await loginPage.login(testEmail, testPassword)
  // Test feature
})
```

**Run tests**:
```bash
cd open-security-dashboard
npx playwright test --project=chromium
npx playwright test --headed  # See browser
npx playwright show-report    # View results
```

### Health Check Script

**Use before testing**: `./comprehensive_health_check.sh`

Validates:
- All containers running
- Database connectivity (postgres, redis)
- Service health endpoints responding
- Known issues auto-fixed

## 🔧 Project-Specific Conventions

### Environment Variables

**Never commit** `.env` files. Use `.env.example` as template.

**Critical variables**:
- `JWT_SECRET_KEY`: Identity service token signing
- `GATEWAY_INTERNAL_SECRET`: Gateway → Identity auth
- `DATABASE_URL`: PostgreSQL connection strings
- `REDIS_URL`: Redis connection (same instance, different DBs)

### Docker Compose Commands

**Always use** `docker-compose` (not `docker compose`) for consistency:
```bash
docker-compose up -d        # Start services
docker-compose logs -f api  # Follow logs
docker-compose restart api  # Restart one service
docker-compose down -v      # Stop and remove volumes (destructive)
```

### Code Style

- **Python**: FastAPI with Pydantic models, async/await, type hints
- **TypeScript**: Next.js App Router, React Server Components where possible
- **Lua**: OpenResty Nginx scripting (gateway logic)

### API Response Format

**Consistent across services**:
```json
{
  "status": "success|error",
  "data": { ... },
  "message": "Human-readable description",
  "timestamp": "ISO8601"
}
```

## 📚 Key Files Reference

### Gateway Configuration
- `open-security-gateway/nginx/nginx.conf`: Main OpenResty config
- `open-security-gateway/nginx/conf.d/wildbox_gateway.conf`: Service routing
- `open-security-gateway/nginx/lua/auth_handler.lua`: Authentication logic
- `open-security-gateway/nginx/lua/utils.lua`: Shared utilities

### Identity Service
- `open-security-identity/app/auth.py`: JWT/API key generation & validation
- `open-security-identity/app/internal.py`: Gateway authorization endpoint
- `open-security-identity/app/api_v1/endpoints/auth.py`: Public auth endpoints

### Frontend
- `open-security-dashboard/src/lib/api-client.ts`: Gateway-aware API clients
- `open-security-dashboard/src/app/api/`: Next.js API routes (SSR)
- `open-security-dashboard/next.config.js`: Proxy & CORS config

### Infrastructure
- `docker-compose.yml`: Service orchestration & dependencies
- `comprehensive_health_check.sh`: Health validation & auto-fix
- `system_monitor.sh`: Performance & resource monitoring

## ⚠️ Security Best Practices

1. **Never bypass the gateway** in production
2. **Trust gateway headers** (`X-Wildbox-*`) only in backend services
3. **Clear gateway headers** before forwarding to prevent spoofing (handled in Lua)
4. **API keys are team-scoped** - check team_id matches
5. **Passwords hashed with bcrypt** - use `pwd_context` from identity service
6. **Rate limiting enforced** at gateway based on subscription plan

## 🎯 Common Tasks Quick Reference

```bash
# Add new Python dependency
echo "package==version" >> open-security-[service]/requirements.txt
docker-compose up -d --build [service]

# View real-time logs across services
docker-compose logs -f | grep ERROR

# Reset database (destructive)
docker-compose down -v
docker-compose up -d postgres wildbox-redis
# Wait 10s, then start other services

# Check gateway auth cache
docker-compose exec wildbox-redis redis-cli
> SELECT 5
> KEYS auth:*

# Rebuild single service
docker-compose up -d --build --no-deps [service]
```

---

**For questions about specific components**, check the README in each service directory (e.g., `open-security-identity/README.md`).
