# Wildbox Security Platform - AI Agent Instructions

**Version:** 1.0 | **Last Updated:** October 2025

## 🏗️ Architecture Overview

Wildbox is a microservices-based security operations platform: ten services and an optional n8n, run as **18 containers** by the default Docker Compose stack. The gateway acts as the intelligent entry point, routing all requests through OpenResty/Nginx with Lua-based authentication and rate limiting.

### Service Communication Pattern

```text
Browser/API Client → Gateway (port 80/443) → Backend Services
                         ↓
                   Identity Service (8001) ← Authentication/Authorization
```

**Critical**: All production traffic MUST flow through the gateway. Direct service access (ports 8000-8019) is for development only.

### Core Services & Ports

| Service | Port | Purpose | Auth Method |
| --------- | ------ | --------- | ------------- |
| **gateway** | 80/443 | OpenResty API gateway with Lua auth | JWT + API Key |
| **identity** | 8001 | FastAPI auth service (JWT, teams, subscriptions) | JWT internally |
| **api** (tools) | 8000 | FastAPI security tools (52 tools) | API Key |
| **data** | 8002 | FastAPI threat intelligence & IOCs | API Key |
| **guardian** | 8013 | Django vulnerability management | API Key |
| **responder** | 8018 | FastAPI incident response & playbooks | API Key |
| **agents** | 8006 | FastAPI AI-assisted analysis (Anthropic API; optional `ANTHROPIC_API_KEY`) | API Key |
| **cspm** | 8019 | FastAPI cloud security (22 AWS checks) | API Key |
| **sensor** | 8004 | Python (aiohttp) host telemetry agent with osquery; not routed by the gateway | API key on its local API |
| **dashboard** | 3000 | Next.js 16 frontend (App Router) | Session + JWT |
| **automations** | 5678 | n8n workflow automation | n8n's own accounts; not behind the gateway |

### Shared Infrastructure

- **postgres**: Single PostgreSQL 15 instance with separate databases (`identity`, `data`, `guardian`, etc.)
- **wildbox-redis**: Single Redis 7 instance with logical database separation (DB 0-15)
  - DB 0: identity
  - DB 1: guardian
  - DB 2: tools and responder
  - DB 3: CSPM
  - DB 4: agents
  - The gateway does not use Redis: its authorization cache is nginx shared memory (`lua_shared_dict auth_cache`)

## 🔐 Authentication Architecture

### Gateway-Based Authentication Flow

1. **Request arrives** at gateway with Bearer token or API key
2. **Gateway Lua script** (`/nginx/lua/auth_handler.lua`) extracts token
3. **Identity service validates** via internal `/internal/authorize` endpoint
4. **Gateway injects headers** to backend: `X-Wildbox-User-ID`, `X-Wildbox-Team-ID`, `X-Wildbox-Role`, `X-Wildbox-Auth-Type` and, for an API key, `X-Wildbox-Scopes`
5. **Backend services trust** these headers (never exposed externally)

### API Key Format

```yaml
wsk_<4-char-prefix>.<64-char-hex>
Example: wsk_a3f4.e7d2c8b1...
```

- Generated in identity service via `generate_api_key()` in `app/auth.py`
- Stored as an HMAC-SHA256 keyed with `API_KEY_HASH_SECRET`
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
# Full stack (recommended); returns when every service is healthy
docker compose up -d --wait --wait-timeout 600

# Verify health (non-zero exit when a service is unhealthy)
make health
```

**First-time setup creates**:

- The initial admin, from `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` in `.env` (`make generate-secrets` generates the password; there is no default)
- API keys for inter-service communication
- Database schemas via migrations

### Debugging Services

```bash
# View logs for specific service
docker compose logs -f [service-name]

# Check authentication flow
docker compose logs -f gateway | grep "auth_handler"

# Monitor gateway routing decisions
docker compose logs -f gateway | grep "proxy_pass"

# Test service directly (bypassing gateway)
curl http://localhost:8001/health
```

### Common Issues & Fixes

**"Gateway upstream host not found"**: Services starting in wrong order

```bash
docker compose restart gateway
```

**"Browser cache showing old data"**: Frontend caching issue

```bash
# Clear browser cache or use incognito mode
```

**"Database does not exist"**: Migration not run

```bash
docker compose exec postgres createdb -U postgres [db-name]
docker compose restart [service-name]
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

   Then add a row for the path to `ROUTE_SCOPES` in
   `nginx/lua/auth_handler.lua`: a path without one requires the `admin`
   scope. `test/route_scope_tests.sh` and `test/upstream_header_tests.sh`
   fail until the new location is pinned and classified.

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
docker compose exec identity alembic revision -m "description"

# Apply migration
docker compose exec identity alembic upgrade head
```

**Django service** (Guardian; data is FastAPI with Alembic migrations):

```bash
# Create migration
docker compose exec guardian python manage.py makemigrations

# Apply migration
docker compose exec guardian python manage.py migrate
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

**Use before testing**: `./scripts/shell-scripts/comprehensive_health_check.sh`

Validates:

- Database connectivity (postgres, redis)
- Every service health URL answers 2xx (redirects are not followed)

It exits non-zero when a check fails. Repairs for known issues run only with
the `fix` argument.

## 🔧 Project-Specific Conventions

### Environment Variables

**Never commit** `.env` files. Use `.env.example` as template.

**Critical variables**:

- `JWT_SECRET_KEY`: Identity service token signing
- `GATEWAY_INTERNAL_SECRET`: Gateway → Identity auth
- `DATABASE_URL`: PostgreSQL connection strings
- `REDIS_URL`: Redis connection (same instance, different DBs)

### Docker Compose Commands

**Always use** `docker compose` (the Compose plugin, 2.24.4 or later), not the legacy `docker-compose` binary:

```bash
docker compose up -d        # Start services
docker compose logs -f api  # Follow logs
docker compose restart api  # Restart one service
docker compose down -v      # Stop and remove volumes (destructive)
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
- `open-security-identity/app/api_v1/endpoints/`: `users.py`, `api_keys.py`, `user_api_keys.py`, `analytics.py`

### Frontend

- `open-security-dashboard/src/lib/api-client.ts`: Gateway-aware API clients
- `open-security-dashboard/src/app/api/`: Next.js API routes (SSR)
- `open-security-dashboard/next.config.js`: Proxy & CORS config

### Infrastructure

- `docker-compose.yml`: Service orchestration & dependencies
- `scripts/shell-scripts/comprehensive_health_check.sh`: Health validation (`make health`)
- `scripts/lib/health_endpoints.sh`: The table of health URLs the scripts share

## ⚠️ Security Best Practices

1. **Never bypass the gateway** in production
2. **Trust gateway headers** (`X-Wildbox-*`) only in backend services
3. **Clear gateway headers** before forwarding to prevent spoofing (handled in Lua)
4. **API keys are team-scoped** - check team_id matches
5. **Passwords are hashed with Argon2id** (legacy bcrypt hashes still verify) - use `password_helper` from `app/auth.py`
6. **Rate limiting enforced** at the gateway: per team (`RATE_LIMIT_PER_HOUR`) and per client address (`GATEWAY_RATE_LIMIT_PER_SECOND`, `GATEWAY_AUTH_RATE_LIMIT_PER_SECOND`, `GATEWAY_STATIC_RATE_LIMIT_PER_SECOND`); there are no plans

## 🎯 Common Tasks Quick Reference

```bash
# Add new Python dependency
# edit open-security-[service]/requirements.in, then compile the hash-pinned lock
./scripts/compile_requirements.sh   # or: make lock
docker compose up -d --build [service]

# View real-time logs across services
docker compose logs -f | grep ERROR

# Reset database (destructive)
docker compose down -v
docker compose up -d postgres wildbox-redis
# Wait 10s, then start other services

# Rebuild single service
docker compose up -d --build --no-deps [service]
```

---

**For questions about specific components**, check the README in each service directory (e.g., `open-security-identity/README.md`).
