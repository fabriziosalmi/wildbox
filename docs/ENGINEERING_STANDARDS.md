# Wildbox Engineering Standards

**Version:** 2.0  
**Last Updated:** November 23, 2025  
**Status:** ENFORCED

---

## Overview

This document establishes **mandatory engineering standards** for the Wildbox Security Platform. These standards address critical issues identified in security audits and ensure production-grade quality.

## 🔐 Security Standards

### 1. Secret Management (CRITICAL)

**Status:** All violations have been remediated as of November 2025.

#### Rules

✅ **DO:**
- Store ALL secrets in `.env` files (never committed to Git)
- Use environment variable injection: `${VARIABLE_NAME}`
- Provide `.env.example` with placeholder values
- Generate cryptographic-quality secrets:
  ```bash
  # JWT/API keys (hex)
  openssl rand -hex 32
  
  # Passwords (base64)
  openssl rand -base64 24
  ```

❌ **DON'T:**
- Hardcode secrets in `docker-compose.yml`
- Use default fallback values for production secrets
- Commit `.env` files to version control
- Use weak secrets like "admin123" or "password"

#### Required .env Variables

```bash
# Authentication (CRITICAL)
JWT_SECRET_KEY=<openssl rand -hex 32>
NEXTAUTH_SECRET=<openssl rand -base64 32>
GATEWAY_INTERNAL_SECRET=<openssl rand -hex 32>

# N8N Automation
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=<openssl rand -base64 24>

# Database
POSTGRES_PASSWORD=<openssl rand -base64 32>

# Monitoring
GRAFANA_ADMIN_PASSWORD=<openssl rand -base64 24>

# API Keys
API_KEY=<openssl rand -hex 32>
```

### 2. Dependency Pinning (CRITICAL)

**Status:** Enforced across all services as of November 2025.

#### Docker Images

✅ **DO:**
```yaml
image: ollama/ollama:0.4.7
image: n8nio/n8n:1.74.0
image: grafana/grafana:11.4.0
image: prom/prometheus:v2.55.1
```

❌ **DON'T:**
```yaml
image: ollama/ollama:latest
image: n8nio/n8n:latest
```

**Rationale:** `:latest` tags are mutable and can introduce breaking changes without warning.

#### Python Dependencies

✅ **DO:**
```python
fastapi==0.115.5
pydantic==2.10.3
requests==2.32.3
```

❌ **DON'T:**
```python
fastapi>=0.104.1
pydantic>=2.5.0
requests>=2.31.0
```

**Rationale:** Pinned versions ensure reproducible builds and prevent supply chain attacks.

### 3. Input Validation (HIGH PRIORITY)

#### API Endpoints

**All user input MUST be validated using Pydantic models:**

```python
from pydantic import BaseModel, Field, validator
from typing import Optional

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    scan_type: str = Field(..., regex="^(port|vuln|ssl)$")
    
    @validator('target')
    def validate_target(cls, v):
        # Implement domain/IP validation
        if not is_valid_domain_or_ip(v):
            raise ValueError('Invalid target format')
        return v

@router.post("/scan")
async def create_scan(request: ScanRequest):
    # Input already validated by Pydantic
    pass
```

**Dashboard forms:**
```typescript
import { z } from 'zod'

const scanSchema = z.object({
  target: z.string().min(1).max(255).refine(isValidDomainOrIP),
  scanType: z.enum(['port', 'vuln', 'ssl'])
})
```

---

## 🧪 Quality Assurance Standards

### 1. Test Suite Integrity (CRITICAL)

**Status:** Fixed as of November 2025.

#### Makefile Test Commands

✅ **DO:**
```makefile
test:
	@failed=0; \
	for dir in open-security-*/; do \
		if ! $(MAKE) -C $$dir test; then \
			failed=1; \
		fi; \
	done; \
	if [ $$failed -eq 1 ]; then \
		exit 1; \
	fi
```

❌ **DON'T:**
```makefile
test:
	@for dir in open-security-*/; do \
		$(MAKE) -C $$dir test || true; \
	done
```

**Rationale:** `|| true` silences test failures, making the CI/CD pipeline worthless.

### 2. Error Handling (HIGH PRIORITY)

#### Specific Exception Handling

✅ **DO:**
```python
import asyncio
from aiohttp import ClientError, ClientTimeout
from pydantic import ValidationError

async def fetch_data(url: str) -> dict:
    """Fetch data with proper error handling."""
    max_retries = 3
    retry_delay = 1.0
    
    for attempt in range(max_retries):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=ClientTimeout(total=10)) as response:
                    response.raise_for_status()
                    return await response.json()
                    
        except ClientTimeout:
            logger.warning(f"Timeout fetching {url} (attempt {attempt+1}/{max_retries})")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay * (2 ** attempt))
            else:
                raise TimeoutError(f"Failed to fetch {url} after {max_retries} attempts")
                
        except ClientError as e:
            logger.error(f"HTTP error fetching {url}: {e}")
            raise
            
        except ValidationError as e:
            logger.error(f"Invalid response format from {url}: {e}")
            raise
```

❌ **DON'T:**
```python
async def fetch_data(url: str) -> dict:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                return await response.json()
    except Exception as e:
        logger.error(f"Error: {e}")
        return {}  # Silent failure!
```

**Problems with blanket exception handling:**
1. Masks the actual error type
2. Makes debugging impossible
3. Prevents proper error recovery
4. Silently fails instead of failing fast

#### Logging Best Practices

```python
import structlog
logger = structlog.get_logger()

# Include context in logs
logger.info("scan_initiated", 
    target=target, 
    scan_type=scan_type,
    user_id=user_id
)

# Log errors with full context
try:
    result = await execute_scan(target)
except ScanError as e:
    logger.error("scan_failed",
        target=target,
        error_type=type(e).__name__,
        error_message=str(e),
        traceback=traceback.format_exc()
    )
    raise
```

---

## 📊 Observability Standards

### 1. Health Metrics (HIGH PRIORITY)

**Status:** Dashboard currently uses mock data (to be fixed).

#### Real Metrics Implementation

✅ **DO:**
```typescript
// Fetch real metrics from services
const metrics = await Promise.all([
  identityClient.get('/metrics'),
  guardiansClient.get('/metrics'),
  dataClient.get('/metrics')
])

const systemHealth = {
  services: metrics.map(m => m.data),
  timestamp: new Date().toISOString()
}
```

❌ **DON'T:**
```typescript
// Hardcoded "approximate" metrics
const systemHealth = {
  apiRequestsToday: Math.floor(Math.random() * 1000) + 500,
  uptime: "99.9%"  // Fake data!
}
```

#### Health Check Endpoints

**Every service MUST expose:**
```python
@router.get("/health")
async def health_check():
    """Health check with real status."""
    return {
        "status": "healthy",
        "service": "guardian",
        "version": "0.2.0",
        "timestamp": datetime.utcnow().isoformat(),
        "dependencies": {
            "database": await check_db_connection(),
            "redis": await check_redis_connection()
        }
    }

@router.get("/metrics")
async def get_metrics():
    """Prometheus-compatible metrics."""
    return {
        "requests_total": request_counter,
        "requests_failed": error_counter,
        "response_time_avg": avg_response_time,
        "active_scans": len(active_scans)
    }
```

### 2. Monitoring Integration

**Required tools:**
- **Prometheus:** Metrics collection (already configured)
- **Grafana:** Visualization dashboards (already configured)
- **Structured logging:** `structlog` for all Python services

---

## 🏗️ Architecture Standards

### 1. Service Communication

**Gateway-based routing is MANDATORY in production:**

```typescript
// ✅ Correct: Uses gateway
const client = new ApiClient(
  useGateway ? `${GATEWAY_URL}/api/v1/identity` : 'http://localhost:8001'
)

// ❌ Wrong: Direct service access in production
fetch('http://identity:8001/api/v1/auth/me')
```

### 2. Resource Limits

**All Docker services MUST have resource limits:**

```yaml
services:
  llm:
    image: ollama/ollama:0.4.7
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

---

## 📝 Documentation Standards

### 1. Code Comments

**Document WHY, not WHAT:**

```python
# ❌ Bad: States the obvious
# Loop through users
for user in users:
    process(user)

# ✅ Good: Explains the reason
# Process users in batches to avoid memory exhaustion
# with large datasets (10k+ users)
for batch in chunk(users, batch_size=100):
    process_batch(batch)
```

### 2. API Documentation

**All endpoints MUST have OpenAPI docs:**

```python
@router.post("/scan", 
    summary="Create security scan",
    description="Initiates a security scan of the specified target",
    response_model=ScanResponse,
    status_code=201
)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(current_active_user)
) -> ScanResponse:
    """
    Create a new security scan.
    
    Args:
        request: Scan configuration (target, type, options)
        background_tasks: FastAPI background task manager
        current_user: Authenticated user from JWT
        
    Returns:
        ScanResponse with scan_id and status
        
    Raises:
        ValidationError: Invalid target format
        RateLimitExceeded: User exceeded scan quota
    """
```

---

## 🚀 CI/CD Standards

### 1. Pre-commit Checks

**Create `.pre-commit-config.yaml`:**

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: check-yaml
      - id: check-added-large-files
      - id: detect-private-key
      - id: end-of-file-fixer
      - id: trailing-whitespace

  - repo: https://github.com/psf/black
    rev: 24.10.0
    hooks:
      - id: black
        language_version: python3.11

  - repo: https://github.com/pycqa/flake8
    rev: 7.1.1
    hooks:
      - id: flake8
        args: ['--max-line-length=100']
```

### 2. GitHub Actions

**Required workflows:**
- ✅ `test.yml`: Run all tests on PR
- ✅ `security-scan.yml`: Dependency and container scanning
- ✅ `lint.yml`: Code quality checks
- ⚠️  `integration.yml`: Currently disabled (requires environment setup)

---

## 📋 Remediation Checklist

### Completed (November 2025)

- [x] Remove all hardcoded secrets from docker-compose files
- [x] Add secrets to .env.example with generation instructions
- [x] Pin all Docker image versions (no `:latest` tags)
- [x] Pin all Python dependencies to exact versions
- [x] Fix Makefile test suite (remove `|| true`)
- [x] Fix security-check command (proper error handling)

### In Progress

- [ ] Replace blanket `except Exception` with specific error handling
- [ ] Remove mock data from dashboard (use real service metrics)
- [ ] Add Prometheus metrics endpoints to all services
- [ ] Implement retry logic with exponential backoff

### Planned

- [ ] Add pre-commit hooks for automated checks
- [ ] Create Grafana dashboards for all services
- [ ] Implement distributed tracing (OpenTelemetry)
- [ ] Add rate limiting at gateway level
- [ ] Implement circuit breakers for external API calls

---

## 🎯 Success Metrics

**Target improvements from D- (41/100) audit score:**

| Category | Before | Target | Status |
|----------|--------|--------|--------|
| Security | 6/20 | 18/20 | 🟢 In Progress |
| Core Engineering | 7/20 | 16/20 | 🟡 Partial |
| QA & Operations | 10/20 | 18/20 | 🟢 In Progress |
| Architecture | 9/20 | 15/20 | 🟢 Stable |
| Performance | 9/20 | 14/20 | 🟡 Planned |

**Overall target: B+ (80/100) by Q1 2026**

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [12-Factor App](https://12factor.net/)
- [Pydantic Validation](https://docs.pydantic.dev/latest/)
- [FastAPI Best Practices](https://fastapi.tiangolo.com/tutorial/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)

---

**Enforcement:** All pull requests MUST comply with these standards or be rejected.
