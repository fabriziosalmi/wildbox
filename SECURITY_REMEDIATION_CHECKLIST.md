# Security Remediation Checklist

**Last Updated**: November 7, 2024  
**Audit Date**: November 7, 2024

---

## CRITICAL FIXES (Must Complete Within 24 Hours)

### [ ] 1. Fix eval() Code Injection Vulnerability

**File**: `open-security-agents/app/main.py`

**Step 1: Backup current code**
```bash
cp open-security-agents/app/main.py open-security-agents/app/main.py.backup
```

**Step 2: Update line 266**

Replace:
```python
task_metadata = eval(task_metadata_str.decode())
```

With:
```python
import json
task_metadata = json.loads(task_metadata_str.decode())
```

**Step 3: Also update line 206 - use json.dumps() instead of str()**

Replace:
```python
redis_client.setex(
    f"task:{task_id}:metadata",
    settings.task_result_expires,
    str(task_metadata)  # WRONG - converts to string representation
)
```

With:
```python
import json
redis_client.setex(
    f"task:{task_id}:metadata",
    settings.task_result_expires,
    json.dumps(task_metadata)  # Proper JSON serialization
)
```

**Step 4: Test**
```bash
cd open-security-agents
python -m pytest tests/ -v
```

**Step 5: Verify fix**
- Ensure no eval() calls remain in the codebase
- Verify Redis data is JSON-serialized correctly

---

### [ ] 2. Remove Committed Credentials from Git

**File**: `open-security-identity/.env`

**Step 1: Check if .env is in gitignore**
```bash
grep "^\.env$" .gitignore  # Should exist at repo root
grep "^\.env" open-security-identity/.gitignore  # Check if it exists locally
```

**Step 2: Add to open-security-identity/.gitignore if not present**
```bash
echo ".env" >> open-security-identity/.gitignore
echo ".env.*" >> open-security-identity/.gitignore
echo "!.env.example" >> open-security-identity/.gitignore
```

**Step 3: Remove .env from git history (REQUIRES FORCE PUSH)**
```bash
# WARNING: This rewrites history - only do if not shared!
git filter-branch --tree-filter 'rm -f open-security-identity/.env' HEAD

# Or use BFG for faster operation:
# bfg --delete-files open-security-identity/.env
```

**Step 4: Verify removal**
```bash
git log --all --name-status | grep "\.env"  # Should show deletions only
```

**Step 5: Force push (if applicable)**
```bash
git push origin --force-with-lease main
```

**Step 6: Create new .env from example**
```bash
cp open-security-identity/.env.example open-security-identity/.env
# Edit with actual secrets from secure vault
```

**Step 7: IMPORTANT - Rotate all credentials**
- Change database password
- Generate new JWT secret
- Regenerate Stripe keys if they were real
- Create new API keys

---

### [ ] 3. Add Authentication to Critical Endpoints

**File 1**: `open-security-agents/app/main.py`

**Step 1: Add import**
```python
from fastapi import Depends
from app.auth import get_current_user  # Adjust import path as needed
```

**Step 2: Update endpoint (line 180)**

Replace:
```python
@app.post("/v1/analyze", response_model=AnalysisTaskStatus, status_code=status.HTTP_202_ACCEPTED)
async def analyze_ioc(request: AnalysisTaskRequest):
```

With:
```python
@app.post("/v1/analyze", response_model=AnalysisTaskStatus, status_code=status.HTTP_202_ACCEPTED)
async def analyze_ioc(
    request: AnalysisTaskRequest,
    current_user: User = Depends(get_current_user)
):
```

**File 2**: `open-security-responder/app/main.py`

**Step 1: Add import**
```python
from fastapi import Depends
from app.auth import get_current_user
```

**Step 2: Update endpoint (line 133)**

Replace:
```python
@app.post("/v1/playbooks/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    request: PlaybookExecutionRequest = PlaybookExecutionRequest()
):
```

With:
```python
@app.post("/v1/playbooks/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    request: PlaybookExecutionRequest = PlaybookExecutionRequest(),
    current_user: User = Depends(get_current_user)
):
```

**Step 3: Test authentication**
```bash
# Should return 401 Unauthorized without token
curl -X POST http://localhost:8001/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "ip", "value": "1.2.3.4"}}'

# Should succeed with valid token
curl -X POST http://localhost:8001/v1/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "ip", "value": "1.2.3.4"}}'
```

---

### [ ] 4. Check & Rotate API Key (If Exposed)

**Action**: Check if `wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90` is a real production key

```bash
# Search for usage of this key
grep -r "wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90" /Users/fab/GitHub/wildbox/

# If found in actual usage:
# 1. Immediately rotate the key in your system
# 2. Check access logs for unauthorized usage
# 3. Generate new API key
# 4. Update all services using this key
```

---

## HIGH PRIORITY FIXES (Within 1 Week)

### [ ] 5. Fix CORS Configuration (Wildcard Origins)

**Files to update:**
- `open-security-agents/app/main.py` (line 91)
- `open-security-responder/app/main.py` (line 79)
- `open-security-data/app/config.py` (line 64)

**Step 1**: Update `open-security-agents/app/main.py`

Replace:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # DANGEROUS
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

With:
```python
import os

cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,  # Use environment variable
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
```

**Step 2**: Set environment variables

```bash
# In your .env or deployment configuration
CORS_ORIGINS=https://dashboard.yourdomain.com,https://app.yourdomain.com
```

**Step 3**: Repeat for other services

Apply same changes to:
- `open-security-responder/app/main.py`
- `open-security-data/app/main.py`

**Step 4**: Test CORS**
```bash
curl -X OPTIONS http://localhost:8001/ \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -v
```

---

### [ ] 6. Remove Default Secrets from docker-compose.yml

**File**: `docker-compose.yml`

**Step 1: Update lines 28-36**

Replace all lines like:
```yaml
- DATABASE_URL=${DATABASE_URL:-postgresql+asyncpg://postgres:postgres@postgres:5432/identity}
```

With:
```yaml
- DATABASE_URL=${DATABASE_URL}  # Will fail if not set - intentional!
```

**Step 2: Update line 58 - Remove exposed API key**

Replace:
```yaml
- API_KEY=${API_KEY:-wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90}
```

With:
```yaml
- API_KEY=${API_KEY}  # Require explicit environment variable
```

**Step 3: Remove all Stripe fallbacks**

Replace:
```yaml
- STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY:-sk_test_set_your_stripe_key}
- STRIPE_WEBHOOK_SECRET=${STRIPE_WEBHOOK_SECRET:-whsec_set_your_webhook_secret}
```

With:
```yaml
- STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}
- STRIPE_WEBHOOK_SECRET=${STRIPE_WEBHOOK_SECRET}
```

**Step 4: Create .env.production with actual values**

```bash
cat > .env.production << 'ENV'
# Generate secure values
DATABASE_URL=postgresql+asyncpg://secure_user:$(openssl rand -base64 32)@postgres:5432/identity
JWT_SECRET_KEY=$(openssl rand -base64 32)
API_KEY=$(openssl rand -hex 32)
STRIPE_SECRET_KEY=sk_live_XXXXX  # Your actual key
STRIPE_WEBHOOK_SECRET=whsec_XXXXX
ENV
```

**Step 5: Update docker-compose to use external .env**
```bash
docker-compose --env-file .env.production up
```

---

### [ ] 7. Remove Plaintext Password Logging

**File 1**: `open-security-identity/demo.py` (line 22)

Replace:
```python
print(f"Password: {password}")
```

With:
```python
logger.debug(f"Demo user created: {email}")  # Never log password
```

**File 2**: `open-security-identity/auth.py` (line 291)

Replace:
```python
except Exception as e:
    print(f"Authentication error: {str(e)}")
    return {"is_authenticated": False}
```

With:
```python
except Exception as e:
    logger.error("Authentication error occurred", exc_info=False)
    return {"is_authenticated": False}
```

**Step 3: Audit all logs for sensitive data**

```bash
grep -r "print(" open-security-* | grep -i "password\|token\|secret\|key"
grep -r "logger.*password\|logger.*secret\|logger.*token" open-security-*
```

---

### [ ] 8. Add Rate Limiting

**File 1**: `open-security-agents/app/main.py`

**Step 1: Install slowapi**
```bash
pip install slowapi
```

**Step 2: Add imports**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
```

**Step 3: Create limiter**
```python
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

def _rate_limit_exceeded_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded"}
    )
```

**Step 4: Add rate limiting decorators**
```python
@app.post("/v1/analyze", ...)
@limiter.limit("10/minute")  # 10 requests per minute per IP
async def analyze_ioc(request: Request, ...):
    ...
```

**Step 5: Repeat for responder service**

---

### [ ] 9. Add Security Headers Middleware

**Create new file**: `open-security-identity/app/security_middleware.py`

```python
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response
```

**Add to main app**:
```python
from app.security_middleware import SecurityHeadersMiddleware

app.add_middleware(SecurityHeadersMiddleware)
```

**Verify headers**:
```bash
curl -I http://localhost:8001/health | grep -E "X-|Strict-Transport|Content-Security"
```

---

## MEDIUM PRIORITY FIXES (Within 2 Weeks)

### [ ] 10. Fix SQL Injection in osquery

**File**: `open-security-sensor/sensor/collectors/osquery_manager.py` (line 411)

Replace:
```python
for table in tables:
    test_query = f"SELECT COUNT(*) FROM {table} LIMIT 1;"
    result = subprocess.run(['osqueryi', '--json', test_query], ...)
```

With:
```python
# Use osquery's schema validation instead
# Option 1: Use osqueryi's introspection
result = subprocess.run(
    ['osqueryi', '--json', '--query', '.schema'],
    capture_output=True, text=True
)
available_tables = json.loads(result.stdout)
valid_tables = [t for t in tables if t in available_tables]

# Option 2: Whitelist known safe tables
SAFE_TABLES = ['processes', 'files', 'users', 'groups']
valid_tables = [t for t in tables if t in SAFE_TABLES]
```

---

### [ ] 11. Remove Weak Hash Algorithm Support

**File**: `open-security-tools/app/tools/hash_generator/main.py`

Replace:
```python
ALGORITHMS = {
    'md5': hashlib.md5,      # BROKEN
    'sha1': hashlib.sha1,    # DEPRECATED
    'sha256': hashlib.sha256,
    ...
}

DEPRECATED = ['md5', 'sha1']
```

With:
```python
ALGORITHMS = {
    'sha256': hashlib.sha256,   # RECOMMENDED
    'sha512': hashlib.sha512,   # RECOMMENDED
    'blake2b': hashlib.blake2b, # MODERN
    'blake2s': hashlib.blake2s, # MODERN
}

# Legacy support only if absolutely necessary
LEGACY_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
}

def get_hash_function(algorithm: str):
    if algorithm in ALGORITHMS:
        return ALGORITHMS[algorithm]
    elif algorithm in LEGACY_ALGORITHMS:
        logger.warning(f"Using deprecated algorithm: {algorithm}")
        return LEGACY_ALGORITHMS[algorithm]
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
```

---

### [ ] 12. Secure Django Secret Key

**File**: `open-security-guardian/guardian/settings.py` (line 23)

Replace:
```python
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here-change-in-production')
```

With:
```python
SECRET_KEY = os.getenv('SECRET_KEY')

if not SECRET_KEY:
    raise ImproperlyConfigured(
        "SECRET_KEY environment variable must be set for production"
    )

# Validate it's not a default/weak value
WEAK_SECRETS = [
    'your-secret-key-here-change-in-production',
    'change-me',
    'secret',
    'insecure',
]

if SECRET_KEY.lower() in WEAK_SECRETS or len(SECRET_KEY) < 32:
    raise ImproperlyConfigured(
        "SECRET_KEY must be changed from default and at least 32 characters"
    )
```

---

### [ ] 13. Add Input Validation to Agents Endpoint

**File**: `open-security-agents/app/schemas.py`

Add validators:
```python
from pydantic import validator, Field
import re

class IOC(BaseModel):
    type: str = Field(..., regex="^(ip|domain|hash|url)$")
    value: str = Field(..., min_length=1, max_length=2048)
    
    @validator('value')
    def validate_ioc_value(cls, v, values):
        ioc_type = values.get('type')
        
        if ioc_type == 'ip':
            # Validate IP format
            import ipaddress
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP address: {v}")
        
        elif ioc_type == 'domain':
            # Validate domain format
            domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
            if not re.match(domain_pattern, v, re.IGNORECASE):
                raise ValueError(f"Invalid domain: {v}")
        
        elif ioc_type == 'hash':
            # Validate hash format (md5, sha1, sha256, sha512)
            hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$'
            if not re.match(hash_pattern, v):
                raise ValueError(f"Invalid hash format: {v}")
        
        elif ioc_type == 'url':
            # Validate URL format
            from urllib.parse import urlparse
            try:
                result = urlparse(v)
                if not all([result.scheme, result.netloc]):
                    raise ValueError()
            except:
                raise ValueError(f"Invalid URL: {v}")
        
        return v

class AnalysisTaskRequest(BaseModel):
    ioc: IOC
    priority: str = Field(default="medium", regex="^(low|medium|high|critical)$")
```

---

## LOW PRIORITY FIXES (When Convenient)

### [ ] 14. Disable API Docs in Production

**File**: `open-security-agents/app/main.py`

Replace:
```python
app = FastAPI(
    title="Open Security Agents API",
    description="AI-powered threat intelligence enrichment service",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)
```

With:
```python
import os

docs_url = "/docs" if os.getenv("ENVIRONMENT") == "development" else None
redoc_url = "/redoc" if os.getenv("ENVIRONMENT") == "development" else None

app = FastAPI(
    title="Open Security Agents API",
    description="AI-powered threat intelligence enrichment service",
    version="1.0.0",
    docs_url=docs_url,
    redoc_url=redoc_url,
    lifespan=lifespan
)
```

Repeat for:
- `open-security-responder/app/main.py`
- `open-security-tools/app/main.py`

---

### [ ] 15. Improve Test Password Security

**File**: `verify_authentication_complete.py` (line 581)

Replace:
```python
password = "demopassword123"
```

With:
```python
# Use secure test password that meets complexity requirements
password = "TempDemo@2024!SecurePass123"
```

---

## CI/CD INTEGRATION (Ongoing)

### [ ] Install Security Scanning Tools

**Step 1: Install tools**
```bash
pip install bandit safety
npm install -g snyk
```

**Step 2: Create GitHub Actions workflow**

**File**: `.github/workflows/security-scan.yml`

```yaml
name: Security Scanning

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install bandit safety
      
      - name: Run Bandit
        run: bandit -r open-security-* -f json -o bandit-report.json
      
      - name: Run Safety Check
        run: safety check --json
      
      - name: Check for secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --debug
```

**Step 3: Enable branch protection**
- Require security checks to pass before merge
- Require code review for security findings

---

## VERIFICATION CHECKLIST

After completing fixes, verify:

- [ ] No eval() calls in codebase: `grep -r "eval(" open-security-*`
- [ ] No plaintext passwords in logs: `grep -r "password=" open-security-*`
- [ ] CORS configured explicitly: `grep -r "allow_origins" open-security-*`
- [ ] All auth dependencies added: `grep -r "@app\." open-security-agents`
- [ ] No .env files in git: `git log --all --name-status | grep "\.env"`
- [ ] Security headers present: `curl -I http://localhost:8001/ | grep "X-"`
- [ ] Rate limiting works: `ab -n 100 -c 10 http://localhost:8001/health`

---

## Sign-Off

- [ ] Security review completed
- [ ] All CRITICAL fixes applied
- [ ] All HIGH fixes applied
- [ ] Tests passing
- [ ] Code review completed
- [ ] Deployed to staging
- [ ] Security re-check completed
- [ ] Deployed to production

**Completed by**: ________________  
**Date**: ________________  
**Verified by**: ________________

