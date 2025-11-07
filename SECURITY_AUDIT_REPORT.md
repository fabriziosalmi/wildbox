# Comprehensive Security Audit Report - Wildbox Security Platform

## Executive Summary
This security audit identified **19 security issues** across the Wildbox Security Platform codebase, ranging from Critical to Low severity. The platform has implemented several good security practices (bcrypt password hashing, defusedxml for XXE protection, proper JWT implementation) but has notable vulnerabilities in authentication, CORS configuration, code injection risks, and hardcoded credentials in committed files.

---

## CRITICAL ISSUES

### 1. Code Injection via eval() - Python Deserialization
**File**: `/Users/fab/GitHub/wildbox/open-security-agents/app/main.py` (Line 266)
**Severity**: CRITICAL
**Risk**: Remote Code Execution (RCE)

```python
task_metadata = eval(task_metadata_str.decode())
```

**Issue**: Using `eval()` to deserialize untrusted data from Redis can allow arbitrary code execution if an attacker can control the Redis data.

**Fix**: 
- Replace with `json.loads()` for safe JSON deserialization
- Use `json.dumps()` when storing instead of `str(task_metadata)`

```python
task_metadata = json.loads(task_metadata_str.decode())
```

---

### 2. Hardcoded Credentials in Committed .env File
**File**: `/Users/fab/GitHub/wildbox/open-security-identity/.env`
**Severity**: CRITICAL
**Risk**: Credential Exposure, Unauthorized Access

**Issues Found**:
- Line 2: `DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/identity_db` (plaintext password)
- Line 5: `JWT_SECRET_KEY=INSECURE-DEFAULT-JWT-SECRET-CHANGE-THIS` (default/insecure key)
- Line 10-12: Stripe test keys (even test keys should not be in repo)

**Fix**:
- Remove all .env files from git history: `git filter-branch --tree-filter 'rm -f open-security-identity/.env' HEAD`
- Ensure .env is in .gitignore (already done for root)
- Add to open-security-identity/.gitignore: `.env` and `.env.*` except `.env.example`
- Use environment variable injection in deployment

---

### 3. Missing Authentication on Critical API Endpoints
**Files**: 
- `/Users/fab/GitHub/wildbox/open-security-agents/app/main.py` (Line 180)
- `/Users/fab/GitHub/wildbox/open-security-responder/app/main.py` (Line 133)

**Severity**: CRITICAL
**Risk**: Unauthorized Access to Core Functionality

**Issue**: Public endpoints that execute critical operations without authentication:

```python
@app.post("/v1/analyze", ...)
async def analyze_ioc(request: AnalysisTaskRequest):  # NO AUTH CHECK
    """Submit IOC for analysis"""

@app.post("/v1/playbooks/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, ...):  # NO AUTH CHECK
    """Execute a playbook"""
```

**Fix**: Add authentication dependencies:

```python
from fastapi import Depends
from app.auth import get_current_user

@app.post("/v1/analyze", ...)
async def analyze_ioc(
    request: AnalysisTaskRequest,
    current_user: User = Depends(get_current_user)
):
```

---

## HIGH SEVERITY ISSUES

### 4. Overly Permissive CORS Configuration (Wildcard Origins)
**Files**:
- `/Users/fab/GitHub/wildbox/open-security-agents/app/main.py` (Line 91)
- `/Users/fab/GitHub/wildbox/open-security-responder/app/main.py` (Line 79)
- `/Users/fab/GitHub/wildbox/open-security-data/app/config.py` (Line 64)

**Severity**: HIGH
**Risk**: Cross-Site Request Forgery (CSRF), Data Exfiltration

**Issue**:
```python
CORSMiddleware,
allow_origins=["*"],  # Dangerous!
allow_credentials=True,  # Even more dangerous with wildcard
```

**Fix**: Restrict to specific domains:

```python
allow_origins=[
    os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
],
allow_credentials=True,
```

For data service - explicitly enumerate:
```python
cors_origins: List[str] = field(default_factory=lambda: [
    "https://dashboard.wildbox.com",
    "https://app.wildbox.com"
])
```

---

### 5. SQL Injection Risk in osquery Table Validation
**File**: `/Users/fab/GitHub/wildbox/open-security-sensor/sensor/collectors/osquery_manager.py` (Line 411)
**Severity**: HIGH
**Risk**: SQL Injection via Dynamic Table Names

```python
table_pattern = r'(?:FROM|JOIN)\s+(\w+)'
tables = re.findall(table_pattern, query, re.IGNORECASE)

for table in tables:
    test_query = f"SELECT COUNT(*) FROM {table} LIMIT 1;"  # VULNERABLE
    result = subprocess.run(['osqueryi', '--json', test_query], ...)
```

**Issue**: While regex restricts to `\w+`, it's still unsafe. Even though subprocess is not using shell=True, this is fragile.

**Fix**: Use osquery's native validation APIs instead:
```python
# Use osquery's schema API instead of dynamic query construction
# Or use parameterized queries if available
```

---

### 6. Missing Rate Limiting on Public Endpoints
**Files**:
- `/Users/fab/GitHub/wildbox/open-security-agents/app/main.py`
- `/Users/fab/GitHub/wildbox/open-security-responder/app/main.py`

**Severity**: HIGH
**Risk**: Denial of Service (DoS), Resource Exhaustion

**Issue**: Public endpoints like `/v1/analyze` and `/v1/playbooks/{id}/execute` can be called unlimited times, consuming resources.

**Fix**: Implement rate limiting:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/v1/analyze")
@limiter.limit("10/minute")  # 10 requests per minute per IP
async def analyze_ioc(request: Request, ...):
```

---

### 7. Plaintext Logging of Sensitive Data
**Files**:
- `/Users/fab/GitHub/wildbox/open-security-identity/demo.py` (Line 22)
- `/Users/fab/GitHub/wildbox/open-security-identity/auth.py` (Line 291)

**Severity**: HIGH
**Risk**: Information Disclosure, Credentials in Logs

```python
# demo.py line 22
print(f"Password: {password}")  # Logs plaintext password

# auth.py line 291
print(f"Authentication error: {str(e)}")  # May include sensitive info
```

**Fix**: Remove password logging and mask sensitive data:

```python
# DON'T log passwords ever
logger.debug("Authentication attempt")  # OK

# Mask errors
except Exception as e:
    logger.error("Authentication error occurred", exc_info=False)
```

---

### 8. Insecure Default Secrets in docker-compose.yml
**File**: `/Users/fab/GitHub/wildbox/docker-compose.yml` (Lines 28-36)
**Severity**: HIGH
**Risk**: Data Compromise, Unauthorized Access

```yaml
- DATABASE_URL=${DATABASE_URL:-postgresql+asyncpg://postgres:postgres@postgres:5432/identity}
- JWT_SECRET_KEY=${JWT_SECRET_KEY:-please-set-jwt-secret-in-env-file}
- STRIPE_WEBHOOK_SECRET=${STRIPE_WEBHOOK_SECRET:-whsec_set_your_webhook_secret}
- INITIAL_ADMIN_PASSWORD=${INITIAL_ADMIN_PASSWORD:-CHANGE-THIS-PASSWORD}
- API_KEY=${API_KEY:-wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90}
```

**Fix**: Remove all default values. Use only `${VAR_NAME}` which will fail if not set:

```yaml
- DATABASE_URL=${DATABASE_URL}  # Will fail if not set - this is good!
- JWT_SECRET_KEY=${JWT_SECRET_KEY}
- INITIAL_ADMIN_PASSWORD=${INITIAL_ADMIN_PASSWORD}
```

Also, change line 58 API_KEY - this looks like a real key was exposed:
```yaml
- API_KEY=${API_KEY:-wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90}  # EXPOSED KEY!
```

**Immediate Action**: If `wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90` is a real key, rotate it immediately.

---

## MEDIUM SEVERITY ISSUES

### 9. Missing Input Validation on Unprotected Endpoints
**File**: `/Users/fab/GitHub/wildbox/open-security-agents/app/main.py` (Line 181)
**Severity**: MEDIUM
**Risk**: Injection Attacks, Unexpected Behavior

```python
async def analyze_ioc(request: AnalysisTaskRequest):
    # No validation of IOC type/value for malicious patterns
    task_metadata = {
        "ioc": request.ioc.dict(),  # May contain malicious data
    }
```

**Fix**: Add robust input validation:

```python
from pydantic import validator, Field

class AnalysisTaskRequest(BaseModel):
    ioc: IOC
    priority: str = Field(..., regex="^(low|medium|high|critical)$")
    
class IOC(BaseModel):
    type: str = Field(..., regex="^(ip|domain|hash|url)$")
    value: str = Field(..., min_length=1, max_length=2048)
    
    @validator('value')
    def validate_ioc_value(cls, v, values):
        ioc_type = values.get('type')
        # Validate based on type
        ...
```

---

### 10. Weak Hashing Algorithms Supported (md5, sha1)
**File**: `/Users/fab/GitHub/wildbox/open-security-tools/app/tools/hash_generator/main.py` (Lines 28-65)
**Severity**: MEDIUM
**Risk**: Weak Cryptography, Compliance Issues

```python
ALGORITHMS = {
    'md5': hashlib.md5,      # BROKEN
    'sha1': hashlib.sha1,    # DEPRECATED
    ...
}

DEPRECATED = ['md5', 'sha1']
```

**Issue**: While these are marked as deprecated, they're still available. MD5 and SHA1 have known collision attacks.

**Fix**: Remove or move to a "legacy only" mode:

```python
ALGORITHMS = {
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
    'blake2b': hashlib.blake2b,
}

LEGACY_ALGORITHMS = {  # Only for compatibility
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
}
```

---

### 11. Missing CSRF Protection Validation
**File**: `/Users/fab/GitHub/wildbox/open-security-identity/app/config.py` (Line 40)
**Severity**: MEDIUM
**Risk**: Cross-Site Request Forgery

**Issue**: 
```python
cors_allow_headers: list[str] = ["*"]  # Allows any headers - CSRF not checked
```

**Fix**: Be explicit about allowed headers:

```python
cors_allow_headers: list[str] = [
    "Content-Type",
    "Authorization",
    "X-CSRF-Token",
]
cors_expose_headers: list[str] = [
    "X-CSRF-Token",
]
```

Also add CSRF middleware for state-changing operations.

---

### 12. Missing Security Headers
**Severity**: MEDIUM
**Risk**: Clickjacking, XSS, MIME Type Sniffing

**Issue**: No explicit security headers configured in FastAPI applications.

**Fix**: Add middleware for security headers:

```python
from fastapi.middleware import Middleware
from fastapi import FastAPI

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    return response
```

---

### 13. Subprocess Usage Without Input Validation
**File**: `/Users/fab/GitHub/wildbox/open-security-sensor/sensor/collectors/log_forwarder.py` (Line 281)
**Severity**: MEDIUM
**Risk**: Command Injection

```python
result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
```

**Issue**: While subprocess.run without shell=True is safer, the `cmd` source should be validated.

**Fix**: Use list form with explicit parameters:

```python
result = subprocess.run(
    ['/usr/bin/journalctl', '-n', '100', '--output', 'json'],  # Explicit args
    capture_output=True,
    text=True,
    timeout=30,
    cwd=None,  # Explicitly set
)
```

---

### 14. Insecure Deserialization - json.loads() without validation
**File**: `/Users/fab/GitHub/wildbox/open-security-cspm/app/main.py` (Multiple lines)
**Severity**: MEDIUM
**Risk**: Injection Attacks, Unexpected Type Confusion

```python
metadata = json.loads(metadata_json)  # Assumes valid JSON from Redis
```

**Issue**: No validation of JSON schema before processing.

**Fix**: Use Pydantic models for validation:

```python
from pydantic import BaseModel, ValidationError

class TaskMetadata(BaseModel):
    task_id: str
    status: str
    ...

try:
    metadata = TaskMetadata(**json.loads(metadata_json))
except ValidationError as e:
    logger.error(f"Invalid metadata: {e}")
    raise HTTPException(400, "Invalid metadata format")
```

---

### 15. Default Django Secret Key (Guardian)
**File**: `/Users/fab/GitHub/wildbox/open-security-guardian/guardian/settings.py` (Line 23)
**Severity**: MEDIUM
**Risk**: Session Hijacking, CSRF Token Forgery

```python
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here-change-in-production')
```

**Fix**: Require environment variable:

```python
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable must be set")

# Validate it's not a default value
if SECRET_KEY in ['your-secret-key-here-change-in-production', 'change-me']:
    raise ValueError("SECRET_KEY must be changed from default")
```

---

## LOW SEVERITY ISSUES

### 16. Missing API Key Validation on Tools Endpoint
**File**: `/Users/fab/GitHub/wildbox/open-security-tools/app/api/router.py` (Line 22)
**Severity**: LOW
**Risk**: Information Disclosure

**Issue**: API key required but endpoints don't return 401 uniformly:

```python
async def list_tools(request: Request, api_key: str = Depends(verify_api_key)):
    # verify_api_key might raise HTTPException
```

**Fix**: Ensure consistent error responses and validate thoroughly.

---

### 17. Debug Flag in Production
**File**: `/Users/fab/GitHub/wildbox/docker-compose.yml` (Line 59)
**Severity**: LOW (if DEBUG is false in production)
**Risk**: Information Disclosure

```yaml
- DEBUG=${DEBUG:-false}
```

**Fix**: Add validation to ensure DEBUG is false:

```python
if os.getenv('ENVIRONMENT') == 'production' and os.getenv('DEBUG') == 'true':
    raise ValueError("DEBUG cannot be true in production")
```

---

### 18. Weak Password Requirements in Demo
**File**: `/Users/fab/GitHub/wildbox/verify_authentication_complete.py` (Line 581)
**Severity**: LOW
**Risk**: Weak Authentication

```python
password = "demopassword123"  # Simple password
```

**Fix**: Use stronger test passwords:

```python
password = "TempDemo@2024!SecurePass"  # Meets complexity requirements
```

---

### 19. Missing API Documentation Security
**Severity**: LOW
**Risk**: Information Disclosure

**Issue**: Swagger/OpenAPI docs exposed at `/docs` without authentication.

**Fix**: Disable in production or protect:

```python
# Only enable in development
if not settings.debug:
    docs_url = None
    redoc_url = None

app = FastAPI(
    title="...",
    docs_url=docs_url,
    redoc_url=redoc_url,
)
```

---

## SUMMARY TABLE

| Severity | Count | Issues |
|----------|-------|--------|
| CRITICAL | 3 | Code injection (eval), Hardcoded credentials, Missing authentication |
| HIGH | 6 | Permissive CORS, SQL injection risk, No rate limiting, Plaintext logging, Default secrets, Guardian defaults |
| MEDIUM | 8 | Input validation, Weak hashes, No CSRF protection, Missing headers, Subprocess risks, Insecure deserialization, Django secret, API validation |
| LOW | 2 | Debug flag, Weak test passwords, API doc security |

**Total Issues: 19**

---

## REMEDIATION PRIORITY

1. **Immediate (Within 24 hours)**:
   - Fix code injection (eval) vulnerability - CRITICAL RCE risk
   - Remove hardcoded credentials from .env file in git
   - Add authentication to critical endpoints
   - Validate API key `wbx-FtWXeuB_1VZut2DjxpT2TCjtVzeNjem8W0V3OA38M90` hasn't been exposed

2. **Short-term (Within 1 week)**:
   - Fix CORS configuration
   - Implement rate limiting
   - Add security headers middleware
   - Fix logging of sensitive data
   - Remove default secrets from docker-compose

3. **Medium-term (Within 2 weeks)**:
   - Input validation enhancements
   - Remove weak hash algorithms
   - Add CSRF protection
   - Secure Guardian SECRET_KEY requirement
   - Subprocess input validation

4. **Ongoing**:
   - Security headers validation
   - API documentation security
   - Dependency vulnerability scanning
   - Regular security audits

---

## RECOMMENDATIONS

1. **Implement Security Testing in CI/CD**:
   - Add `bandit` for Python security checks
   - Add `safety` for dependency vulnerability scanning
   - Add `trivy` or `snyk` for container scanning

2. **Enable Secret Scanning**:
   - Use `git-secrets` or `detect-secrets` pre-commit hooks
   - Enable GitHub secret scanning

3. **Add Security Middleware Stack**:
   - Request/Response validation
   - Rate limiting
   - Security headers
   - CORS validation

4. **Authentication/Authorization**:
   - Implement authz on all sensitive endpoints
   - Use role-based access control (RBAC)
   - Implement API key rotation policies

5. **Logging & Monitoring**:
   - Implement structured logging
   - Never log passwords, tokens, or credentials
   - Monitor for suspicious activity
   - Set up security event alerts

---

## COMPLIANCE NOTES

Current implementation is partially aligned with:
- OWASP Top 10 (some issues present)
- CWE/SANS Top 25 (several CWEs identified)
- Missing: GDPR data protection logging, PII handling

---

**Audit Date**: November 7, 2024
**Audit Scope**: Python FastAPI/Django services, Docker configuration, dependency files
**Tools Used**: Manual code review, grep/pattern matching, dependency analysis
