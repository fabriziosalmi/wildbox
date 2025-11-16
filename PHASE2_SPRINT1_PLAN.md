# Fase 2 - Sprint 1: Hardening dell'Accesso API

**Sprint Goal**: Implementare gestione API key e rate limiting per proteggere la piattaforma
**Duration**: 1 settimana (5 giorni lavorativi)
**Expected Test Improvement**: 50.8% → 55-57%
**Expected Feature Value**: 2 critical security features

---

## Sprint Backlog

### 🔑 User Story 1: API Key Management

**Come** utente autenticato
**Voglio** poter creare, gestire e revocare API key
**Per** autenticare le mie applicazioni e servizi senza esporre le mie credenziali

**Acceptance Criteria**:
- [ ] Posso creare una nuova API key con nome e descrizione
- [ ] Posso vedere una lista delle mie API key attive
- [ ] Posso revocare un'API key esistente
- [ ] Le API key scadono dopo 90 giorni (configurabile)
- [ ] Posso usare un'API key per autenticare richieste API
- [ ] Il test `test_api_key_management` passa

**Priority**: P0 (Critical)
**Effort**: 8 story points (1-2 giorni)
**Service**: open-security-identity

#### Technical Tasks

**Task 1.1: Database Schema**
```sql
-- Table: api_keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    key_prefix VARCHAR(16) NOT NULL,  -- Per identificare la key nei log
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    scopes JSONB DEFAULT '[]'::jsonb,  -- Per future permission granulari
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = true;
```

**Task 1.2: API Key Model** (`open-security-identity/app/models/api_key.py`)
```python
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from datetime import datetime, timedelta
import secrets
import hashlib

class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    key_hash = Column(String(255), nullable=False, unique=True)
    key_prefix = Column(String(16), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    last_used_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    scopes = Column(JSONB, default=list)
    metadata = Column(JSONB, default=dict)

    @staticmethod
    def generate_key() -> tuple[str, str, str]:
        """Generate a new API key.

        Returns:
            tuple: (full_key, key_hash, key_prefix)
        """
        # Format: wb_live_randomstring (wildbox_environment_secret)
        prefix = "wb_live_"
        secret = secrets.token_urlsafe(32)  # 43 chars
        full_key = f"{prefix}{secret}"

        # Hash for storage
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()

        # Prefix for identification in logs
        key_prefix = full_key[:16]

        return full_key, key_hash, key_prefix

    @classmethod
    def hash_key(cls, key: str) -> str:
        """Hash an API key for comparison."""
        return hashlib.sha256(key.encode()).hexdigest()
```

**Task 1.3: API Endpoints** (`open-security-identity/app/api/v1/api_keys.py`)
```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timedelta

from app.models.api_key import APIKey
from app.schemas.api_key import APIKeyCreate, APIKeyResponse, APIKeyListResponse
from app.api.deps import get_current_user, get_db
from app.models.user import User

router = APIRouter()

@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    api_key_data: APIKeyCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new API key for the authenticated user."""

    # Generate key
    full_key, key_hash, key_prefix = APIKey.generate_key()

    # Set expiration (default 90 days)
    expires_at = datetime.utcnow() + timedelta(days=90)

    # Create database record
    db_api_key = APIKey(
        user_id=current_user.id,
        name=api_key_data.name,
        description=api_key_data.description,
        key_hash=key_hash,
        key_prefix=key_prefix,
        expires_at=expires_at
    )

    db.add(db_api_key)
    db.commit()
    db.refresh(db_api_key)

    # Return response with full key (only time it's shown!)
    return {
        "id": db_api_key.id,
        "name": db_api_key.name,
        "description": db_api_key.description,
        "key": full_key,  # ⚠️ Only returned on creation!
        "key_prefix": key_prefix,
        "created_at": db_api_key.created_at,
        "expires_at": db_api_key.expires_at
    }

@router.get("/api-keys", response_model=List[APIKeyListResponse])
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all active API keys for the authenticated user."""

    api_keys = db.query(APIKey).filter(
        APIKey.user_id == current_user.id,
        APIKey.is_active == True
    ).all()

    return [
        {
            "id": key.id,
            "name": key.name,
            "description": key.description,
            "key_prefix": key.key_prefix,
            "created_at": key.created_at,
            "expires_at": key.expires_at,
            "last_used_at": key.last_used_at
        }
        for key in api_keys
    ]

@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke an API key."""

    api_key = db.query(APIKey).filter(
        APIKey.id == key_id,
        APIKey.user_id == current_user.id
    ).first()

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_active = False
    db.commit()

    return {"message": "API key revoked successfully"}
```

**Task 1.4: Authentication Dependency**
```python
# Add to app/api/deps.py

async def get_current_user_from_api_key(
    api_key: str = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
) -> User:
    """Authenticate user via API key."""

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required"
        )

    # Hash the provided key
    key_hash = APIKey.hash_key(api_key)

    # Find the API key
    db_api_key = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True
    ).first()

    if not db_api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )

    # Check expiration
    if db_api_key.expires_at and db_api_key.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=401,
            detail="API key expired"
        )

    # Update last used
    db_api_key.last_used_at = datetime.utcnow()
    db.commit()

    # Return the user
    user = db.query(User).filter(User.id == db_api_key.user_id).first()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user
```

**Task 1.5: Pydantic Schemas**
```python
# app/schemas/api_key.py

from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import uuid

class APIKeyCreate(BaseModel):
    name: str
    description: Optional[str] = None

class APIKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    key: str  # Full key - only on creation!
    key_prefix: str
    created_at: datetime
    expires_at: Optional[datetime]

class APIKeyListResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    key_prefix: str  # Never show full key in lists!
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
```

**Task 1.6: Database Migration**
```bash
# In open-security-identity directory
alembic revision -m "add_api_keys_table"
# Edit the generated migration file with the SQL above
alembic upgrade head
```

**Task 1.7: Integration Tests Update**
- The existing test in `test_identity_comprehensive.py` should now pass!
- No test changes needed if endpoints match test expectations

**Definition of Done**:
- [ ] Database migration created and applied
- [ ] Models, schemas, and endpoints implemented
- [ ] API key authentication works with X-API-Key header
- [ ] Unit tests written for key generation and hashing
- [ ] Integration test `test_api_key_management` passes
- [ ] Code reviewed
- [ ] Documentation updated

---

### 🛡️ User Story 2: API Rate Limiting

**Come** amministratore di sistema
**Voglio** proteggere la piattaforma da abusi con rate limiting
**Per** prevenire attacchi DDoS e garantire disponibilità del servizio

**Acceptance Criteria**:
- [ ] Il gateway limita le richieste a 100 req/min per IP
- [ ] Burst di max 20 richieste immediate consentito
- [ ] Risponde con HTTP 429 quando il limite è superato
- [ ] Header `X-RateLimit-*` forniscono informazioni sul limite
- [ ] Il test `test_rate_limiting` passa

**Priority**: P0 (Critical)
**Effort**: 5 story points (1 giorno)
**Service**: open-security-gateway

#### Technical Tasks

**Task 2.1: Nginx Rate Limiting Configuration**
```nginx
# File: open-security-gateway/nginx.conf

# Define rate limit zones (in http block)
http {
    # Rate limit: 100 requests per minute per IP
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;

    # Burst zone for temporary spikes
    limit_req_zone $binary_remote_addr zone=api_burst:10m rate=20r/s;

    # Connection limit: max 10 concurrent connections per IP
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

    # Custom log format for rate limiting
    log_format rate_limited '$remote_addr - $remote_user [$time_local] '
                           '"$request" $status $body_bytes_sent '
                           '"$http_referer" "$http_user_agent" '
                           'rate_limited';

    server {
        listen 80;
        listen 443 ssl;

        # Apply rate limits to API endpoints
        location /api/ {
            # Main rate limit with burst allowance
            limit_req zone=api_limit burst=20 nodelay;

            # Connection limit
            limit_conn conn_limit 10;

            # Set rate limit headers
            add_header X-RateLimit-Limit "100" always;
            add_header X-RateLimit-Remaining $limit_req_status always;

            # Log rate limited requests
            access_log /var/log/nginx/rate_limited.log rate_limited if=$limit_req_status;

            # Proxy to backend
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Health checks exempt from rate limiting
        location /health {
            limit_req off;
            proxy_pass http://backend;
        }
    }
}
```

**Task 2.2: Rate Limit Error Response**
```nginx
# Custom error page for 429 responses
location @rate_limit_error {
    internal;
    default_type application/json;
    return 429 '{
        "error": {
            "code": 429,
            "message": "Too Many Requests",
            "type": "RateLimitExceeded",
            "retry_after": 60
        }
    }';
    add_header Content-Type application/json always;
    add_header Retry-After 60 always;
}

# Intercept rate limit errors
error_page 429 = @rate_limit_error;
```

**Task 2.3: Docker Configuration Update**
```yaml
# docker-compose.yml - Gateway service
gateway:
  image: nginx:alpine
  container_name: open-security-gateway
  volumes:
    - ./open-security-gateway/nginx.conf:/etc/nginx/nginx.conf:ro
    - nginx_cache:/var/cache/nginx
    - nginx_logs:/var/log/nginx
  ports:
    - "80:80"
    - "443:443"
  environment:
    - NGINX_WORKER_PROCESSES=auto
    - NGINX_WORKER_CONNECTIONS=1024
  restart: unless-stopped
```

**Task 2.4: Monitoring & Metrics**
```bash
# Script to monitor rate limiting
# File: scripts/monitor_rate_limits.sh

#!/bin/bash
echo "Rate Limiting Statistics (last hour):"
echo "======================================"

# Count 429 responses
echo -n "Total rate limited requests: "
docker-compose logs gateway --since 1h | grep -c "rate_limited"

# Top IPs being rate limited
echo -e "\nTop 10 rate limited IPs:"
docker-compose logs gateway --since 1h | \
  grep "rate_limited" | \
  awk '{print $1}' | \
  sort | uniq -c | sort -rn | head -10

# Rate limit by endpoint
echo -e "\nRate limited by endpoint:"
docker-compose logs gateway --since 1h | \
  grep "rate_limited" | \
  awk '{print $7}' | \
  sort | uniq -c | sort -rn
```

**Task 2.5: Integration Test Update**
```python
# Update test_gateway_security.py if needed
# The existing test should pass with:
# - 100 req/min = ~1.67 req/sec baseline
# - Burst of 20 immediate requests allowed
# - 21st request in rapid succession gets 429
```

**Definition of Done**:
- [ ] Nginx configuration with rate limiting implemented
- [ ] Rate limit headers included in responses
- [ ] Custom 429 error response with JSON format
- [ ] Health endpoints exempt from rate limiting
- [ ] Monitoring script created
- [ ] Integration test `test_rate_limiting` passes
- [ ] Documentation updated with rate limit policies

---

## Sprint Metrics

### Test Success Rate Target

| Metric | Current | After Sprint | Target |
|--------|---------|--------------|--------|
| Identity Tests | 5/8 (63%) | 6/8 (75%) | 75% |
| Gateway Tests | 4/7 (57%) | 5/7 (71%) | 71% |
| **Overall** | **33/65 (51%)** | **35/65 (54%)** | **55-57%** |

### Feature Value Metrics

| Feature | Security Impact | User Value | Business Value |
|---------|----------------|------------|----------------|
| API Keys | 🔴 Critical | High | High |
| Rate Limiting | 🔴 Critical | Medium | High |

---

## Risk Management

### Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Database schema conflicts | Low | Medium | Review existing migrations first |
| Rate limit too restrictive | Medium | High | Start conservative, monitor, adjust |
| API key backwards compatibility | Low | High | Existing JWT auth still works |
| Performance impact of rate limiting | Low | Medium | Use nginx (very efficient) |

---

## Daily Plan

### Day 1: Setup & Design
- Morning: Database schema design and migration
- Afternoon: API key model and core logic

### Day 2: API Implementation
- Morning: API endpoints implementation
- Afternoon: Authentication dependency and testing

### Day 3: Rate Limiting
- Morning: Nginx configuration
- Afternoon: Testing and monitoring setup

### Day 4: Integration & Testing
- Morning: Run full integration test suite
- Afternoon: Fix issues, documentation

### Day 5: Review & Deploy
- Morning: Code review, final adjustments
- Afternoon: Deploy to staging, validate

---

## Success Criteria

Sprint is successful if:
- ✅ Both user stories meet acceptance criteria
- ✅ Test success rate increases to 54-57%
- ✅ No regressions in existing tests
- ✅ Code coverage > 80% for new code
- ✅ Documentation updated
- ✅ Zero critical bugs

---

## Notes

### API Key Security Best Practices Implemented
1. ✅ Keys are hashed (SHA-256) in database
2. ✅ Full key only shown once (on creation)
3. ✅ Key prefix for safe logging/identification
4. ✅ Automatic expiration (90 days default)
5. ✅ Last used timestamp for monitoring
6. ✅ Revocation capability

### Rate Limiting Strategy
1. ✅ Burst allowance for legitimate usage spikes
2. ✅ Health checks exempt (monitoring shouldn't be rate limited)
3. ✅ Informative headers for clients
4. ✅ JSON error responses (API-friendly)
5. ✅ Monitoring and alerting built-in

---

**Sprint Start**: Ready when you are!
**Sprint Owner**: Development Team
**Last Updated**: 16 November 2025
