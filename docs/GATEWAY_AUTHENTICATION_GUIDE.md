# Gateway Authentication Pattern - Developer Guide

## Overview

All Wildbox backend services use a **trust-based authentication pattern** where the API Gateway validates user credentials (JWT or API keys) and injects trusted headers to backend services.

```
┌────────┐     ┌─────────┐     ┌──────────┐     ┌─────────┐
│ Client │────▶│ Gateway │────▶│ Identity │────▶│ Backend │
└────────┘     └─────────┘     └──────────┘     └─────────┘
   API Key         ↓                ↓                ↓
   or JWT      Validates        Returns          Trusts
               Auth            User Info        Headers
```

### Dual-Mode Authentication (Tools Service)

The Tools service supports **two authentication modes** for flexibility during development and testing:

**Production Mode (Recommended):**
- Requests go through API Gateway (`http://localhost/api/v1/tools/...`)
- Gateway validates credentials and injects `X-Wildbox-*` headers
- Backend trusts gateway headers

**Legacy/Development Mode:**
- Direct service access (`http://localhost:8000/api/tools/...`)
- Client provides `X-API-Key` header directly
- Service validates API key locally
- ⚠️ **Use only for development/testing** - not recommended for production

## Security Model

### Principles

1. **Gateway is the single entry point** - All external traffic MUST go through the gateway
2. **Identity service validates credentials** - JWT tokens and API keys are validated once
3. **Backend services trust gateway** - Headers injected by gateway are trusted implicitly
4. **Network isolation** - Backend services should only be accessible from gateway (Docker network)

### Injected Headers

The gateway injects these headers after successful authentication:

| Header | Type | Description | Example |
|--------|------|-------------|---------|
| `X-Wildbox-User-ID` | UUID | Authenticated user's unique ID | `da8adf0a-072a-4f53-8b29-043212761bbd` |
| `X-Wildbox-Team-ID` | UUID | User's team ID | `28169a02-5b81-4ec4-a668-a7a100f8d642` |
| `X-Wildbox-Plan` | String | Subscription plan (`free`, `pro`, `business`, `enterprise`) | `pro` |
| `X-Wildbox-Role` | String | User's role in team (`owner`, `admin`, `member`, `viewer`) | `admin` |

**🔒 Security Note**: These headers are NEVER accepted from external clients. The gateway clears any X-Wildbox-* headers from incoming requests before authentication.

## Implementation Guide

### Step 1: Add Shared Module to Service

All backend services should include the `open-security-shared` directory in their Python path:

```python
# In your service's auth.py or dependencies.py
import sys
import os

# Add shared modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'open-security-shared'))

from gateway_auth import get_user_from_gateway_headers, GatewayUser
```

### Step 2: Use Gateway Authentication Dependency

Replace existing authentication dependencies with the gateway auth:

```python
from fastapi import APIRouter, Depends
from gateway_auth import get_user_from_gateway_headers, GatewayUser

router = APIRouter()

@router.post("/api/tools/scan")
async def scan_target(
    target: str,
    user: GatewayUser = Depends(get_user_from_gateway_headers)
):
    """
    This endpoint is automatically authenticated.
    The 'user' parameter contains validated user information.
    """
    logger.info(f"Scan requested by user {user.user_id} in team {user.team_id}")
    
    # Access user properties
    print(f"User ID: {user.user_id}")      # UUID
    print(f"Team ID: {user.team_id}")      # UUID
    print(f"Plan: {user.plan}")            # "free", "pro", "business"
    print(f"Role: {user.role}")            # "owner", "admin", "member", "viewer"
    
    # Your business logic here
    return {"status": "scanning", "target": target}
```

### Step 3: Role-Based Access Control (Optional)

Use helper functions for role-based restrictions:

```python
from gateway_auth import get_user_from_gateway_headers, require_role, GatewayUser

@router.delete("/api/teams/{team_id}/members/{user_id}")
async def remove_member(
    team_id: str,
    user_id: str,
    user: GatewayUser = Depends(get_user_from_gateway_headers),
    _: None = Depends(require_role("owner", "admin"))  # Only owners and admins
):
    """Only team owners and admins can remove members."""
    # Remove member logic
    return {"message": "Member removed"}
```

### Step 4: Plan-Based Access Control (Optional)

Restrict features based on subscription plan:

```python
from gateway_auth import get_user_from_gateway_headers, require_plan, GatewayUser

@router.post("/api/tools/advanced-scan")
async def advanced_scan(
    target: str,
    user: GatewayUser = Depends(get_user_from_gateway_headers),
    _: None = Depends(require_plan("pro", "business", "enterprise"))
):
    """Advanced scan is only available for pro+ users."""
    # Advanced scan logic
    return {"status": "advanced_scanning", "target": target}
```

## Error Handling

The gateway authentication dependency raises standard FastAPI HTTPExceptions:

### 403 Forbidden - Request Bypassed Gateway

```json
{
  "error": "Gateway authentication required",
  "message": "This service must be accessed through the API gateway. Direct access is not permitted.",
  "code": "GATEWAY_AUTH_REQUIRED"
}
```

**Cause**: Headers `X-Wildbox-User-ID` or `X-Wildbox-Team-ID` are missing  
**Solution**: Ensure all requests go through the gateway (http://localhost/api/...)

### 400 Bad Request - Malformed Headers

```json
{
  "error": "Invalid authentication headers",
  "message": "Gateway provided malformed user/team identifiers",
  "code": "INVALID_GATEWAY_HEADERS"
}
```

**Cause**: UUIDs in headers are invalid  
**Solution**: Check gateway authentication logic

### 402 Payment Required - Plan Upgrade Needed

```json
{
  "error": "Plan upgrade required",
  "message": "This feature requires one of these plans: pro, business, enterprise",
  "code": "PLAN_UPGRADE_REQUIRED",
  "current_plan": "free"
}
```

**Cause**: User's plan doesn't have access to this feature  
**Solution**: User needs to upgrade subscription

### 403 Forbidden - Insufficient Role

```json
{
  "error": "Insufficient permissions",
  "message": "This action requires one of these roles: owner, admin",
  "code": "INSUFFICIENT_ROLE"
}
```

**Cause**: User's role doesn't have permission for this action  
**Solution**: User needs appropriate team role

## Testing

### E2E Test via Gateway

```bash
# Authenticate and get API key
curl -X POST 'http://localhost/api/v1/tools/whois_lookup' \
  -H 'X-API-Key: wsk_51c0.77d4c520955c5908e4a9d9202533aff0f3dbb10dfb7f12cb701009b3e1993fde' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'

# Expected: 200 OK with WHOIS results
```

### Direct Service Access (Should Fail)

```bash
# Try to access service directly
curl -X POST 'http://localhost:8000/api/tools/whois_lookup' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'

# Expected: 401 Unauthorized - "Authentication required"
```

### With Invalid API Key

```bash
# Use invalid API key
curl -X POST 'http://localhost/api/v1/tools/whois_lookup' \
  -H 'X-API-Key: invalid_key' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'

# Expected: 401 Unauthorized - "Invalid API key"
```

## Migration Guide

### Old Pattern (Direct Auth in Service)

```python
from fastapi.security import HTTPBearer
from app.auth import verify_jwt_token

security = HTTPBearer()

@router.get("/api/endpoint")
async def endpoint(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = verify_jwt_token(credentials.credentials)  # Validates token in service
    return {"user_id": user.id}
```

### New Pattern (Trust Gateway)

```python
from gateway_auth import get_user_from_gateway_headers, GatewayUser

@router.get("/api/endpoint")
async def endpoint(user: GatewayUser = Depends(get_user_from_gateway_headers)):
    return {"user_id": str(user.user_id)}  # Gateway already validated
```

### Benefits

✅ **Simpler code** - No JWT validation logic in each service  
✅ **Better performance** - Token validated once at gateway  
✅ **Centralized auth** - All auth logic in one place  
✅ **Easier to update** - Change auth method without touching services  
✅ **Better security** - Services never see raw credentials  

## Troubleshooting

### Headers Not Received by Backend

**Problem**: Service logs "Missing gateway authentication headers"

**Solutions**:
1. Check gateway Lua code is setting headers:
   ```lua
   ngx.req.set_header("X-Wildbox-User-ID", auth_data.user_id)
   ngx.req.set_header("X-Wildbox-Team-ID", auth_data.team_id)
   ```

2. Check proxy_params.conf forwards headers:
   ```nginx
   proxy_set_header X-Wildbox-User-ID $http_x_wildbox_user_id;
   proxy_set_header X-Wildbox-Team-ID $http_x_wildbox_team_id;
   ```

3. Verify request goes through gateway:
   ```bash
   # Correct: http://localhost/api/v1/tools/...
   # Wrong: http://localhost:8000/api/tools/...
   ```

### Import Error - gateway_auth Not Found

**Problem**: `ImportError: No module named 'gateway_auth'`

**Solution**: Add shared directory to Python path:
```python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'open-security-shared'))
```

### Docker Network Issues

**Problem**: Services can't reach each other

**Solution**: Verify all services are in same Docker network:
```bash
docker-compose ps
docker network inspect wildbox
```

## Best Practices

1. **Always use gateway in production** - Never expose backend services directly
2. **Log user actions** - Use `user.user_id` and `user.team_id` for audit trails
3. **Check plans/roles at feature level** - Not at endpoint level when possible
4. **Fail closed** - If headers missing, deny access (don't assume defaults)
5. **Trust the gateway** - Don't re-validate credentials in backend services

## Example: Complete Service Integration

```python
# File: open-security-myservice/app/auth.py
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'open-security-shared'))

from gateway_auth import get_user_from_gateway_headers, GatewayUser, require_plan
from fastapi import Depends

# Export for use in routers
__all__ = ["get_current_user", "require_pro_plan", "GatewayUser"]

# Alias for your service
get_current_user = get_user_from_gateway_headers

# Service-specific helpers
require_pro_plan = require_plan("pro", "business", "enterprise")
```

```python
# File: open-security-myservice/app/api/router.py
from fastapi import APIRouter, Depends
from app.auth import get_current_user, require_pro_plan, GatewayUser

router = APIRouter()

@router.get("/api/myservice/basic")
async def basic_feature(user: GatewayUser = Depends(get_current_user)):
    """Available to all authenticated users."""
    return {
        "message": f"Hello {user.user_id}",
        "plan": user.plan
    }

@router.get("/api/myservice/advanced")
async def advanced_feature(
    user: GatewayUser = Depends(get_current_user),
    _: None = Depends(require_pro_plan)
):
    """Only for pro+ users."""
    return {"message": "Advanced feature access granted"}
```

---

**Questions?** Check the reference implementation in `open-security-tools/app/auth.py`
