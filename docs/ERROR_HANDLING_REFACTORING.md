# Error Handling Refactoring Guide

**Status:** 🟡 IN PROGRESS  
**Priority:** HIGH  
**Impact:** Monitoring, Observability, API Standards

## The Problem

Current codebase uses **anti-pattern** of returning `{"success": False, "error": "message"}` objects instead of proper HTTP status codes:

### ❌ **WRONG** (Current)
```python
def execute_tool(params):
    try:
        # ... logic ...
        return {"success": True, "result": data}
    except ValueError:
        return {"success": False, "error": "Invalid input"}  # Returns 200 OK!
```

**Why This Breaks Monitoring:**
- Prometheus/Grafana see `200 OK` for failures
- API gateways can't rate-limit by error codes
- Load balancers can't detect unhealthy services
- Logs don't show HTTP error patterns
- Frontend has to parse JSON to know if request failed

### ✅ **CORRECT** (Target)
```python
from fastapi import HTTPException

def execute_tool(params):
    if not validate(params):
        raise HTTPException(
            status_code=400,
            detail="Invalid input parameters"
        )
    
    try:
        # ... logic ...
        return {"result": data}  # Success = 200 OK with data
    except ConnectionError:
        raise HTTPException(
            status_code=503,
            detail="Service unavailable"
        )
```

## HTTP Status Code Guide

| Code | When to Use | Example |
|------|-------------|---------|
| **200** | Success with response body | Data retrieved successfully |
| **201** | Resource created | New vulnerability added |
| **204** | Success with no content | Delete operation completed |
| **400** | Client error - bad request | Invalid JSON, missing fields |
| **401** | Not authenticated | Missing/invalid JWT token |
| **403** | Forbidden | User lacks permission for resource |
| **404** | Resource not found | Vulnerability ID doesn't exist |
| **409** | Conflict | Duplicate entry, version mismatch |
| **422** | Validation failed | Parameters fail schema validation |
| **429** | Rate limit exceeded | Too many requests |
| **500** | Internal server error | Unexpected exception |
| **502** | Bad gateway | Upstream service returned invalid response |
| **503** | Service unavailable | Database connection failed |
| **504** | Gateway timeout | Upstream service didn't respond |

## Files Refactored

### ✅ Completed
- [x] `open-security-tools/app/tools/security_automation_orchestrator/main.py`

### 🚧 In Progress
- [ ] `open-security-agents/app/tools/langchain_tools.py` (⚠️ Special case - LangChain tool returns)
- [ ] `open-security-agents/app/tools/wildbox_client.py` (Client library - different pattern)

### ⏳ Pending
- [ ] Review all FastAPI route handlers in:
  - `open-security-identity/app/api_v1/endpoints/*.py`
  - `open-security-guardian/api/views.py` (Django REST)
  - `open-security-data/api/views.py` (Django REST)
  - `open-security-responder/app/api/*.py`
  - `open-security-cspm/app/api/*.py`

## Refactoring Patterns

### Pattern 1: Simple Validation
```python
# Before
if not user_input:
    return {"success": False, "error": "Missing input"}

# After
if not user_input:
    raise HTTPException(status_code=400, detail="Missing required input")
```

### Pattern 2: Database Errors
```python
# Before
try:
    result = db.query(...)
except DBError as e:
    return {"success": False, "error": str(e)}

# After
try:
    result = db.query(...)
except DBError as e:
    logger.error(f"Database error: {e}", exc_info=True)
    raise HTTPException(status_code=503, detail="Database temporarily unavailable")
```

### Pattern 3: External API Calls
```python
# Before
try:
    response = requests.get(external_api)
    if response.status_code != 200:
        return {"success": False, "error": "API failed"}
except Timeout:
    return {"success": False, "error": "Timeout"}

# After
try:
    response = requests.get(external_api, timeout=5)
    response.raise_for_status()  # Raises HTTPError for 4xx/5xx
except requests.Timeout:
    raise HTTPException(status_code=504, detail="External API timeout")
except requests.HTTPError as e:
    raise HTTPException(status_code=502, detail=f"External API error: {e.response.status_code}")
```

### Pattern 4: Authorization Checks
```python
# Before
if not user.has_permission(resource):
    return {"success": False, "error": "Not authorized"}

# After
if not user.has_permission(resource):
    raise HTTPException(
        status_code=403,
        detail=f"User lacks '{required_permission}' permission"
    )
```

## Special Cases

### LangChain Tools (Agents Service)

**Current:** Returns JSON strings for tool execution results
```python
return json.dumps({"error": str(e), "success": False})
```

**Status:** ⚠️ **KEEP AS IS** - LangChain expects string returns from tools, not HTTP responses. This is a framework requirement, not an API endpoint.

### Client Libraries

Files like `wildbox_client.py` are **SDK/client code**, not API endpoints. They should:
- Return `Result[T, Error]` types or tuples: `(data, error)`
- Or raise custom exceptions that callers can catch
- Do NOT use HTTPException (that's for FastAPI routes only)

```python
# Client library pattern
class WildboxClient:
    def get_vulnerabilities(self):
        try:
            response = self.session.get('/api/vulnerabilities')
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            # Re-raise with context, let caller handle
            raise WildboxAPIError(f"Failed to fetch vulnerabilities: {e}")
```

## Testing Updated Endpoints

### Before (Broken Monitoring)
```bash
$ curl -X POST /api/tool/execute -d '{"tool": "invalid"}'
HTTP/1.1 200 OK
{"success": false, "error": "Tool invalid not authorized"}

# Prometheus records: 200 OK ✅ (WRONG!)
```

### After (Proper Status Codes)
```bash
$ curl -X POST /api/tool/execute -d '{"tool": "invalid"}'
HTTP/1.1 403 Forbidden
{"detail": "Tool 'invalid' not authorized. Available tools: ..."}

# Prometheus records: 403 Forbidden ❌ (CORRECT!)
```

## Migration Checklist

For each file being refactored:

- [ ] Identify all `return {"success": False, ...}` patterns
- [ ] Determine appropriate HTTP status code (see table above)
- [ ] Replace with `raise HTTPException(status_code=..., detail=...)`
- [ ] Remove `{"success": True, "result": ...}` wrapper - just return data
- [ ] Update tests to check `response.status_code` instead of `response.json()["success"]`
- [ ] Update API documentation (OpenAPI/Swagger auto-updates)
- [ ] Verify gateway auth doesn't break with new error codes
- [ ] Test with real monitoring tools (Prometheus scraper)

## Rollout Plan

1. **Phase 1** (Current): Core orchestrator and shared utilities
2. **Phase 2**: FastAPI services (identity, responder, cspm)
3. **Phase 3**: Django services (guardian, data) - use DRF exception handlers
4. **Phase 4**: Frontend updates to remove `.success` checks
5. **Phase 5**: Update monitoring dashboards and alerts

## Breaking Changes

⚠️ **Frontend Impact**: Dashboard code currently checks `response.data.success`:

```typescript
// OLD (will break after refactor)
const response = await api.executeTool(params)
if (response.data.success) {
  // handle success
}

// NEW (correct way)
try {
  const data = await api.executeTool(params)
  // 2xx response = success, data is the result
} catch (error) {
  // 4xx/5xx response = failure, error.response.status has code
  if (error.response?.status === 403) {
    // handle authorization
  }
}
```

## Documentation Updates Needed

- [ ] API reference docs (OpenAPI specs will auto-update)
- [ ] Developer guide - error handling section
- [ ] Integration test examples
- [ ] Gateway routing guide (error code passthrough)

---

**Next Steps:**
1. Review all FastAPI route handlers for anti-pattern
2. Create issue template for error handling refactor PRs
3. Update pre-commit hooks to flag `{"success": False}` pattern

**Reference:** This is industry standard RESTful API design. See:
- [RFC 7231 - HTTP Status Codes](https://tools.ietf.org/html/rfc7231#section-6)
- [FastAPI Exception Handling](https://fastapi.tiangolo.com/tutorial/handling-errors/)
- [REST API Error Handling Best Practices](https://www.baeldung.com/rest-api-error-handling-best-practices)
