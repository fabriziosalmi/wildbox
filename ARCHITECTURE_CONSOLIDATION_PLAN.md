# Architecture Consolidation Plan

**Status:** PLANNING  
**Priority:** MEDIUM (Post-Critical Fixes)  
**Estimated Impact:** Reduce infrastructure overhead by 60-70%  
**Target:** Modular Monolith Architecture

---

## Problem Statement

From Brutal Rep Auditor v2.3:

> "A monolithic microservices cosplay that fakes its observability metrics. 12+ containers (Identity, Gateway, Tools, Data, CSPM, Guardian, Sensor, Responder, Agents, Dashboard, Redis, Postgres, Ollama, n8n) for a solo-dev project is architectural vanity, not engineering necessity."

> "CONSOLIDATE. Merge Identity, Gateway, and Tools into a single monolithic API. The overhead of separating them is not justified for this scale."

### Current Problems

1. **Resource Overhead**: Requires 32GB+ RAM just to boot
2. **Network Latency**: Client → Gateway → Identity → Service → Database (4+ hops)
3. **Deployment Complexity**: 12 containers to orchestrate
4. **Development Friction**: Changes often require updating multiple services
5. **Testing Complexity**: Integration tests require full stack

### When Microservices Make Sense

- **Scale:** >10 engineers, >100K requests/sec
- **Team Structure:** Independent teams owning services
- **Deployment Independence:** Services released on different schedules
- **Technology Diversity:** Different languages/frameworks per service

**Wildbox Reality:** Solo developer, <1K requests/sec, unified release schedule, all Python/TypeScript

---

## Proposed Architecture

### Phase 1: Core Consolidation (Immediate Impact)

**Merge:** Identity + Gateway + Tools → **Wildbox API**

**Benefits:**
- Eliminates 2 service containers
- Removes network hop (Gateway → Identity auth)
- Shared database connection pool
- Single deployment unit for core API
- RAM reduction: ~6GB → ~2GB

**Implementation:**

```python
# New structure: wildbox-api/
wildbox-api/
  ├── app/
  │   ├── main.py                 # FastAPI application
  │   ├── auth/                   # Identity service (auth, users, teams)
  │   │   ├── endpoints.py
  │   │   ├── models.py
  │   │   └── services.py
  │   ├── gateway/                # Routing & rate limiting (Nginx → middleware)
  │   │   ├── middleware.py
  │   │   ├── rate_limiting.py
  │   │   └── auth_middleware.py
  │   ├── tools/                  # Security tools execution
  │   │   ├── router.py
  │   │   ├── execution.py
  │   │   └── tools/              # 55+ security tools
  │   ├── database.py             # Shared DB connection
  │   ├── redis_client.py         # Shared Redis connection
  │   └── config.py               # Unified configuration
  ├── requirements.txt
  ├── Dockerfile
  └── README.md
```

**Migration Steps:**

1. Create `wildbox-api` directory
2. Copy identity service code to `app/auth/`
3. Convert OpenResty Lua middleware to FastAPI middleware
4. Move tools execution to `app/tools/`
5. Update frontend API clients (already support gateway mode)
6. Test with docker-compose
7. Deprecate old services

**Backwards Compatibility:**

```python
# app/main.py - Maintain existing API paths
app = FastAPI()

# Identity endpoints (already at /auth/*)
app.include_router(auth_router, prefix="/auth", tags=["auth"])

# Tools endpoints (already at /api/v1/tools/*)
app.include_router(tools_router, prefix="/api/v1/tools", tags=["tools"])

# Gateway health check
@app.get("/health")
async def gateway_health():
    return {"status": "healthy", "service": "wildbox-api"}
```

### Phase 2: Optional Services (Make Opt-In)

**Default Stack (Minimal):**
- wildbox-api (consolidated)
- postgres
- redis
- dashboard

**Optional Extensions** (via profiles):

```yaml
# docker-compose.yml
services:
  # ... core services ...
  
  data:
    profiles: ["full", "threat-intel"]
    # Threat intelligence & IOC management
  
  guardian:
    profiles: ["full", "vuln-mgmt"]
    # Vulnerability management
  
  responder:
    profiles: ["full", "incident-response"]
    # Incident response & playbooks
  
  agents:
    profiles: ["full", "ai"]
    # AI-powered analysis (requires GPU)
  
  cspm:
    profiles: ["full", "cloud"]
    # Cloud security posture management
  
  automations:
    profiles: ["full", "workflows"]
    # n8n workflow automation
  
  ollama:
    profiles: ["full", "ai"]
    # Local LLM (requires GPU + 16GB+ RAM)
```

**Usage:**

```bash
# Minimal stack (4 containers, ~8GB RAM)
docker-compose up -d

# With threat intelligence
docker-compose --profile threat-intel up -d

# Full platform (12 containers, 32GB RAM)
docker-compose --profile full up -d
```

**Benefits:**
- New users can start with minimal stack
- Power users can enable needed features
- Clear resource requirements per profile
- Easier testing (don't need full stack)

### Phase 3: Long-Term Modularity

**Keep Separate (Justified):**

1. **Dashboard** (Next.js) - Different runtime (Node.js vs Python)
2. **Sensor** (Rust) - Performance-critical endpoint monitoring
3. **Postgres** - Shared infrastructure
4. **Redis** - Shared infrastructure

**Evaluate for Consolidation:**

1. **Data Service** (Django) → Consider migrating to FastAPI in wildbox-api
2. **Guardian Service** (Django) → Consider migrating to FastAPI in wildbox-api
3. **Responder Service** (FastAPI) → Likely candidate for wildbox-api module
4. **Agents Service** (FastAPI) → Keep separate (optional, GPU-dependent)
5. **CSPM Service** (FastAPI) → Keep separate (optional, cloud-specific)

---

## Migration Strategy

### Option B: Strangler Fig (Recommended)

1. **Week 1-2:** Create wildbox-api with identity + gateway
   - Maintain old services running
   - Route 10% traffic to new service
   - Monitor for issues
   
2. **Week 3-4:** Migrate tools execution
   - Route 50% traffic to new service
   - Compare response times
   - Fix performance issues
   
3. **Week 5-6:** Full cutover
   - Route 100% traffic to wildbox-api
   - Monitor for 1 week
   - Deprecate old services

4. **Week 7+:** Optional services
   - Implement docker-compose profiles
   - Document resource requirements
   - Update deployment guides

### Rollback Plan

If consolidation causes issues:

```yaml
# docker-compose.override.yml (emergency rollback)
services:
  wildbox-api:
    profiles: ["disabled"]
  
  identity:
    profiles: ["active"]
  
  gateway:
    profiles: ["active"]
  
  tools:
    profiles: ["active"]
```

```bash
docker-compose --profile active up -d
```

---

## Expected Benefits

### Resource Savings

| Metric | Before (12 containers) | After (4-6 containers) | Savings |
|--------|------------------------|------------------------|---------|
| **RAM Usage** | 32GB+ | 8-12GB | 60-70% |
| **CPU Overhead** | 12 Python processes | 4-6 processes | 50% |
| **Network Hops** | 4-5 per request | 1-2 per request | 60% |
| **Docker Overhead** | 12 containers | 4-6 containers | 50-66% |
| **Boot Time** | 180+ seconds | 30-60 seconds | 66-83% |

### Performance Improvements

- **Request Latency:** 142ms avg → 50-80ms avg (eliminate inter-service calls)
- **Database Connections:** 7 pools → 2 pools (shared connections)
- **Redis Connections:** 7 clients → 2 clients (connection reuse)

### Developer Experience

- **Local Development:** Start 4 containers instead of 12
- **Testing:** Unit tests don't need full stack
- **Debugging:** Single codebase, easier to trace requests
- **Deployment:** One API service to deploy instead of three

### Operational Simplicity

- **Health Checks:** 4 endpoints instead of 12
- **Log Aggregation:** Fewer sources to correlate
- **Secrets Management:** Fewer services needing credentials
- **Backup/Restore:** Simpler with fewer moving parts

---

## Risks & Mitigations

### Risk 1: Blast Radius Increases

**Problem:** Bug in one module crashes entire API

**Mitigation:**
- Comprehensive test coverage (>80%)
- Error isolation (try/except at module boundaries)
- Circuit breakers for external calls
- Health checks per module
- Gradual rollout with monitoring

### Risk 2: Database Connection Limits

**Problem:** All services share one connection pool

**Mitigation:**
- Configure PostgreSQL for higher max_connections (100+)
- Use connection pooling (SQLAlchemy async)
- Monitor connection usage
- Implement connection limits per module

### Risk 3: Deployment Coupling

**Problem:** Can't deploy auth without deploying tools

**Mitigation:**
- Use feature flags for new features
- Maintain API versioning (v1, v2)
- Blue/green deployment strategy
- Comprehensive rollback plan

### Risk 4: Code Organization Complexity

**Problem:** One large codebase is harder to navigate

**Mitigation:**
- Clear module boundaries (auth/, tools/, gateway/)
- Shared code in common/ directory
- Enforced import rules (no circular dependencies)
- Module-specific README files
- Type hints and documentation

---

## Success Metrics

**Must Achieve:**

- [ ] 50%+ reduction in RAM usage
- [ ] 30%+ reduction in average request latency
- [ ] 100% API compatibility (no breaking changes)
- [ ] No regression in security tests
- [ ] Startup time <60 seconds

**Nice to Have:**

- [ ] 60%+ reduction in RAM usage
- [ ] 50%+ reduction in request latency
- [ ] Simplified deployment (single docker-compose up)
- [ ] Easier onboarding for new developers

---

## Timeline & Ownership

| Phase | Duration | Owner | Milestone |
|-------|----------|-------|-----------|
| **Phase 0:** Planning & Design | 1 week | Architect | Architecture doc approved |
| **Phase 1:** Create wildbox-api | 2 weeks | Backend | Service runs, passes tests |
| **Phase 2:** Migrate identity | 1 week | Backend | Auth works in new service |
| **Phase 3:** Migrate gateway | 1 week | Backend | Routing works, rate limiting OK |
| **Phase 4:** Migrate tools | 2 weeks | Backend | All 55 tools execute correctly |
| **Phase 5:** Testing & Validation | 1 week | QA | All tests pass, performance OK |
| **Phase 6:** Gradual Rollout | 2 weeks | DevOps | 100% traffic on new service |
| **Phase 7:** Cleanup | 1 week | DevOps | Old services deprecated |

**Total Duration:** 11 weeks (~3 months)


---


