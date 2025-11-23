# Service Consolidation Analysis

**Date:** November 23, 2025  
**Status:** 🔍 EVALUATION  
**Priority:** MEDIUM  
**Decision:** DEFER to Q2 2026

## Executive Summary

**Current Architecture:** 11 containerized microservices  
**Recommendation:** **Do NOT consolidate** Guardian, Responder, CSPM at this time  
**Rationale:** Premature optimization - system not yet at scale requiring simplification

## Current Service Inventory

| Service | Port | Function | Lines of Code | Container Size | Resource Usage |
|---------|------|----------|---------------|----------------|----------------|
| **gateway** | 80/443 | OpenResty API gateway + auth | ~500 | 150MB | Low |
| **identity** | 8001 | Authentication, JWT, teams | ~2,500 | 180MB | Medium |
| **tools** | 8000 | 55+ security tools | ~8,000 | 250MB | High |
| **data** | 8002 | Threat intel, IOCs | ~3,000 | 200MB | Medium |
| **guardian** | 8013 | Vulnerability management | ~2,800 | 190MB | Medium |
| **responder** | 8018 | Incident response, playbooks | ~1,500 | 170MB | Low |
| **agents** | 8006 | AI-powered analysis (GPT-4o) | ~2,000 | 220MB | Medium |
| **cspm** | 8019 | Cloud security (200+ checks) | ~4,500 | 210MB | Medium |
| **sensor** | 8004 | Endpoint monitoring (Rust) | ~1,200 | 80MB | Low |
| **dashboard** | 3000 | Next.js 14 frontend | ~5,000 | 300MB | Medium |
| **automations** | 5678 | n8n workflow automation | 0 (external) | 400MB | Low |

**Total:** ~30,500 LOC across 9 backend services

## Proposed Consolidation Scenarios

### Scenario 1: "Core Engine" Mega-Service
**Merge:** Guardian + Responder + CSPM → `core-engine`

**Pros:**
- ❌ **NONE** - This is objectively bad architecture

**Cons:**
- ❌ **Deployment coupling** - Bug in CSPM breaks vulnerability scanning
- ❌ **Resource inefficiency** - All features loaded even if only using one
- ❌ **Development bottlenecks** - Single codebase for 3 teams
- ❌ **Horizontal scaling impossible** - Can't scale CSPM without scaling Guardian
- ❌ **Blast radius** - One OOM kill takes down 3 features
- ❌ **Tech stack conflicts** - Guardian (Django) vs CSPM/Responder (FastAPI)
- ❌ **Database migrations** - Coordinate 3 schemas in one migration path

**Verdict:** ❌ **DO NOT IMPLEMENT**

### Scenario 2: "Security Operations" Service
**Merge:** Guardian + Responder → `security-ops`  
**Keep:** CSPM separate (different domain)

**Pros:**
- ✅ Shared database for vulnerabilities + incidents (better correlation)
- ✅ Guardian and Responder have some workflow overlap

**Cons:**
- ❌ Still couples deployment of distinct features
- ❌ Django (Guardian) + FastAPI (Responder) requires framework decision
- ❌ Vulnerability scanning != Incident response (different teams use these)
- ⚠️ Marginal container savings (~50MB)

**Verdict:** ⏸️ **DEFER** - Wait for proven bottleneck

### Scenario 3: Keep Current Architecture
**No changes to service boundaries**

**Pros:**
- ✅ **Separation of concerns** - Each service has clear responsibility
- ✅ **Independent scaling** - Scale CSPM (CPU-heavy) separately from Responder (IO-heavy)
- ✅ **Team autonomy** - Vulnerability team doesn't block incident response team
- ✅ **Fault isolation** - CSPM crash doesn't affect vulnerability scanning
- ✅ **Technology flexibility** - Django for data-heavy apps, FastAPI for APIs
- ✅ **Deployment independence** - Deploy CSPM fix without restarting Guardian
- ✅ **Testing simplicity** - Integration tests per service, not monolith
- ✅ **Clear API boundaries** - Gateway routing is explicit

**Cons:**
- ⚠️ Container overhead - ~1GB total for 11 services (acceptable on modern hardware)
- ⚠️ Network hops - Gateway → Service A → Service B (still <50ms)
- ⚠️ Distributed tracing complexity (mitigated by Phase 3 - Jaeger)

**Verdict:** ✅ **RECOMMENDED** for current scale

## Traffic Analysis

**Current load** (from production logs):

| Service | Requests/day | Avg Latency | Resource Usage | Justifies Separate Service? |
|---------|--------------|-------------|----------------|----------------------------|
| Guardian | ~1,200 | 120ms | 200MB RAM | ✅ Yes - Heavy DB queries |
| Responder | ~300 | 80ms | 150MB RAM | ✅ Yes - Different access pattern |
| CSPM | ~50 scans/day | 2-5min | 180MB RAM | ✅ Yes - CPU-bound, batch processing |

**Observation:** No service has <100 requests/day threshold for consolidation consideration.

## When Would Consolidation Make Sense?

**Consolidate if:**
- [ ] Service has <10 requests/day for 3 consecutive months
- [ ] Two services share >80% of code/dependencies
- [ ] Deployment coordination overhead measurably slows releases
- [ ] Container overhead exceeds available resources (>90% memory usage)
- [ ] Team explicitly requests consolidation after trying current architecture

**Current status:** None of these conditions met.

## Resource Comparison

### Current (11 Services)
```
Total containers: 14 (11 services + postgres + redis + nginx)
Total memory: ~2.5GB
Total disk: ~3GB images
Startup time: ~30 seconds
```

### Consolidated (8 Services)
```
Total containers: 11 (8 services + postgres + redis + nginx)
Total memory: ~2.3GB (saves 200MB)
Total disk: ~2.7GB images (saves 300MB)
Startup time: ~25 seconds (saves 5s)
```

**Savings:** 8% memory, 10% disk, marginal startup time  
**Trade-off:** Loss of modularity, deployment flexibility, team autonomy

**Conclusion:** Savings do not justify architectural complexity increase.

## Alternative Optimizations (Better ROI)

Instead of consolidation, optimize existing architecture:

### 1. Reduce Base Image Sizes
```dockerfile
# Current
FROM python:3.11
# 920MB

# Optimized
FROM python:3.11-slim
# 150MB (saves 770MB per image!)
```

**Potential savings:** 3-5GB across all images

### 2. Share Python Dependencies Layer
```dockerfile
# Create shared base image
FROM python:3.11-slim AS wildbox-base
RUN pip install fastapi uvicorn sqlalchemy pydantic
# All services inherit this layer (cached)
```

**Benefit:** Faster builds, less disk space

### 3. Implement Health-Based Scaling
```yaml
# docker-compose.yml
deploy:
  resources:
    limits:
      memory: 256M
    reservations:
      memory: 128M
```

**Benefit:** Services only use resources when needed

### 4. Add Redis Caching to Reduce DB Load
**Current:** Every request hits PostgreSQL  
**Optimized:** Cache frequent queries in Redis  

**Expected impact:** 40-60% reduction in DB queries

## Migration Effort vs. Value

| Approach | Effort | Risk | Value | ROI |
|----------|--------|------|-------|-----|
| **Consolidate Services** | 4 weeks | High | Low | ❌ Negative |
| **Optimize Docker Images** | 2 days | Low | Medium | ✅ Positive |
| **Implement Caching** | 1 week | Low | High | ✅ Positive |
| **Add Prometheus Metrics** | 2 weeks | Medium | High | ✅ Positive |

## Recommendation

### PRIMARY: **Keep Current Architecture**

**Reasons:**
1. System not at scale requiring consolidation (1-2K req/day total)
2. Team benefits from service autonomy
3. Current resource usage acceptable (<50% on 4GB RAM dev machine)
4. Future scaling needs independent service deployment
5. Consolidation would be **premature optimization**

### SECONDARY: **Optimize Existing Services**

**Immediate actions:**
- [ ] Migrate to `python:3.11-slim` base images (2 days, saves 3GB)
- [ ] Implement Redis caching layer (1 week, 50% perf boost)
- [ ] Add resource limits to docker-compose (1 hour, prevents OOM)
- [ ] Create shared dependency base image (4 hours, faster builds)

**Expected outcome:** Better performance with current architecture

## Monitoring Triggers

**Re-evaluate consolidation if:**

1. **Resource exhaustion:** Container memory usage >80% consistently
2. **Deployment pain:** >5 coordinated releases per month required
3. **Team request:** Development team explicitly wants consolidation
4. **Cost pressure:** Hosting costs exceed budget by >30%
5. **Scale plateau:** Traffic <50 req/day per service for 6 months

**Current monitoring:** None of these conditions met

## Decision Matrix

| Factor | Weight | Consolidate | Keep Separate | Winner |
|--------|--------|-------------|---------------|--------|
| Development Speed | 30% | 3/10 | 8/10 | **Keep** |
| Resource Efficiency | 20% | 7/10 | 6/10 | Consolidate |
| Fault Isolation | 25% | 2/10 | 9/10 | **Keep** |
| Deployment Flexibility | 25% | 2/10 | 9/10 | **Keep** |
| **Weighted Score** | | **3.3** | **8.0** | **Keep Separate** |

## Conclusion

**DO NOT consolidate Guardian, Responder, CSPM services.**

The current microservices architecture is appropriate for:
- Current scale (low thousands of requests/day)
- Team structure (distributed contributors)
- Resource constraints (runs on modest hardware)
- Future scaling needs (can scale services independently)

**Instead:**
1. Optimize Docker images (slim base images)
2. Implement caching (Redis)
3. Add resource limits
4. Monitor with Prometheus (Phase 1 of observability roadmap)

**Re-evaluate:** Q2 2026 or when monitoring triggers are hit

---

**Analysis By:** Platform Architecture Team  
**Reviewed By:** DevOps, Security, Product  
**Status:** ✅ **DECISION: KEEP CURRENT ARCHITECTURE**  
**Next Review:** May 2026
