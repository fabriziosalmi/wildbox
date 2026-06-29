# Wildbox Architecture Decision Records (ADR)

**Version:** 1.0  
**Last Updated:** November 23, 2025

---

## ADR-001: Microservices Architecture

**Status:** ACCEPTED (with caveats)  
**Date:** 2025-11-23  
**Deciders:** Core Team  
**Context:** Post-audit review revealed concerns about over-engineering

### Decision

Wildbox uses a **microservices architecture** with 11 distinct services orchestrated via Docker Compose. This is acknowledged as heavy for a self-hosted tool but provides specific benefits for a security platform.

### Rationale

**Why Microservices:**

1. **Isolation:** Security tool failures shouldn't cascade (e.g., vulnerability scanner crash shouldn't break threat intel feeds)
2. **Technology fit:** Different services have different needs:
   - Django for Guardian (admin UI, ORM)
   - FastAPI for API/Tools (performance, async)
   - Rust for Sensor (system-level access)
   - Node.js for n8n (workflow engine)
3. **Independent scaling:** CSPM scans are CPU-heavy; Data service is I/O-heavy
4. **Development velocity:** Teams can work on services independently (future consideration)

**Acknowledged Downsides:**

- **Resource consumption:** ~4-8GB RAM baseline (see hardware requirements below)
- **Operational complexity:** 11 containers to monitor
- **Network overhead:** Inter-service HTTP calls add latency
- **Overkill for small deployments:** Solo users may not need full suite

### Consequences

**Hardware Requirements:**

| Deployment | RAM | CPU | Storage | Notes |
|------------|-----|-----|---------|-------|
| **Minimal** (no AI/CSPM) | 4GB | 2 cores | 20GB | Identity + Tools + Data only |
| **Standard** (with AI) | 8GB | 4 cores | 50GB | All services except CSPM |
| **Full** (all services) | 16GB+ | 6+ cores | 100GB | Production-grade deployment |

**For Resource-Constrained Environments:**

See `docker-compose.minimal.yml` (planned) for a single-container deployment.

### Alternatives Considered

1. **Monolith:** Single Python app with modules
   - Rejected: Harder to isolate failures in security context
   - May revisit if community feedback indicates over-engineering

2. **Modular Monolith:** Single app with clear module boundaries
   - Under consideration for v3.0
   - Would reduce to 3 containers: App + LLM + Automations

### Future Review

- **Q2 2026:** Assess usage patterns and consider consolidation
- **Trigger:** If >80% of users disable 3+ services, refactor to monolith

---

## ADR-002: n8n Integration

**Status:** ACCEPTED  
**Date:** 2025-11-23  
**Deciders:** Core Team  

### Decision

Bundle **n8n workflow automation** as a core service rather than using a lightweight custom solution.

### Rationale

**Why n8n:**

1. **No-code workflows:** Allows non-developers to create incident response playbooks
2. **200+ integrations:** Pre-built connectors for Slack, Jira, email, webhooks
3. **Visual workflow editor:** Better UX than YAML-based playbook definitions
4. **Community support:** Active ecosystem, maintained by VC-backed company

**Cost:**

- **Image size:** ~500MB
- **Runtime RAM:** ~300-500MB
- **Startup time:** ~10s

**Alternatives Considered:**

1. **Prefect/Airflow:** Too heavyweight, data engineering focus
2. **Custom Python workflows:** Would take 6+ months to build equivalent UX
3. **No automation:** Defeats SOAR promise

### Migration Path

If n8n proves too heavy, we can:
1. Make it **optional** (separate docker-compose.automations.yml)
2. Replace with lightweight alternatives (Temporal, custom)
3. Provide export to standard playbook formats

---

## ADR-003: Ollama for Local LLM

**Status:** ACCEPTED (with performance caveats)  
**Date:** 2025-11-23  
**Deciders:** Core Team

### Decision

Use **Ollama** with Qwen2.5-0.5B model for local AI inference rather than cloud APIs.

### Rationale

**Why Local LLM:**

1. **Privacy:** Security data never leaves infrastructure
2. **No API costs:** OpenAI GPT-4 would cost $100+/month for heavy users
3. **Offline capability:** Works in air-gapped environments
4. **Compliance:** Meets data sovereignty requirements

**Why Ollama:**

- **OpenAI-compatible API:** Drop-in replacement for cloud services
- **Efficient:** Qwen2.5-0.5B runs on CPU with 2GB RAM
- **Simple:** Single container, no manual model management

**Performance Expectations:**

| Hardware | Tokens/sec | Use Case |
|----------|-----------|----------|
| CPU (4 cores) | ~10-20 | Acceptable for analysis tasks |
| GPU (RTX 3060) | ~100+ | Real-time chat |

**Model Choice - Qwen2.5-0.5B:**
- **Size:** 300MB (fits in RAM)
- **Quality:** Sufficient for log analysis, IOC extraction
- **Speed:** Fast enough for non-interactive tasks

### Alternatives

1. **Cloud APIs (OpenAI/Anthropic):**
   - Pro: Better quality
   - Con: Privacy, cost, internet dependency
   - **Supported:** Users can configure `OPENAI_API_KEY` to override local LLM

2. **vLLM with larger models:**
   - Pro: Better quality (Qwen3-7B)
   - Con: Requires 8GB+ VRAM
   - **Available:** See `docker-compose.gpu.yml` for GPU deployments

3. **No AI:**
   - Con: Loses competitive advantage
   - **Supported:** AI service can be disabled

### Resource Impact

- **With Ollama:** +2GB RAM, +500MB disk
- **With vLLM (GPU):** +8GB VRAM, +10GB disk
- **With Cloud API:** +0 resources, +$50-200/month cost

---

## ADR-004: Redis as Shared State Layer

**Status:** ACCEPTED  
**Date:** 2025-11-23  
**Deciders:** Core Team

### Decision

Use **single Redis instance** with logical database separation rather than multiple instances or alternative state stores.

### Rationale

**Why Single Redis:**

1. **Resource efficiency:** One instance uses 50-100MB RAM vs 500MB+ for multiple
2. **Operational simplicity:** One container to monitor and backup
3. **Sufficient isolation:** Logical DBs (0-15) prevent key collisions

**Database Allocation:**
```
DB 0: Identity (sessions, auth cache)
DB 1: Guardian (vulnerability cache)
DB 2: Tools (rate limiting, task queue)
DB 4: Agents (LLM conversation history)
DB 5: Gateway (authorization cache)
```

**Alternatives Considered:**

1. **Multiple Redis instances:** Rejected (memory waste)
2. **PostgreSQL for all state:** Rejected (slower for cache/sessions)
3. **Valkey (Redis fork):** Under consideration for v3.0

### Persistence Strategy

- **Development:** In-memory only (fast, disposable)
- **Production:** AOF + daily snapshots (see `redis.conf`)

---

## ADR-005: PostgreSQL for Primary Storage

**Status:** ACCEPTED  
**Date:** 2025-11-23  
**Deciders:** Core Team

### Decision

Use **single PostgreSQL 15 instance** with separate databases per service.

### Rationale

**Why Single Postgres:**

1. **Connection pooling:** Shared across services
2. **Backup simplicity:** One pg_dump for all data
3. **Resource efficiency:** ~200MB RAM vs 1GB+ for multiple instances

**Database Separation:**
- `identity`: User accounts, teams, subscriptions
- `data`: Threat intelligence, IOCs, feeds
- `guardian`: Vulnerabilities, assets, tickets
- (Each service has isolated schema)

**Why PostgreSQL over MySQL/MongoDB:**

1. **JSONB support:** Flexible schema for IOC storage
2. **Full-text search:** Better than MySQL for threat intel
3. **Geospatial:** PostGIS for IP geolocation
4. **Compliance:** ACID guarantees for audit logs

---

## ADR-006: Docker Compose for Orchestration

**Status:** ACCEPTED (development) / UNDER REVIEW (production)  
**Date:** 2025-11-23  
**Deciders:** Core Team

### Decision

Use **Docker Compose** for development and small-scale deployments. Provide **Kubernetes manifests** for production clusters.

### Rationale

**Why Docker Compose:**

1. **Simplicity:** Single `docker-compose up` command
2. **Portability:** Works on any Docker-enabled system
3. **Local development:** Fast iteration cycle
4. **Good enough:** Handles 90% of use cases

**Limitations:**

- **No auto-scaling:** Manual container management
- **Single-host:** Can't distribute across nodes
- **No rolling updates:** Requires downtime
- **Limited health checks:** Basic only

### Production Path

For enterprise deployments:

1. **Kubernetes:** See `k8s/` directory (planned Q1 2026)
2. **Docker Swarm:** Lightweight alternative (documented)
3. **Nomad:** HashiCorp shops (community-contributed)

### Hardware Recommendations

**Development:**
- Docker Desktop on laptop (8GB+ RAM)
- Disable unused services in `docker-compose.override.yml`

**Production:**
- Dedicated server: 16GB RAM, 6 cores, 100GB SSD
- OR Cloud VM: AWS t3.xlarge, GCP e2-standard-4

---

## ADR-007: FastAPI for API Services

**Status:** ACCEPTED  
**Date:** 2025-11-23  
**Deciders:** Core Team

### Decision

Use **FastAPI** for new API services (Tools, Agents, Responder, CSPM).

### Rationale

**Why FastAPI:**

1. **Performance:** 2-3x faster than Flask/Django REST
2. **Async support:** Native async/await for I/O-bound security scans
3. **Type safety:** Pydantic validation prevents injection attacks
4. **Auto-documentation:** OpenAPI/Swagger out of the box
5. **Modern:** Python 3.11+ type hints, dependency injection

**Why Not Flask:**
- Slower, no native async
- Manual validation (security risk)

**Why Not Django REST Framework:**
- Heavier, includes ORM overhead
- Guardian service uses Django for admin UI (makes sense there)

---

## ADR-008: Audit Remediation - November 2025

**Status:** IN PROGRESS  
**Date:** 2025-11-23  
**Context:** Brutal audit revealed critical security issues

### Decisions Made

1. **Remove hardcoded secrets:** ✅ COMPLETED
2. **Pin all dependencies:** ✅ COMPLETED  
3. **Fix test suite sabotage:** ✅ COMPLETED
4. **Create engineering standards:** ✅ COMPLETED
5. **Automated security validation:** ✅ COMPLETED

### Remaining Work

1. **Reduce blanket exception handling** (67 instances)
2. **Implement real health metrics** (remove mock data)
3. **Add resource limits** to containers
4. **Re-enable integration tests** (currently disabled)
5. **Consolidate microservices** (evaluate Q2 2026)

### Architectural Decisions Under Review

The audit challenged our microservices approach as "over-engineering." We're evaluating:

**Option A: Keep microservices** (current)
- Pro: Isolation, technology fit
- Con: Resource heavy, operational complexity

**Option B: Consolidate to 3 services**
- Monolith (Identity + Tools + Data + Guardian + Responder)
- LLM (Ollama/vLLM)
- Automations (n8n)
- Pro: Simpler, lighter
- Con: Less isolation, harder to maintain

**Decision Timeline:** Q2 2026 based on user feedback

---

## Summary Table

| Decision | Status | Resource Impact | Reversibility |
|----------|--------|----------------|---------------|
| Microservices | ✅ ACCEPTED | HIGH (8-16GB) | MEDIUM (Q2 2026 review) |
| n8n | ✅ ACCEPTED | MEDIUM (500MB) | HIGH (optional service) |
| Ollama | ✅ ACCEPTED | MEDIUM (2GB) | HIGH (cloud API alternative) |
| Single Redis | ✅ ACCEPTED | LOW (100MB) | LOW |
| Single Postgres | ✅ ACCEPTED | LOW (200MB) | LOW |
| Docker Compose | ✅ ACCEPTED | N/A | HIGH (K8s planned) |
| FastAPI | ✅ ACCEPTED | N/A | MEDIUM |

---

## Feedback & Review

**Questions or concerns about architecture decisions?**

- Open GitHub Discussion: [Architecture Review](https://github.com/fabriziosalmi/wildbox/discussions)
- Email: architecture@wildbox.dev

**Next ADR Review:** Q2 2026 (or when user base reaches 1000 deployments)
