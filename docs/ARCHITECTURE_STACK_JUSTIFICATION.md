# Architecture Stack Evaluation

> **Partly superseded.** This evaluation was written in November 2025. The
> reasoning still stands, but several statements about the deployment were
> wrong or have changed; they are corrected in place below, and the
> benchmark figures cannot be reproduced. For the services that run today see
> <https://www.wildbox.io/guides/ports/>.

**Purpose**: Justify technical choices for Wildbox's infrastructure stack and identify simplification opportunities.

## Current Stack

### Core Infrastructure

- **OpenResty (Nginx + Lua)**: API gateway, authentication, rate limiting
- **PostgreSQL 15**: Relational database (users, teams, vulnerabilities, IOCs)
- **Redis 7**: Caching, session storage, rate limiting, Celery broker
- **Celery**: Distributed task queue for background jobs

### Question: Is this over-engineered?

**TL;DR**: No for production security platform. Each component serves a distinct purpose that simpler alternatives cannot fulfill.

---

## Component Justification

### 1. OpenResty (Nginx + Lua) vs. Alternatives

**Why OpenResty?**

- **Lua scripting**: Authentication logic at gateway level (reduces latency)
- **Performance**: C-based Nginx core handles 10k+ req/sec
- **Header injection**: Secure `X-Wildbox-User-ID` injection prevents backend spoofing
- **Centralized auth**: Backend services trust gateway headers, no JWT validation per-service

**Alternatives Considered**:

| Alternative | Why Not Chosen |
| ------------ | ---------------- |
| **Traefik** | Lacks Lua scripting for custom auth logic, middleware limited |
| **Kong** | Overkill (plugin ecosystem we don't need), higher resource usage |
| **Envoy** | Excellent choice, but steeper learning curve for Lua → WASM migration |
| **Express.js Gateway** | Node.js overhead, slower than Nginx, single-threaded |
| **None (direct access)** | No centralized auth, rate limiting, or request validation |

**Verdict**: ✅ **Keep OpenResty**. Gateway pattern is industry standard for microservices. Lua auth handler is ~100 lines vs. duplicating JWT validation across 10+ services.

**Simplification Option**: Migrate to **Envoy** if team has experience with WASM filters. Otherwise, OpenResty is optimal.

---

### 2. PostgreSQL vs. Alternatives

**Why PostgreSQL?**

- **ACID compliance**: Critical for auth, subscriptions, financial data
- **JSON support**: Store flexible data (IOCs, CSPM findings) without schema changes
- **Performance**: Handles 10k+ writes/sec with proper indexing
- **Extensions**: PostGIS for geolocation, pg_trgm for fuzzy search
- **Ecosystem**: Battle-tested, extensive tooling (pgAdmin, pg_dump, Alembic)

**Alternatives Considered**:

| Alternative | Why Not Chosen |
| ------------ | ---------------- |
| **MySQL** | Weaker JSON support, less ACID strict in default config |
| **MongoDB** | No ACID across collections (pre-v4), auth data requires consistency |
| **SQLite** | No concurrent writes, unsuitable for multi-service architecture |
| **Supabase** | Vendor lock-in, hosted solution increases attack surface |

**Current State**:

- **1 PostgreSQL instance, 3 databases**: `identity` (the default
  `POSTGRES_DB`), plus `guardian` and `data` created by
  `scripts/init-databases.sql`
- Each service keeps its own connection pool; there is no PgBouncer

**Simplification Needed?**:

❌ **No**. Consolidating into fewer databases increases blast radius (one compromised service = all data exposed). Current separation follows **database-per-service pattern** (microservices best practice).

**Potential Optimization**:

- Use **read replicas** for analytics queries (current: all queries hit primary)
- Implement **connection pooling** via PgBouncer (reduces connection overhead)

**Verdict**: ✅ **Keep PostgreSQL**. Industry standard for OLTP workloads. No simpler alternative provides ACID + JSON + extensions.

---

### 3. Redis vs. Alternatives

**Why Redis?**

- **Performance**: 100k+ ops/sec in-memory
- **Celery broker**: Task queue requires Redis or RabbitMQ
- **Session storage**: TTL-based expiry (JWT denylisting, API rate limits)
- **Atomic operations**: INCR for rate limiting (thread-safe without locks)

The gateway does not use Redis for its authorization cache or its per-team
rate limit counters: both live in nginx shared memory (`lua_shared_dict
auth_cache` and `rate_limit_cache` in `open-security-gateway/nginx/nginx.conf`).

**Current Usage**:

- **1 Redis instance, 5 logical databases in use** (the server allows 16):
  DB 0 identity, DB 1 guardian, DB 2 tools and responder, DB 3 CSPM, DB 4
  agents
- **Celery brokers**: each service's Celery app uses that service's database;
  there is no shared broker database

**Alternatives Considered**:

| Alternative | Why Not Chosen |
| ------------ | ---------------- |
| **Memcached** | No persistence, no Celery support, no atomic ops |
| **In-memory dicts** | Shared state across containers impossible, no TTL |
| **RabbitMQ** | Heavier (Erlang VM), overkill for our queue volume |
| **PostgreSQL LISTEN/NOTIFY** | Not designed for task queues, no retry/dead-letter |

**Simplification Needed?**:

⚠️ **Maybe**. Logical DB separation (DB 0-15) is organizational convenience, not security boundary. Could consolidate to:

- **DB 0**: All application caching
- **DB 1**: Celery broker

**Risk**: Key collisions if services use same key names. Mitigation: Prefix keys (`identity:user:123`, `guardian:vuln:456`).

**Verdict**: ✅ **Keep Redis**. Essential for Celery and high-performance caching. Simplification = use key prefixes instead of logical DBs.

---

### 4. Celery vs. Alternatives

**Why Celery?**

- **Background jobs**: Port scanning, DNS enumeration, CSPM checks (long-running)
- **Scheduling**: Periodic tasks (daily CVE updates, weekly reports)
- **Retry logic**: Exponential backoff for failed API calls
- **Monitoring**: Flower dashboard for task visibility

**Current Usage**:

- **Tools service**: tool runs execute in the `tools-worker` container
- **Guardian service**: `guardian-worker` and `guardian-beat` (scans, alert
  rules, reports)
- **CSPM service**: scans execute in the `cspm-worker` container
- **Data service**: does not use Celery; feed collection runs in the
  `data-scheduler` container (`python -m app.scheduler.main`)

**Alternatives Considered**:

| Alternative | Why Not Chosen |
| ------------ | ---------------- |
| **APScheduler** | No distributed workers, single-process (not fault-tolerant) |
| **Kubernetes CronJobs** | For scheduled tasks, not ad-hoc jobs. No retry logic. |
| **AWS Lambda** | Vendor lock-in, cold start latency, cost for high volume |
| **Background threads** | No distribution across containers, memory leaks accumulate |

**Simplification Needed?**:

❌ **No**. Security tools (port scans, fuzzing, cloud checks) are CPU-intensive and must run asynchronously. Without Celery:

- API endpoints block for minutes (port scan of /16 subnet = 20+ minutes)
- No fault tolerance (worker crash = lost job)
- No rate limiting (all jobs run simultaneously, exhaust memory)

**Verdict**: ✅ **Keep Celery**. Critical for production-grade async task execution. No simpler alternative provides distribution + retry + monitoring.

---

## Simplification Opportunities

### 1. Consolidate Redis Logical Databases

**Current**: 5 logical databases in use  
**Proposed**: 2 databases with key prefixes

```python
# Before (DB 0 for identity)
redis_client = redis.StrictRedis(host='wildbox-redis', db=0)
redis_client.set('user:123', data)

# After (DB 0 for all, prefixed keys)
redis_client = redis.StrictRedis(host='wildbox-redis', db=0)
redis_client.set('identity:user:123', data)
redis_client.set('guardian:vuln:456', data)
```

**Benefits**:

- Simpler configuration (no DB number management)
- Better visibility (all keys in one namespace)
- Minimal code changes (update key generation functions)

**Risks**:

- Key collision if prefixes not enforced
- Slightly harder to flush single service's cache (`FLUSHDB` won't work)

**Verdict**: ✅ **Implement in v0.3.0**. Low effort, reduces complexity.

---

### 2. Remove Unused Services

**Analysis**:

- **Automations (n8n)**: at the time, upstream marked `down` in gateway config
- **CSPM**: 314 files, extensive testing required before production

**Outcome**:

- **Automations**: done differently. n8n is now in the `automations` Compose
  profile, off by default, and the gateway resolves it at request time on
  `/api/v1/automations/`.
- **CSPM**: not done. CSPM starts by default and no `ENABLE_CSPM` setting
  exists.

---

### 3. Database Connection Pooling

**Current**: Each service creates own connection pool (wasteful)  
**Proposed**: Single **PgBouncer** instance

```yaml
# docker-compose.yml
pgbouncer:
  image: pgbouncer/pgbouncer
  environment:
    - DATABASES_HOST=postgres
    - POOL_MODE=transaction
    - MAX_CLIENT_CONN=1000
    - DEFAULT_POOL_SIZE=25
```

**Benefits**:

- Reduce PostgreSQL connections (current: ~100 per service = 1000+ total)
- Faster connection reuse (connection handshake cached)
- Centralized connection limits

**Effort**: Medium (1-2 days)  
**Verdict**: ⚠️ **Evaluate in v0.4.0**. Useful at scale (>1000 req/sec), overkill for current load.

---

## "Do You Really Need This?" Decision Tree

```text
Need background jobs (port scans, API fuzzing)?
  ├─ Yes → Keep Celery + Redis
  └─ No → Use APScheduler (but lose distribution)

Need centralized authentication + rate limiting?
  ├─ Yes → Keep OpenResty gateway
  └─ No → Direct service access (but lose security controls)

Need ACID transactions (auth, billing, subscriptions)?
  ├─ Yes → Keep PostgreSQL
  └─ No → SQLite (but lose concurrency)

Need sub-millisecond caching?
  ├─ Yes → Keep Redis
  └─ No → PostgreSQL JSONB (but lose TTL, atomic ops)
```

---

## Recommended Minimal Stack

If Wildbox were **only** a dashboard (no security tools), this would suffice:

```yaml
services:
  dashboard:
    # Next.js frontend
  
  api:
    # Single FastAPI backend
  
  postgres:
    # Database
```

**What's lost**:

- No background jobs (port scanning, fuzzing)
- No rate limiting (DDoS vulnerable)
- No centralized auth (JWT validation per-endpoint)
- No caching (slower, higher DB load)

**Conclusion**: Current stack is **appropriate for a security platform**. Simpler alternatives sacrifice core functionality.

---

## Performance Benchmarks (Justify Complexity)

> **Not reproducible.** No script or result file in the repository produced
> these figures, so treat them as illustrations, not measurements. The Redis
> hit-rate example does not measure the gateway's authorization cache, which
> is held in nginx shared memory, not in Redis.

### Gateway Performance (OpenResty)

```bash
# Authenticated requests with Lua validation
wrk -t4 -c100 -d30s https://api.wildbox.local/health
  --header "Authorization: Bearer <token>"

Results:
  Requests/sec: 12,453
  Latency (avg): 8.03ms
  Transfer/sec: 2.15MB
```

**Comparison**: Node.js Express gateway = ~3,500 req/sec (3.5x slower)

### Celery Task Throughput

```bash
# Port scan of /24 subnet (254 hosts)
celery -A app.celery_app worker --loglevel=info --concurrency=10

Results:
  Completed: 254 scans in 4m 32s
  Throughput: ~56 scans/min
  Avg task time: 1.07s
```

**Without Celery**: Sequential execution = 254 * 1.07s = **4.5 minutes**. Celery parallelizes to **4.5 minutes total** (10x speedup).

### Redis Cache Hit Rate (Gateway Auth)

```bash
# 10,000 requests with same JWT token
redis-cli INFO stats | grep keyspace_hits

Results:
  keyspace_hits: 9,987
  keyspace_misses: 13
  Hit rate: 99.87%
```

**Impact**: DB queries reduced to 13, down 769x on the previous 10,000. Response time: 8ms (cached) vs. 45ms (DB query).

---

## Final Verdict

### Keep (Critical to platform)

- ✅ **OpenResty**: Gateway pattern industry standard, Lua auth = performance
- ✅ **PostgreSQL**: ACID, JSON, extensions essential for security data
- ✅ **Redis**: Celery broker + caching irreplaceable
- ✅ **Celery**: Async jobs core to security tools

### Simplify (Low effort, high clarity)

- ✅ **Consolidate Redis DBs**: Use key prefixes instead of logical databases
- ✅ **Disable unused services**: n8n is now an opt-in Compose profile; CSPM
  still starts by default

### Defer (Optimize at scale)

- ⏸️ **PgBouncer**: Useful at >1000 req/sec, not needed yet
- ⏸️ **Read replicas**: Implement when analytics queries slow primary DB

---

**Conclusion**: Stack is **not over-engineered** for a production security platform. Each component is justified by specific requirements (async jobs, performance, ACID). Simplification efforts should focus on **operational clarity** (logical DB consolidation) rather than removing infrastructure.

---

**Last Updated**: 2025-11-24  
**Review Cycle**: Quarterly (reassess as platform scales)  
**Related Docs**:

- `docs/GATEWAY_AUTHENTICATION_GUIDE.md`
- `docs/SERVICE_LIFECYCLE.md`
- `docs/OBSERVABILITY_ROADMAP.md`
