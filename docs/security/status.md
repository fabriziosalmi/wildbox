# Wildbox Security Status Report

**Date**: February 22, 2026
**Version**: v0.5.5
**Scope**: Complete security audit, vulnerability remediation, and dependency updates
**Status**: Security-Hardened

---

## Vulnerability Metrics

| Metric | Value |
| -------- | ------- |
| **Initial Vulnerabilities (Nov 2024)** | 29 (6 critical, 10 high, 9 moderate, 4 low) |
| **After Phase 1 Fixes** | 10 (66% reduction) |
| **Security Audit Rounds 1-3 (Feb 2026)** | 35 issues identified |
| **Issues Fixed (v0.5.2)** | 35/35 (100%) |
| **Security Audit Round 4 (Feb 2026)** | 24 issues identified (9 critical, 15 high) |
| **Issues Fixed (v0.5.5)** | 24/24 (100%) |
| **Dependabot Alerts (Pre-update)** | 98 |
| **Dependabot Alerts (Post-update v0.5.4)** | 2 (Next.js, requires breaking migration) |
| **Overall Reduction** | **99% of known vulnerabilities resolved** |

---

## Security Audit Summary (v0.5.2)

### Round 1: Critical & High Severity

| # | Issue | Severity | Status |
| --- | ------- | ---------- | -------- |
| 1 | Hardcoded secrets in CI/CD pipelines | CRITICAL | Fixed |
| 2 | JWT tokens not revocable after logout | CRITICAL | Fixed |
| 3 | No account lockout mechanism | CRITICAL | Fixed |
| 4 | Path traversal in report generation | HIGH | Fixed |
| 5 | Missing security headers on dashboard | HIGH | Fixed |
| 6 | CORS wildcard in Next.js config | HIGH | Fixed |
| 7 | PostgreSQL exposed on host network | HIGH | Fixed |
| 8 | No Docker network segmentation | HIGH | Fixed |
| 9 | Unpinned CI/CD action versions | HIGH | Fixed |
| 10 | Bare except clauses (8 instances) | HIGH | Fixed |

### Round 2: Medium Severity

| # | Issue | Severity | Status |
| --- | ------- | ---------- | -------- |
| 11 | No circuit breaker for external APIs | MEDIUM | Fixed |
| 12 | HTTP used for external API calls | MEDIUM | Fixed |
| 13 | Missing DB connection pool health checks | MEDIUM | Fixed |
| 14 | Cookie security settings missing | MEDIUM | Fixed |
| 15 | Race conditions in Stripe webhooks | MEDIUM | Fixed |
| 16-25 | Various code quality and security issues | MEDIUM | Fixed |

### Round 3: Infrastructure & Monitoring

| # | Issue | Severity | Status |
| --- | ------- | ---------- | -------- |
| 26 | No Prometheus alerting rules | MEDIUM | Fixed |
| 27 | Incomplete monitoring coverage | MEDIUM | Fixed |
| 28 | No database backup strategy | MEDIUM | Fixed |
| 29-35 | Additional infrastructure hardening | LOW-MEDIUM | Fixed |

---

## Security Audit Round 4 (v0.5.5)

### Critical Severity (9)

| # | Issue | Status |
| --- | ------- | -------- |
| C1 | Bearer token bypass in data service (grants enterprise/admin) | Fixed |
| C2 | Bearer token bypass in responder service (grants enterprise/admin) | Fixed |
| C3 | 5 unauthenticated endpoints in responder service | Fixed |
| C4 | 14 unauthenticated endpoints in data service | Fixed |
| C5 | Open redirect via unvalidated billing URLs | Fixed |
| C6 | Gateway internal secret not mandatory | Fixed |
| C7 | SSRF in URL security scanner (no private IP filtering) | Fixed |
| C8 | SSRF in header analyzer (no private IP filtering) | Fixed |
| C9 | Docker socket mounted in n8n container | Fixed |

### High Severity (15)

| # | Issue | Status |
| --- | ------- | -------- |
| H1 | Account enumeration via different HTTP status codes | Fixed |
| H2 | /metrics endpoint unauthenticated | Fixed |
| H3 | Health endpoint leaks database error details | Fixed |
| H4 | CORS wildcard with credentials in sensor | Fixed |
| H5 | No queryset filtering for non-admin users in Guardian | Fixed |
| H6 | Flat role check in API key permissions (no hierarchy) | Fixed |
| H7 | has_perm() grants view_all to members | Fixed |
| H8 | No file upload validation in Guardian | Fixed |
| H9 | SSL verification disabled in security tools | Fixed |
| H10 | Agents GET endpoint unauthenticated | Fixed |
| H11 | IOC values unsanitized (prompt injection risk) | Fixed |
| H12 | Sensor mounts full /proc, /sys, docker.sock | Fixed |
| H13 | Ollama CORS wildcard and exposed port | Fixed |
| H14 | Guardian DEBUG=true in Docker Compose | Fixed |
| H15 | N8N_SECURE_COOKIE=false | Fixed |

---

## Dependency Updates (v0.5.4)

### Python Packages Updated

| Package | Previous | Updated | CVEs Resolved |
| --------- | ---------- | --------- | --------------- |
| aiohttp | 3.12.14/3.13.2 | 3.13.3 | 48 (DoS, zip bomb, path leak) |
| cryptography | 44.0.x | 46.0.5 | 10 (subgroup attack, OpenSSL) |
| Django | 4.2.26 | 4.2.28 | 8 (SQL injection, DoS, timing) |
| fastapi-users | 15.0.0 | 15.0.4 | 1 (account takeover) |
| urllib3 | 2.5.0 | 2.6.3 | 3 (decompression bomb) |
| starlette | 0.46.2 | 0.52.1 | 2 (DoS) |
| python-multipart | 0.0.20 | 0.0.22 | 1 (arbitrary file write) |
| Pillow | 11.1.0 | 12.1.1 | 1 (OOB write) |
| nltk | 3.9 | 3.9.2 | 1 (Zip Slip) |
| fastapi | 0.115.x | 0.129.2 | Required for starlette update |

### npm Packages Updated

| Package | Previous | Updated | CVEs Resolved |
| --------- | ---------- | --------- | --------------- |
| axios | ^1.7.0 | ^1.13.5 | 1 (DoS) |
| next | ^14.2.0 | ^14.2.35 | Partial mitigation |
| minimatch | (transitive) | ^10.2.1 (override) | 2 (ReDoS) |
| lodash | (transitive) | ^4.17.22 (override) | 2 (prototype pollution) |
| diff | (transitive) | ^7.0.0 (override) | 1 (DoS) |
| mdast-util-to-hast | (transitive) | ^13.2.1 (override) | 2 (XSS) |

### Remaining Vulnerabilities (2)

| Package | Issue | Severity | Reason |
|---------|-------|----------|--------|
| next.js | DoS via Image Optimizer | HIGH | Requires Next.js 16 (breaking change) |
| next.js | DoS via Server Components | HIGH | Requires Next.js 16 (breaking change) |

**Action**: Next.js 16 migration planned as separate effort.

---

## Security Controls Implemented

### Authentication & Authorization

- JWT token revocation via Redis blacklist with JTI claims
- Account lockout after configurable failed login attempts
- Token blacklist with automatic TTL expiry
- SELECT FOR UPDATE on subscription mutations (prevents TOCTOU)

### Infrastructure Security

- Docker network segmentation: frontend, backend (internal), data (internal)
- PostgreSQL not exposed to host network
- CI/CD secrets via GitHub Secrets (no hardcoded values)
- Pinned CI/CD action versions (Trivy @0.28.0)

### Application Security

- Security headers on Next.js dashboard (CSP, HSTS, X-Frame-Options, etc.)
- CORS restricted to configured origins (no wildcards)
- Path traversal prevention with realpath validation
- HTTP → HTTPS for all external API calls
- Circuit breaker for OpenAI API resilience
- Specific exception handling (no bare except clauses)

### Monitoring & Operations

- Prometheus alert rules for service health, infrastructure, database, security
- PostgreSQL backup script with optional GPG encryption and S3 upload
- Connection pool health checks (pool_pre_ping)
- Cookie security: httpOnly, sameSite=Lax

---

## Verification Checklist

| Check | Status |
| ------- | -------- |
| No eval() calls in source code | PASS |
| No plaintext passwords in code | PASS |
| CORS configured explicitly (no wildcards) | PASS |
| Authentication on all API endpoints | PASS |
| No .env files in git repository | PASS |
| Security headers implemented | PASS |
| API docs disabled in production | PASS |
| JWT tokens revocable | PASS |
| Account lockout enabled | PASS |
| Docker networks segmented | PASS |
| CI/CD secrets externalized | PASS |
| Database not exposed to host | PASS |
| Bare except clauses eliminated | PASS |
| SSRF protection on outbound requests | PASS |
| SSL verification enabled on all tools | PASS |
| File upload validation enforced | PASS |
| No Docker socket mounts | PASS |
| LLM input sanitization | PASS |

---

## Related Documentation

- **[CHANGELOG.md](../../CHANGELOG.md)** - Version history with all security changes
- **[SECURITY.md](../../SECURITY.md)** - Security policy and vulnerability reporting
- **[audit-report.md](audit-report.md)** - Detailed technical audit findings
- **[improvements-summary.md](improvements-summary.md)** - Executive summary of improvements
- **[remediation-checklist.md](remediation-checklist.md)** - Implementation procedures

---

**Last Updated**: February 22, 2026
**Next Review**: Monthly or when upstream patches are available
