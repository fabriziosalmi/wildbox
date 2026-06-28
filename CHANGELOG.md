# Changelog

All notable changes to Wildbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2] - 2026-06-28

### Changed
- Documentation-quality CI: run link checking on Node 22 (Node 18 broke on the now-ESM `marked`), expand the cspell dictionary, and fix the empty-alt examples so the Spell Check, Link Validation, and Image Alt Text gates pass.

### Removed
- Stopped tracking generated artifacts (`.coverage`, `tests/reports/junit.xml`, Playwright `test-results/`).
- Removed committed status-report docs (`*_COMPLETE.md`, `*_IN_PROGRESS.md`, …) and one-off migration scripts.

### Fixed
- Removed a hardcoded developer path from the tool audit/integration scripts so they run on any checkout.
- Fixed the dead YouTube thumbnail link in the README (`maxresdefault` → `hqdefault`).

## [0.5.5] - 2026-02-22

### Security
- Removed Bearer token bypass in data and responder services (granted enterprise/admin to any token)
- Added authentication to 19 previously unauthenticated endpoints across data, responder, and agents services
- Added SSRF protection (private IP filtering) to URL scanner and header analyzer tools
- Added redirect URL validation in billing checkout to prevent open redirects
- Made gateway internal secret mandatory (no longer falls back to accepting all requests)
- Fixed account enumeration via different HTTP status codes on login
- Protected /metrics endpoint with gateway secret authentication
- Removed detailed database error info from /health endpoint responses
- Replaced CORS wildcard with localhost-only in sensor service
- Added asset-based queryset filtering for non-admin users in Guardian
- Fixed role hierarchy in API key permission checks (OWNER > ADMIN > MEMBER)
- Fixed has_perm() to deny view_all permissions for member role
- Added file upload validation (type whitelist + 10MB size limit) in Guardian
- Enabled SSL verification in security tools (removed ssl=False and CERT_NONE)
- Sanitized IOC values to mitigate prompt injection in threat enrichment agent
- Removed Docker socket mount from n8n container
- Restricted sensor host volume mounts to specific safe paths
- Restricted Ollama CORS origins and removed host port exposure
- Set Guardian DEBUG=false by default in Docker Compose
- Enabled N8N_SECURE_COOKIE in Docker Compose

## [0.5.4] - 2026-02-22

### Security
- Updated aiohttp 3.12.x/3.13.2 → 3.13.3 across 6 services (fixes 8 CVEs: DoS, zip bomb, path leak)
- Updated cryptography 44.0.x → 46.0.5 across 7 services (subgroup attack + OpenSSL vulnerability)
- Updated Django 4.2.26 → 4.2.28 (SQL injection + DoS + timing attack)
- Updated Pillow 11.1.0 → 12.1.1 (out-of-bounds write on PSD images)
- Updated nltk 3.9 → 3.9.2 (Zip Slip vulnerability)
- Updated python-multipart 0.0.20 → 0.0.22 (arbitrary file write)
- Updated urllib3 2.5.0 → 2.6.3 (decompression bomb bypass)
- Updated starlette 0.46.2 → 0.52.1 (DoS via Range header + multipart)
- Updated fastapi 0.115.x → 0.129.2 (to support patched starlette)
- Updated fastapi-users → 15.0.4 (1-click account takeover fix)
- Updated axios ^1.7.0 → ^1.13.5 (DoS via `__proto__`)
- Updated next ^14.2.0 → ^14.2.35 (DoS mitigations)
- Added npm overrides for minimatch, lodash, diff, mdast-util-to-hast
- Resolves ~96 of 98 Dependabot alerts

## [0.5.2] - 2026-02-22

### Security
- Added JWT token revocation via Redis blacklist with JTI claims
- Implemented account lockout after failed login attempts
- Added Docker network segmentation (frontend/backend/data layers)
- Fixed path traversal vulnerability in report generation
- Added security headers (CSP, HSTS, X-Frame-Options) to Next.js dashboard
- Replaced hardcoded CI secrets with GitHub Secrets references
- Pinned Trivy action to specific version (0.28.0) in CI/CD
- Added PostgreSQL connection pool health checks (pool_pre_ping)
- Added cookie security settings (httpOnly, sameSite) to Guardian service
- Fixed TOCTOU race conditions in Stripe webhook handlers (SELECT FOR UPDATE)
- Added Prometheus alert rules for service health monitoring
- Migrated external API calls from HTTP to HTTPS
- Added circuit breaker for OpenAI API resilience
- Replaced all bare except clauses with specific exception types
- Removed PostgreSQL port exposure in development docker-compose

### Added
- `open-security-identity/app/token_blacklist.py` - Redis-based token blacklist and account lockout
- `open-security-sensor/monitoring/alert_rules.yml` - Prometheus alerting rules
- `scripts/backup_postgres.sh` - PostgreSQL backup script with encryption

### Removed
- `.env-e` sed artifact removed from repository

## [0.5.0] - 2026-02-22

### Security
- Comprehensive security hardening across all microservices

### Fixed
- Pydantic v2 type annotation error in CSPM config
- Test suite failures: missing services and insufficient timeouts in CI

### Changed
- Enhanced integration tests for Identity Service authentication flow

## [0.4.0] - 2026-02-22

### Added
- 8 FAANG-level architectural patterns implementation
- Comprehensive documentation quality framework
- Spell check dictionary (100 terms)

### Changed
- Critical code quality remediation: removed test skips, fixed tests, extracted components
- Documentation quality improvements (phases 1 and 2, issues 1-35)
- Documentation quality audit completion report
- Removed self-congratulatory progress reports from repository root

### Documentation
- Replaced "blacklist/whitelist" with "denylist/allowlist" across documentation
- Replaced "JWT blacklisting" with "JWT denylisting" in architecture docs
- Added descriptive alt text to images for accessibility
- Fixed broken documentation links (QUICKSTART.md → SETUP_GUIDE.md)
- Defined acronyms on first use in README (RBAC, JWT, CSPM, SOAR, LLM, CVE)

## [0.3.2] - 2025-11-24

### Added
- Comprehensive documentation improvements following best practices
- Table of Contents in long documentation files
- Explicit environment variable documentation in `.env.example`
- Clearer vulnerability reporting process in SECURITY.md
- Quick Start section in README.md
- Architecture decision documentation
- Troubleshooting section expansions

### Changed
- Replaced "Simply" and "Just" with direct instructions (removed condescending language)
- Replaced "master/slave" with "main/replica" terminology
- Replaced "sanity check" with "validity check" terminology
- Replaced "guys" with "team/everyone" for inclusive language
- Updated code examples with proper syntax highlighting
- Improved error messages to be more user-friendly
- Standardized date formats to ISO 8601 (YYYY-MM-DD)
- Enhanced CONTRIBUTING.md with clearer dev environment setup
- Updated API documentation with explicit return types

### Fixed
- Removed hardcoded API keys from example code (replaced with clear placeholders)
- Removed TODO placeholders from production documentation
- Fixed broken hyperlinks throughout documentation
- Corrected grammar in success messages
- Standardized header capitalization across documentation
- Fixed whitespace in Markdown tables

### Security
- Removed real-looking secrets from code examples
- Added explicit security warnings for production deployments
- Clarified authentication flow documentation

## [0.3.1] - 2025-11-24

### Fixed
- Corrected integration tests to use fastapi-users JWT endpoints (`/api/v1/auth/jwt/login`)
- Fixed endpoint path mismatches causing 404 errors in CI/CD
- Added appropriate test skips for unavailable services in test environment

### Changed
- Improved CI/CD pipeline stability and reliability
- Integration tests now validate actual API behavior when endpoints exist
- Tests gracefully handle test environment limitations

## [0.3.0] - 2025-11-23

### Added
- Comprehensive integration test suite
- E2E Playwright tests for frontend
- Security validation tests
- Performance monitoring tests

### Changed
- Updated test infrastructure with docker-compose.test.yml
- Enhanced test fixtures and utilities

## [0.2.0] - 2025-11-16

### Added
- Security Tools Service with 55+ production-ready tools
- Dual-mode authentication (API Key + Bearer Token)
- Gateway-level authentication via OpenResty Lua
- Redis integration for caching
- Health check system
- Next.js 14 dashboard with App Router
- WebSocket support for real-time updates

### Changed
- Optimized FastAPI performance with async/await
- Enhanced Django admin for Guardian service
- Improved error handling across all APIs
- Frontend bundle optimization with code splitting

### Fixed
- PostgreSQL password inconsistencies
- CORS issues in data service
- Gateway routing for direct service access
- Authentication header forwarding
- Redis connection pooling issues

### Performance
- 30% faster gateway authentication validation
- Optimized database queries (eliminated N+1 patterns)
- 60% reduced database load via Redis caching
- 20% average API response time improvement

## [0.1.0] - 2025-11-01

### Added
- Initial release
- Core microservices architecture
- Identity management with RBAC
- Basic API gateway
- PostgreSQL database layer
- Docker Compose orchestration
- Dashboard UI with Next.js

[Unreleased]: https://github.com/fabriziosalmi/wildbox/compare/v0.5.5...HEAD
[0.5.5]: https://github.com/fabriziosalmi/wildbox/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/fabriziosalmi/wildbox/compare/v0.5.2...v0.5.4
[0.5.2]: https://github.com/fabriziosalmi/wildbox/compare/v0.5.0...v0.5.2
[0.5.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/fabriziosalmi/wildbox/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/fabriziosalmi/wildbox/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fabriziosalmi/wildbox/releases/tag/v0.1.0
