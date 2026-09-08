# Changelog

All notable changes to Wildbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2026-09-08

Everything here was found by running the thing. A 20-category audit produced 115
findings, all remediated; then the stack was started for the first time, which
produced a second and larger set of defects that no amount of reading would have
surfaced — services that could not boot, a gateway that could not reach one of
its backends, and an executive dashboard whose headline numbers came from
`random.choice`. The integration suite, which had never really run, now runs
against the full stack and passes. **Several changes are user-facing — read
[UPGRADING.md](UPGRADING.md) before deploying.**

### Upgrade notes

Read [UPGRADING.md](UPGRADING.md); it has the commands. In short:

- **New required secrets.** `CSPM_CREDENTIAL_KEY`, `REDIS_PASSWORD`,
  `FLOWER_PASSWORD`, `GUARDIAN_SECRET_KEY`, `CSPM_SECRET_KEY` and
  `SENSOR_API_KEY` are now required. Without them `docker compose config` fails,
  or the service starts and refuses every request. `make generate-secrets FORCE=1`
  produces them.
- **Rotate `API_KEY`.** The platform key was rendered into dashboard HTML and is
  to be treated as public.
- **Run the migrations.** `identity` and `data` own alembic chains now, and the
  data API migrates at startup instead of calling `create_all()`. Two revisions
  add CHECK constraints and **stop on rows that violate them** — deliberately,
  and they name the offending values and the query that fixes them.
- **Identity's JSON metrics moved** from `GET /metrics` (now the Prometheus text
  exposition, like every other service) to `GET /api/v1/admin/metrics`.
- **Rebuild the images.** All six FastAPI services now resolve to one Starlette
  and one FastAPI; the deployment previously ran three different Starlette
  majors.

### Fixed — the platform could not start

- **`docker compose build` was broken for every Python service.**
  `additional_contexts` pointed at `../open-security-shared`, which compose
  resolves from the project directory, so it escaped the repository. CI was
  unaffected, which is why it went unnoticed.
- **The tools service could not import its own entrypoint.** The shared package
  imported `auth_utils` eagerly, which imports `jose`; services install it with
  `--no-deps` and none pin python-jose. Names resolve lazily now (PEP 562), with
  a test that fails if an eager import returns.
- **The identity service could not boot**: it imports `redis` through
  `token_blacklist` and never pinned it. At the previous release the only
  importer did it inside a function, so it surfaced as a 500 on the first
  authenticated request rather than at boot.
- **The data image shipped no `alembic/` directory**, so the startup migration
  died with `Path doesn't exist: '/app/alembic'`.
- **The sensor image had never built**: `setup.py` opened a `README.md` excluded
  from the build context and fed the hash-pinned lockfile to `install_requires`.
- **The sensor lockfile could not install on Linux.** Compiled on macOS, it
  contained `pyobjc-core`, whose build refuses to run anywhere else.
  `compile_requirements.sh` now resolves for linux, so the same
  `requirements.in` yields the same lock from a laptop and from CI.
- **The gateway crash-looped whenever any upstream was absent.** nginx resolves
  upstream hostnames at load time and treats failure as fatal; the gateway's
  `depends_on` named five of its nine upstreams.
- **A fresh install could not reach `docker compose up`.** `.env.template` and
  `.env.example` had drifted into two different variable sets, with `make setup`
  reading one and `make generate-secrets` the other; the generator replaced only
  empty values, leaving the template's placeholders for the validator to reject;
  and it prompted unconditionally, so the documented setup order aborted on EOF
  and left every secret empty.
- **Generated passwords could contain `$`,** which docker compose interpolates —
  the container received a different, truncated secret than the one in `.env`,
  silently.

### Fixed — services unreachable or wrong

- **Guardian was unreachable through the gateway**, on every route, for every
  client. Django validates `Host` against `ALLOWED_HOSTS` before anything else
  runs; the gateway forwarded the caller's. It now presents guardian its own
  name and forwards the caller's as `X-Forwarded-Host`.
- **The CSPM executive dashboard invented its numbers.** Severity was assigned
  with `random.choice(['critical','high','medium','low'])` — re-rolled on every
  request — and the 30-day trend was synthesized by a formula that always
  improved, for accounts that had never been scanned. Severity now comes from
  the check's own metadata; no scan history means no trend.
- **Three data-service endpoints answered 500.** `from app.schemas.api import *`
  after importing the models shadowed `SensorMetadata` and `TelemetryEvent`, so
  `db.query()` was querying Pydantic classes and telemetry ingest was building
  schema instances that never reached the database.
- **The sensor's local API was inert**: it fails closed without an API key, the
  shipped config had it null, and no environment variable could set it — every
  route but `/health` answered 503.
- **`/api/v1/tools`** (the list of tools) **was not routed**, and
  **`/api/v1/responder/*`** mapped to the responder's root rather than `/v1/`,
  so every documented responder path 404ed.
- **New API keys stored JSON `null` in `scopes`**, satisfying the NOT NULL
  constraint while restoring the ambiguity it was added to remove. Omitted
  scopes now store `["*"]` explicitly.
- **The rate-limit headers described two different budgets**: `Limit` advertised
  the hourly figure while `Remaining` counted against the enforced 60-second
  window, so a client could not compute a backoff.
- **The gateway's development certificate had no `subjectAltName`,** which no
  current TLS client accepts — anything talking to it had to disable
  verification outright.

### Fixed — the tests did not test

- **71 test functions ended in `return passed`.** pytest ignores a return value,
  so all of them passed unconditionally, whatever happened.
- **`asyncio_mode` sat below the `[coverage:*]` sections** of
  `tests/integration/pytest.ini`, so configparser filed it under coverage and
  every async test was skipped as "no async plugin installed".
- **The integration CI job started no gateway.** It ran five services as bare
  processes with `GATEWAY_URL` pointing at a port nothing listened on, so the
  reachability guard skipped every test that goes through the gateway — which is
  most of them. It now brings the real stack up with `docker compose up --wait`.
- **Whole test files targeted endpoints that never existed** and asserted field
  names no schema has. They now use the documented routes, through the gateway,
  over verified TLS, and the suite mints a real API key through the same code
  path a client would use instead of relying on a placeholder the gateway
  rejects.

### Changed

- **The CSPM check catalogue is honest.** 166 generated placeholders that
  declared full metadata while inspecting nothing are deleted; 31 real checks
  remain, all of which call a cloud API. Two of those 31 had never run
  (`gcp/compute` had no `__init__.py`) and four `check_id`s were claimed by two
  checks each, silently shadowing one another. Documentation claiming "200+
  checks" now says 31.
- **`DEP-01` closed**: all six FastAPI services on `starlette==1.6.0` and
  `fastapi==0.141.1`. `pydantic==2.5.0` had been holding cspm and data three
  Starlette majors back.
- **The "Code Quality" CI job gates.** Every step carried
  `continue-on-error: true` and `build-images` did not depend on it. Three tiers
  now block: correctness across the whole tree, full style on the shared
  package, and full style on files a change adds.
- **The SBOM license check does something.** It was `pip install pip-licenses`
  followed by an `echo`, under `continue-on-error`. It now reads the CycloneDX
  SBOM of the built image and fails on copyleft in language packages.
- **The restore drill compares row counts** table by table against the source
  and covers all three databases; it compared table counts and skipped guardian.


## [0.9.0] - 2026-08-03

Truthful security tooling. The headline is a catalog-wide cleanup: every tool that fabricated its results with `random` now either does real work or has been removed. Alongside it, a 360° pre-release audit produced a batch of security fixes — a privilege escalation, leaked-secret purge with CI scanning, real gateway CORS, and more. **Several changes are user-facing — read the upgrade notes.**

### Upgrade notes

- **Fabricated tools are gone or now behave differently.** Fourteen tools used to invent their output with `random`. Nine now perform real analysis (their output shape is unchanged but the data is real, so downstream consumers that keyed on the old fake fields may see different values); five were removed entirely (`compliance_checker`, `security_compliance_checker`, `incident_response_automation`, `threat_hunting_platform`, `social_media_osint`). The tool catalog went from 59 to 54.
- **`database_security_analyzer` now supports PostgreSQL and MySQL/MariaDB only.** It connects for real with the supplied credentials; Oracle, MSSQL and MongoDB return an honest "engine not supported" instead of fabricated findings. Add `PyMySQL`/`pg8000` are bundled.
- **`container_security_scanner` requires Trivy.** It wraps the real scanner (bundled in the tools image, pinned) and returns an honest error if the binary is absent rather than inventing vulnerabilities.
- **Set the gateway CORS allowlist for split-origin deployments.** If the dashboard is served from a different origin than the gateway, add that origin to `$cors_allow_origin` in `open-security-gateway/nginx/nginx.conf`. Same-origin deployments need no change. (Previously the gateway emitted no CORS headers at all, silently breaking login on split-origin setups.)
- **Rotate any credentials ever used with the keys purged from history** (see Security). None were known to be live, but the repo is public.

### Security

- **Privilege escalation on the identity admin endpoints fixed (#323).** Three "admin" user endpoints gated on being OWNER/ADMIN of _any_ team, and registration makes every new user OWNER of a personal team — so any registered account could list all users and deactivate every account, superadmins included. They now require `is_superuser`.
- **Leaked keys purged from HEAD and secret scanning armed in CI (#322).** Three high-entropy credentials had been committed to the public repo; replaced with placeholders and a Gitleaks job added so new secrets fail the build. Compose files no longer degrade to `changeme`/known-password defaults — an incomplete `.env` now fails loudly.
- **Gateway now emits real CORS headers via a secure allowlist (#336).** Credentialed cross-origin requests echo only allowlisted origins (never `*`-with-credentials), with a proper preflight; a comment-only stub had left login broken on split-origin deployments.
- **Five audit fixes (#325):** the responder no longer reports success for containment actions it never ran; one malformed tool no longer crashes the whole tools service; the sensor's local API (which runs osquery) is now authenticated and fails closed; the sensor compose no longer grants host-escape privileges; and the production gateway can actually start (it mounted a non-existent nginx config).
- **Dashboard auth cookie `secure` flag now follows the page protocol (#337)** instead of being hardcoded, so login works on non-HTTPS origins without weakening production (partial fix for the audit's token-handling finding).

### Tools — now real

- **CT log scanner (#326):** queries crt.sh instead of generating certificates with `random`.
- **Email security analyzer (#327):** real SPF/DKIM/DMARC record checks and DNSBL lookups via `dnspython`, replacing random verdicts layered over genuine header parsing.
- **PKI certificate manager (#328):** parses real X.509 certificates and fetches the one a host actually serves over TLS; revocation and CT entries are reported honestly, not invented.
- **Vulnerability DB scanner (#329):** queries OSV.dev and NVD with CVSS computed from the published vector — no more invented CVE ids mixed into real results.
- **WAF bypass tester (#330):** sends real encoded/obfuscated payloads to the target (behind an authorization allowlist) instead of a `hash(payload) % 100` simulation.
- **IoT security scanner (#332):** real TCP discovery and banner grabbing; fields a network scan cannot know (MAC, firmware, default-credential status) are left unset rather than guessed.
- **Container security scanner (#333):** wraps Trivy for real image/Dockerfile scanning.
- **Database security analyzer (#334):** connects to real PostgreSQL/MySQL servers and reports their actual security posture.
- **Security automation orchestrator (#331):** kept (its engine really runs other tools) but made honest — no fabricated metrics or scheduler.

### CI / quality

- **Gateway now has CI coverage (#320, #258):** Lua lint plus a behavioral auth-test harness (25+ assertions incl. anti-spoofing, scope enforcement, proof-of-origin, and CORS) that drives the real gateway.
- **Full-stack E2E harness (#321):** backend-dependent Playwright login flows run against a real identity+gateway+dashboard stack; four redirect-dependent specs are quarantined pending a cross-origin auth follow-up.
- **CI made truthful (#255, #245, #247, #256):** `make test` and the unit-test matrix no longer swallow failures; secret-less fork/dependabot runs get explicit CI-only fallbacks.
- Removed the dead `docker-compose.test.yml` harness (#244) and untracked committed `.pyc` bytecode (#248).

### Privacy

- **Self-hosted ReDoc and fonts (#301, #306)** — no third-party CDN at runtime.
- **`/privacy` notice added and linked** from the footer and previously-orphaned pages (#265, #300); processor list corrected — Cloudflare is not involved (#266).

### Features

- **Entra ID security analyzer (#249):** flags stale accounts and MFA gaps in a Microsoft Entra tenant via the Graph API.
- Unit tests added for the cspm, data, responder and identity services (#250).

### Dependencies

- Security-motivated dependency bumps across the dashboard and website (axios, lodash, node-forge, form-data, brace-expansion, shell-quote, immutable, js-yaml, and others), plus the CI actions group and `black`.

## [0.8.0] - 2026-06-30

Tenancy and RBAC across the backend: downstream services now isolate data by team and enforce the gateway-provided role. **These are behavior changes — read the upgrade notes.** Backward-compatible for existing single-team deployments (pre-existing data has no `team_id` and is treated as global/shared).

### Upgrade notes

- **Set `GATEWAY_INTERNAL_SECRET` everywhere.** Guardian and CSPM now **fail closed** (HTTP `503`) when the secret is unset, matching the other services — they will not serve requests without it. It is also forwarded by the agents service (see below).
- **Members are now read-only in Guardian.** Mutating viewsets require the gateway role `owner`/`admin`; plain members can read but no longer create/update/delete. Configuration mutations elsewhere (e.g. responder playbook reload) also require `owner`/`admin`.
- **Data is team-scoped.** Existing rows without a `team_id` are treated as global and stay visible to everyone; new team-owned data is private. The data service adds nullable `team_id` columns on startup (`create_tables()`); deployments managing the schema externally should add `team_id` to `sources` and `indicators`.
- **AI agent tool calls now run with the requesting user's identity** instead of a zero-team admin key (#175). Ensure `GATEWAY_INTERNAL_SECRET` is set for the agents service so it can forward identity; otherwise it falls back to the (now non-privileged) service key.

### Security

- **Data service** read endpoints are team-scoped: collector/feed records stay global (`team_id` NULL, visible to all), team-owned records are private; reads return global OR own-team. Fixes a cross-tenant disclosure (#178).
- **Responder** run history is owned by the team that started each run; another team gets `404` on read and cancel (#180).
- **CSPM** scans are namespaced per team (no more scanning every team's keys), and its auth now fails closed when `GATEWAY_INTERNAL_SECRET` is unset (it had been missed by the earlier hardening) (#179).
- **Guardian** enforces the gateway role on mutating viewsets and tightens `GatewayUser.has_perm()` so a member can no longer perform admin-only actions at the service layer (#181).
- The legacy `X-API-Key` on the tools service is scoped to a non-privileged `service` identity (no longer a zero-team admin); the agents service forwards the caller's gateway identity on internal calls (#175).
- Configuration mutations require `owner`/`admin` across services; operational and machine-to-machine endpoints stay member-allowed, audited per endpoint (#182).

### Added

- Reusable tenancy helpers `team_or_global_filter` / `scope_query_shared` and a DRF `RequireGatewayRole` permission.
- Two-team cross-tenant and role-enforcement integration/unit tests for data, responder, CSPM and guardian, run in CI (#183).

### Fixed

- CSPM `/dashboard/summary` returned a payload that didn't match its response model and `500`'d for every caller — it now returns the declared fields (#179 follow-up).
- CSPM scan creation `500`'d on a float Redis `SETEX` TTL; the TTL is now an int (#179).

### CI

- The integration harness now runs the data, responder and CSPM services; agents and guardian gained real unit tests (the agents unit-test job previously collected nothing).

## [0.7.1] - 2026-06-30

Shared-library consolidation and the first tenancy isolation, with new CI safety nets. Backward-compatible for existing single-team deployments.

### Security

- Data service read endpoints are now team-scoped (#178). Model: shared feeds + per-team overlay — collector/feed records stay global (`team_id` NULL, visible to all teams) and team-owned records are private; reads return global OR own-team. Fixes a cross-tenant disclosure where every team's indicators/sources were returned. Existing data (no `team_id`) is treated as global, so behavior is unchanged for single-team setups.

### Changed

- Gateway authentication is consolidated onto the shared `open_security_shared.gateway_auth` dependency across tools/agents/data/responder (#173, #174); the per-service `auth.py` duplicates and `sys.path`/`try-except` import shims were removed (~520 LOC). Also forwards `X-Gateway-Secret` correctly so the proof-of-origin is always enforced.

### Added

- `open-security-shared` is now a real installable package (`pyproject.toml`), installed into every service image via a BuildKit additional context (#172).
- Reusable tenancy helpers in `open_security_shared.tenancy` — `team_filter`, `scope_query`, `team_or_global_filter`, `scope_query_shared` (#177).

### CI

- Build every service image (build-only) on pull requests so Docker/build changes are validated before merge (#229).
- Run the data service in the integration harness, in its own venv against the test database (#233).

### Documentation

- Document the canonical service layout (identity reference) in CONTRIBUTING (#176).

## [0.7.0] - 2026-06-29

Security hardening, first-run honesty, and a documentation/site overhaul. Some changes affect existing deployments — see **Security** and **Changed**.

### Security

- Gateway authentication now **fails closed**: the shared dependency, the per-service `auth.py` wrappers, and the Guardian middleware refuse to trust `X-Wildbox-*` identity headers and return `503` when `GATEWAY_INTERNAL_SECRET` is unset, instead of warning and trusting potentially-forged headers (#163).
- Backend service ports are now bound to `127.0.0.1`; only the gateway is published publicly (#164).
- The central tools SSRF guard now also inspects `file_url`, `app_url`, and `download_url`, closing the bypass in `metadata_extractor` and `mobile_security_analyzer` (#165).

### Added

- Dashboard error handling: branded `error.tsx`, `not-found.tsx`, and a top-level `global-error.tsx` boundary, so a render throw no longer white-screens the app (#166).
- `make generate-secrets` and `make validate-secrets` targets wrapping the existing scripts (#170).

### Fixed

- CSPM: unimplemented placeholder checks now report `NOT_IMPLEMENTED` instead of `PASSED`, and the compliance score counts only checks that actually ran — removing a false compliance signal (#158).
- Data, Guardian and Responder boot: `DATABASE_URL` falls back to the shared value when the per-service variable is unset, so the documented stack no longer crashes on start (#170).

### Changed

- AI analysis standardizes on `ANTHROPIC_*`; leftover OpenAI/Stripe configuration was removed from the env templates (setting the old key made AI analysis silently no-op) (#169).
- Dashboard header: the static "3" notification badge, the always-green "All Systems Operational" pill, and the non-functional global search are hidden until backed by real data (#168).

### Removed

- Dead dashboard navigation links (`/ai-analyst`, `/auth/forgot-password`, `/terms`, `/privacy`) and the hardcoded `mockRuns` fallback, replaced with real empty/error states (#167).
- A committed status-report document that read as churn in a public repo (#160).

### Documentation

- Redesigned the GitHub Pages site under `docs/`: removed AI-"slop" theming, fixed the broken landing-page markup and logo, and made the copy honest (#210).
- Documentation Quality CI is fully green for the first time: Markdown Linting passes repo-wide, alongside Spell Check and Link Validation (#211).
- Reconciled README, SETUP_GUIDE and the quickstart to one source of truth — `INITIAL_ADMIN_*` credentials, the real `/auth/jwt/login` endpoint, correct Compose service names, and `make` / `docker compose` commands (#171).

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

[Unreleased]: https://github.com/fabriziosalmi/wildbox/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/fabriziosalmi/wildbox/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/fabriziosalmi/wildbox/compare/v0.5.5...v0.6.2
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
