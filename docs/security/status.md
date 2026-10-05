# Wildbox Security Status

What is known about Wildbox's security today, including what is still wrong.
This page replaces an earlier report that marked every audit finding "Fixed"
and every check "PASS"; several of those claims did not hold when they were
checked against the code.

**Current release**: v0.11.2. Its changes, and those of every earlier
release, are listed in [CHANGELOG.md](https://github.com/fabriziosalmi/wildbox/blob/main/CHANGELOG.md).  
**Checked against**: `main` on 4 October 2026. Each check below names how it
was made, so it can be repeated.

To report a vulnerability, follow
[SECURITY.md](https://github.com/fabriziosalmi/wildbox/blob/main/SECURITY.md);
do not open a public issue.

---

## Known Open Issues

| Issue | Where | Notes |
| --- | --- | --- |
| API schema served regardless of environment | tools, data | tools serves `/openapi.json` in every environment, although it no longer has documentation pages that use it: its docs and redoc pages were removed with its standalone web UI ([#581](https://github.com/fabriziosalmi/wildbox/issues/581)). data serves its docs and redoc pages in development only, but does not set `openapi_url`, so FastAPI's default `/openapi.json` stays on in every environment. Both are reachable only on their `127.0.0.1` ports, not through the gateway, which maps no client path to either schema. identity, agents, responder and cspm disable docs, redoc and the schema in production ([#496](https://github.com/fabriziosalmi/wildbox/issues/496)). |
| Unauthenticated system endpoints | tools | `/api/system/info`, `/api/system/metrics`, `/api/system/operational-metrics` and `/api/system/health-aggregate` declare no authentication and disclose the environment, the tool inventory, execution statistics and the internal URLs of the services. The gateway does not route them, so they are reachable only on the internal network and on `127.0.0.1:8000` ([#646](https://github.com/fabriziosalmi/wildbox/issues/646)). |
| API-key scopes enforced at the gateway only | gateway, all backends | The gateway refuses a key that lacks the scope a route needs, but forwards only the user, team and role, so no backend can check scopes itself. This is not exploitable through the gateway, and the backends that require `X-Gateway-Secret` cannot be reached any other way; but a gateway route added without `authenticate()`, or a mistake in the scope map, would not be caught ([#637](https://github.com/fabriziosalmi/wildbox/issues/637)). One such mistake is open: `GET /api/v1/tools` requires the generic `read` scope, so a `tools:read` key is refused there and a `read` key can list the tools ([#647](https://github.com/fabriziosalmi/wildbox/issues/647)). |
| Rate-limit settings that change nothing | tools, guardian | tools never enforces `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW` ([#646](https://github.com/fabriziosalmi/wildbox/issues/646)). `docker-compose.yml` does not pass `API_RATE_LIMIT` to guardian, which always runs at its built-in rates ([#645](https://github.com/fabriziosalmi/wildbox/issues/645)). The gateway's own limits apply in both cases. |
| Unpinned pip in four images | cspm, guardian, responder, tools | These Dockerfiles run `pip install --upgrade pip` before the hash-checked install, so the installer itself is whatever PyPI serves at build time, without a hash ([#657](https://github.com/fabriziosalmi/wildbox/issues/657)). |
| Advisory without a fix in the dashboard's build tooling | dashboard | `npm audit` reports [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) (high, published 18 September 2026, no patched release) in `braces`, reached only through `eslint-config-next` since the move to Tailwind CSS 4 in v0.11.1. It is lint tooling and does not reach the built image. No issue is open for it yet. |

---

## Verification Checks

Re-run on `main` on 4 October 2026. "Not verified" means nobody has checked
the claim against the current code; it is not a pass.

| Check | Result | How it was checked |
| --- | --- | --- |
| No `eval()` in service code | PASS | `grep` for `eval(` in `open-security-*/**/*.py`, outside tests: only string literals in blocklists |
| No plaintext passwords in code or logs | PASS | The initial administrator password is no longer printed ([#493](https://github.com/fabriziosalmi/wildbox/issues/493)). No password literal is used as a default: `docker-compose.yml` refuses to start without the required secrets |
| No known vulnerable dependencies | **FAIL**, one advisory without a fix | GitHub reports 0 open Dependabot alerts (API, 4 October 2026). pip-audit (`--no-deps --disable-pip`, 4 October 2026) finds no advisory in the hash-pinned locks of the eight Python services ([#415](https://github.com/fabriziosalmi/wildbox/issues/415)). `npm audit` finds one advisory in the dashboard's build tooling; see "Advisory without a fix in the dashboard's build tooling" above. The `Main Advisories` workflow re-checks `main` daily with Trivy, for critical advisories that have a released fix |
| No `.env` file in git | PASS | `git ls-files` finds only `.env.example` and `.env.template` files, which hold placeholders |
| Database and Redis not published to the host | PASS | Neither `postgres` nor `wildbox-redis` has `ports:` in `docker-compose.yml`; backends bind to `127.0.0.1` |
| Docker networks segmented | PASS | In the production configuration (`docker-compose.yml` + `docker-compose.prod.yml`, Compose 2.24.4+) each service's networks are replaced with `!override` rather than merged with the flat `wildbox` network ([#494](https://github.com/fabriziosalmi/wildbox/issues/494)). The `Production Stack` workflow checks the rendered map service by service, starts the stack, runs the integration suite against it, and probes from inside the containers with `scripts/check_network_segmentation.py`: the dashboard cannot resolve PostgreSQL, Redis or any backend service, the gateway cannot resolve PostgreSQL or Redis, the data network has no route out, and every connection a service needs succeeds. The development stack (`docker-compose.yml` alone) stays on one flat network |
| Gateway requires authentication on service APIs | PASS | Every `/api/v1/<service>/` location in `wildbox_gateway.conf` calls `auth_handler.authenticate()`; identity validates tokens itself |
| Gateway secret sent only for authenticated callers | PASS | `proxy_params.conf` sends `X-Gateway-Secret` from `$wildbox_gateway_secret`, which the server block seeds empty and only `authenticate()` fills in (`auth_handler.lua`). The identity passthrough and the dashboard forward no secret and drop a client's own ([#664](https://github.com/fabriziosalmi/wildbox/issues/664)). Tested in `open-security-gateway/test/ci_auth_tests.sh` and `tests/integration/test_identity_access_scope.py` |
| Identity admin metrics restricted to superusers | PASS | `GET /api/v1/admin/metrics` authenticates the bearer token and requires `is_superuser`; the gateway secret alone no longer opens it ([#664](https://github.com/fabriziosalmi/wildbox/issues/664)). Tested anonymously, with a forged and with the real secret, as a team owner and as a superuser in `open-security-identity/tests/unit/test_admin_metrics_access.py` and `tests/integration/test_identity_access_scope.py` |
| Each team reaches only its own data | PASS for guardian, data, responder and cspm | guardian scopes its models, routes and Celery tasks to the caller's team ([#642](https://github.com/fabriziosalmi/wildbox/issues/642)); data stores and serves sensor telemetry per team ([#641](https://github.com/fabriziosalmi/wildbox/issues/641)). The integration suite registers two accounts and checks each service through the gateway: `test_guardian_tenancy.py`, `test_data_tenancy.py`, `test_data_cross_tenant.py`, `test_telemetry_tenancy.py`, `test_responder_tenancy.py` and `test_cspm_tenancy.py` all passed on `main` (Integration Tests, commit `bcbc569f`) |
| Guardian's answers name no internal host | PASS | The `next` and `previous` links of a paginated list are relative references under the gateway's `/api/v1/guardian/` path, with no scheme and no host; they were absolute URLs on `open-security-guardian`, the Host the gateway presents guardian ([#643](https://github.com/fabriziosalmi/wildbox/issues/643)). The path comes from `X-Forwarded-Prefix`, a literal in the gateway's guardian location that replaces a client's own; guardian reads no host header for a link. `tests/integration/test_guardian_pagination_links.py` follows the links through the gateway, with and without forged `X-Forwarded-*`, `Forwarded`, `SCRIPT_NAME` and `Host` headers; `open-security-guardian/tests/unit/test_gateway_links.py` checks the header against the gateway configuration |
| Self-service API-key routes reach the caller's keys only | PASS | The self-service routes match the caller's user ID as well as the team, so a member cannot read or revoke a teammate's key; a team owner or admin revokes through the team route ([#664](https://github.com/fabriziosalmi/wildbox/issues/664)). Tested in `tests/integration/test_identity_access_scope.py` and `test_api_key_revocation.py` |
| API keys stored as keyed digests | PASS | identity stores an HMAC of each key, keyed with `API_KEY_HASH_SECRET` (`app/auth.py`). `docker-compose.yml` and `docker-compose.prod.yml` refuse to start without it, and identity refuses to start in production without it ([#648](https://github.com/fabriziosalmi/wildbox/issues/648)). Tested in `open-security-identity/tests/unit/test_api_key_hash_secret.py` |
| Agent tasks reachable by their owner only | PASS | Reading or cancelling an analysis fails closed: a missing owner record or another user's task answers 404. The analyze rate limit is keyed by the verified gateway user, with an optional per-team ceiling, instead of the gateway's address ([#650](https://github.com/fabriziosalmi/wildbox/issues/650), [#651](https://github.com/fabriziosalmi/wildbox/issues/651)). Tested in `open-security-agents/tests/unit/test_task_ownership.py` and `test_analyze_rate_limit.py` |
| Every API endpoint enforces authentication | Not verified | Not checked endpoint by endpoint behind the gateway |
| JWT tokens revocable | PASS | `POST /auth/logout` and `POST /auth/jwt/logout` blacklist the token's `jti` in Redis; the gateway and identity's own routes refuse it (`logout.py`, `user_manager.py`) |
| Account lockout after failed logins | PASS | After 5 failed password logins an account, registered or not, is refused with 429 for 15 minutes, whatever the password; a successful login clears the counter ([#509](https://github.com/fabriziosalmi/wildbox/issues/509)). Tested in `tests/integration/test_login_lockout.py` |
| CORS without wildcards | PASS | No `allow_origins=["*"]` or wildcard `Access-Control-Allow-Origin` in service code or gateway config |
| Security headers at the gateway | PASS | HSTS, `X-Frame-Options`, `X-Content-Type-Options` and `Permissions-Policy` set in `wildbox_gateway.conf` |
| API docs disabled in production | **FAIL** | identity, agents, responder and cspm: disabled. tools and data still serve `/openapi.json`; see "API schema served regardless of environment" above |
| No bare `except:` | PASS, one exception | Only `open-security-responder/demo_final.py`, a demo script |
| TLS verification enabled in all tools | PASS | Scanners verify certificates by default and report a failed verification instead of falling back; accepting an invalid certificate needs `verify_ssl: false` on that scan. The three certificate analyzers keep an unverified handshake to read broken certificates and report an untrusted one as a finding ([#495](https://github.com/fabriziosalmi/wildbox/issues/495)) |
| No Docker socket mounts | PASS for the platform stack | No `docker.sock` in `docker-compose.yml`, `docker-compose.prod.yml` or the sensor's Compose files. `open-security-gateway/docker-compose.dev.yml`, a standalone development file, mounts it read-only into a `logspout` log viewer; `:ro` restricts the file, not the Docker API |
| Development reloader off in production | PASS | identity's `scripts/init.sh` passes `--reload` to uvicorn only when `ENVIRONMENT` is `development` ([#664](https://github.com/fabriziosalmi/wildbox/issues/664)). Tested in `tests/scripts/test_identity_init_reload.py` |
| SSRF protection on outbound requests | Not verified | |
| File upload validation | Not verified | |
| LLM input sanitization | Not verified | |
| CI secrets externalized | Not verified | `secret-scan.yml` runs on every PR; the workflows were not reviewed one by one |

---

## History

The November 2024 platform audit (its report, remediation checklist and
improvements summary) is no longer published: it described code that has since
changed, and its findings are superseded by this page. The tools service
audit of November 2025 is not published either, for the same reason; it is
kept in the repository as
[docs/security/tools-service-audit.md](https://github.com/fabriziosalmi/wildbox/blob/main/docs/security/tools-service-audit.md).

The audit rounds of February 2026 (v0.5.2 to v0.5.5) and every later security
change are recorded release by release in
[CHANGELOG.md](https://github.com/fabriziosalmi/wildbox/blob/main/CHANGELOG.md).
