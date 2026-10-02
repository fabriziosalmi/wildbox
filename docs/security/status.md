# Wildbox Security Status

What is known about Wildbox's security today, including what is still wrong.
This page replaces an earlier report that marked every audit finding "Fixed"
and every check "PASS"; several of those claims did not hold when they were
checked against the code.

**Current release**: v0.10.0. Changes since then are listed under
"Unreleased" in [CHANGELOG.md](https://github.com/fabriziosalmi/wildbox/blob/main/CHANGELOG.md).  
**Checked against**: `main` on 2 October 2026. Each check below names how it
was made, so it can be repeated.

To report a vulnerability, follow
[SECURITY.md](https://github.com/fabriziosalmi/wildbox/blob/main/SECURITY.md);
do not open a public issue.

---

## Known Open Issues

| Issue | Where | Notes |
| --- | --- | --- |
| Vulnerable dependencies | dashboard (npm), four unlocked Python requirement files | The hash-pinned locks of all eight Python services have no known advisory (pip-audit, 2 October 2026; [#415](https://github.com/fabriziosalmi/wildbox/issues/415) closed). Still open: about 60 npm alerts in `open-security-dashboard`, and 15 pip alerts in requirement files outside the lock system (`open-security-cspm/requirements-dev.txt`, `open-security-guardian/requirements-dev.txt`, `open-security-tools/requirements-secure.txt`, `tests/requirements.txt`). The `Main Advisories` workflow reports critical advisories on `main` daily. |
| API schema served regardless of environment | tools | tools always serves `/openapi.json` (its own documentation pages use it). It is reachable only on its `127.0.0.1` port, not through the gateway. identity, agents, responder and cspm disable docs, redoc and the schema in production ([#496](https://github.com/fabriziosalmi/wildbox/issues/496)). |

---

## Verification Checks

Re-run on `main` on 2 October 2026. "Not verified" means nobody has checked
the claim against the current code; it is not a pass.

| Check | Result | How it was checked |
| --- | --- | --- |
| No `eval()` in service code | PASS | `grep` for `eval(` in `open-security-*/**/*.py`, outside tests: only string literals in blocklists |
| No plaintext passwords in code or logs | PASS | The initial administrator password is no longer printed ([#493](https://github.com/fabriziosalmi/wildbox/issues/493)). No password literal is used as a default: `docker-compose.yml` refuses to start without the required secrets |
| No `.env` file in git | PASS | `git ls-files` finds only `.env.example` and `.env.template` files, which hold placeholders |
| Database and Redis not published to the host | PASS | Neither `postgres` nor `wildbox-redis` has `ports:` in `docker-compose.yml`; backends bind to `127.0.0.1` |
| Docker networks segmented | PASS | In the production configuration (`docker-compose.yml` + `docker-compose.prod.yml`, Compose 2.24.4+) each service's networks are replaced with `!override` rather than merged with the flat `wildbox` network ([#494](https://github.com/fabriziosalmi/wildbox/issues/494)). The `Production Stack` workflow checks the rendered map service by service, starts the stack, runs the integration suite against it, and probes from inside the containers with `scripts/check_network_segmentation.py`: the dashboard cannot resolve PostgreSQL, Redis or any backend service, the gateway cannot resolve PostgreSQL or Redis, the data network has no route out, and every connection a service needs succeeds. The development stack (`docker-compose.yml` alone) stays on one flat network |
| Gateway requires authentication on service APIs | PASS | Every `/api/v1/<service>/` location in `wildbox_gateway.conf` calls `auth_handler.authenticate()`; identity validates tokens itself |
| Every API endpoint enforces authentication | Not verified | Not checked endpoint by endpoint behind the gateway |
| JWT tokens revocable | PASS | `POST /auth/logout` and `POST /auth/jwt/logout` blacklist the token's `jti` in Redis; the gateway and identity's own routes refuse it (`logout.py`, `user_manager.py`) |
| Account lockout after failed logins | PASS | After 5 failed password logins an account, registered or not, is refused with 429 for 15 minutes, whatever the password; a successful login clears the counter ([#509](https://github.com/fabriziosalmi/wildbox/issues/509)). Tested in `tests/integration/test_login_lockout.py` |
| CORS without wildcards | PASS | No `allow_origins=["*"]` or wildcard `Access-Control-Allow-Origin` in service code or gateway config |
| Security headers at the gateway | PASS | HSTS, `X-Frame-Options`, `X-Content-Type-Options` and `Permissions-Policy` set in `wildbox_gateway.conf` |
| API docs disabled in production | **FAIL** | identity, agents, responder and cspm: disabled. tools still serves `/openapi.json`; see "API schema served regardless of environment" above |
| No bare `except:` | PASS, one exception | Only `open-security-responder/demo_final.py`, a demo script |
| TLS verification enabled in all tools | PASS | Scanners verify certificates by default and report a failed verification instead of falling back; accepting an invalid certificate needs `verify_ssl: false` on that scan. The three certificate analyzers keep an unverified handshake to read broken certificates and report an untrusted one as a finding ([#495](https://github.com/fabriziosalmi/wildbox/issues/495)) |
| No Docker socket mounts | PASS | No `docker.sock` in any Compose file |
| SSRF protection on outbound requests | Not verified | |
| File upload validation | Not verified | |
| LLM input sanitization | Not verified | |
| CI secrets externalized | Not verified | `secret-scan.yml` runs on every PR; the workflows were not reviewed one by one |

---

## History

The November 2024 platform audit (its report, remediation checklist and
improvements summary) is no longer published: it described code that has since
changed, and its findings are superseded by this page. The
[Tools service audit](tools-service-audit.md) (November 2025) is kept for
reference, with the same caveat.

The audit rounds of February 2026 (v0.5.2 to v0.5.5) and every later security
change are recorded release by release in
[CHANGELOG.md](https://github.com/fabriziosalmi/wildbox/blob/main/CHANGELOG.md).
