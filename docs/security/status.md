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
| Network segmentation is not effective | `docker-compose.yml`, `docker-compose.prod.yml` | The production overlay defines `frontend`, `backend` and `data` networks, but Compose merges service networks with the base file, so every service also stays on the flat `wildbox` network. With both files, `docker compose config` shows the dashboard and the gateway on the same network as PostgreSQL and Redis. |
| Failed logins are not locked out | `open-security-identity/app/token_blacklist.py` | `config.py` sets 5 attempts and 15 minutes, and `record_failed_login` / `is_account_locked` exist, but no login route calls them. The only brake is the gateway's rate limit on `/auth/jwt/` (5 requests per second per address, burst 3). |
| API documentation served regardless of environment | identity, tools | identity always serves `/docs` and `/redoc`; tools always serves `/openapi.json`. Both are reachable only on their `127.0.0.1` ports, not through the gateway. agents, responder and cspm disable theirs in production. |

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
| Docker networks segmented | **FAIL** | See "Network segmentation is not effective" above |
| Gateway requires authentication on service APIs | PASS | Every `/api/v1/<service>/` location in `wildbox_gateway.conf` calls `auth_handler.authenticate()`; identity validates tokens itself |
| Every API endpoint enforces authentication | Not verified | Not checked endpoint by endpoint behind the gateway |
| JWT tokens revocable | PASS | `POST /auth/logout` and `POST /auth/jwt/logout` blacklist the token's `jti` in Redis; the gateway and identity's own routes refuse it (`logout.py`, `user_manager.py`) |
| Account lockout after failed logins | **FAIL** | See "Failed logins are not locked out" above |
| CORS without wildcards | PASS | No `allow_origins=["*"]` or wildcard `Access-Control-Allow-Origin` in service code or gateway config |
| Security headers at the gateway | PASS | HSTS, `X-Frame-Options`, `X-Content-Type-Options` and `Permissions-Policy` set in `wildbox_gateway.conf` |
| API docs disabled in production | **FAIL** | See "API documentation served regardless of environment" above |
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
