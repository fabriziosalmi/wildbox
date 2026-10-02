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
| Vulnerable dependencies | all services | Tracked in [#415](https://github.com/fabriziosalmi/wildbox/issues/415). On 2 October 2026 Dependabot listed about 180 open alerts (none critical, 85 high) and code scanning about 190 (Trivy and CodeQL). The `Main Advisories` workflow keeps an issue with the current list of advisories on `main`. |
| Network segmentation is not effective | `docker-compose.yml`, `docker-compose.prod.yml` | The production overlay defines `frontend`, `backend` and `data` networks, but Compose merges service networks with the base file, so every service also stays on the flat `wildbox` network. With both files, `docker compose config` shows the dashboard and the gateway on the same network as PostgreSQL and Redis. |
| Initial admin password written to the log | `open-security-identity/scripts/init.sh` | When the identity service creates the first administrator it prints the password from `INITIAL_ADMIN_PASSWORD` to the container log. Change that password after the first login and treat container logs as sensitive. |
| TLS verification disabled in two scanners | `open-security-tools/app/tools/web_vuln_scanner/main.py`, `open-security-tools/app/tools/cookie_scanner/main.py` | Both create `aiohttp.TCPConnector(ssl=False)`, so they accept any certificate from the target. |
| API documentation served regardless of environment | identity, tools | identity always serves `/docs` and `/redoc`; tools always serves `/openapi.json`. Both are reachable only on their `127.0.0.1` ports, not through the gateway. agents, responder and cspm disable theirs in production. |

---

## Verification Checks

Re-run on `main` on 2 October 2026. "Not verified" means nobody has checked
the claim against the current code; it is not a pass.

| Check | Result | How it was checked |
| --- | --- | --- |
| No `eval()` in service code | PASS | `grep` for `eval(` in `open-security-*/**/*.py`, outside tests: only string literals in blocklists |
| No plaintext passwords in code or logs | **FAIL** | See "Initial admin password written to the log" above. No password literal is used as a default: `docker-compose.yml` refuses to start without the required secrets |
| No `.env` file in git | PASS | `git ls-files` finds only `.env.example` and `.env.template` files, which hold placeholders |
| Database and Redis not published to the host | PASS | Neither `postgres` nor `wildbox-redis` has `ports:` in `docker-compose.yml`; backends bind to `127.0.0.1` |
| Docker networks segmented | **FAIL** | See "Network segmentation is not effective" above |
| Gateway requires authentication on service APIs | PASS | Every `/api/v1/<service>/` location in `wildbox_gateway.conf` calls `auth_handler.authenticate()`; identity validates tokens itself |
| Every API endpoint enforces authentication | Not verified | Not checked endpoint by endpoint behind the gateway |
| JWT tokens revocable | PASS | `POST /api/v1/auth/logout` blacklists the token's `jti` (`open-security-identity/app/logout.py`) |
| Account lockout | PASS | `max_failed_login_attempts` (5) and `account_lockout_minutes` (15) in `open-security-identity/app/config.py` |
| CORS without wildcards | PASS | No `allow_origins=["*"]` or wildcard `Access-Control-Allow-Origin` in service code or gateway config |
| Security headers at the gateway | PASS | HSTS, `X-Frame-Options`, `X-Content-Type-Options` and `Permissions-Policy` set in `wildbox_gateway.conf` |
| API docs disabled in production | **FAIL** | See "API documentation served regardless of environment" above |
| No bare `except:` | PASS, one exception | Only `open-security-responder/demo_final.py`, a demo script |
| TLS verification enabled in all tools | **FAIL** | See "TLS verification disabled in two scanners" above |
| No Docker socket mounts | PASS | No `docker.sock` in any Compose file |
| SSRF protection on outbound requests | Not verified | |
| File upload validation | Not verified | |
| LLM input sanitization | Not verified | |
| CI secrets externalized | Not verified | `secret-scan.yml` runs on every PR; the workflows were not reviewed one by one |

---

## History

Earlier audits are kept for reference. They describe the code as it was when
they were written, and their file paths and line numbers no longer match:

- [Platform audit report](audit-report.md) (November 2024)
- [Remediation checklist](remediation-checklist.md) (November 2024)
- [Improvements summary](improvements-summary.md) (November 2024)
- [Tools service audit](tools-service-audit.md) (November 2025)

The audit rounds of February 2026 (v0.5.2 to v0.5.5) and every later security
change are recorded release by release in
[CHANGELOG.md](https://github.com/fabriziosalmi/wildbox/blob/main/CHANGELOG.md).
