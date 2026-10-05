# Security Policy

## Reporting a Vulnerability

Report vulnerabilities privately. Do not open a public issue, pull request or
discussion for a security problem.

- **Preferred**: [report it privately on GitHub](https://github.com/fabriziosalmi/wildbox/security/advisories/new)
  (Security tab, "Report a vulnerability").
- **Email**: the address in
  [`security.txt`](https://www.wildbox.io/.well-known/security.txt)
  (`fabrizio.salmi@gmail.com`), with `[SECURITY]` and a short description in
  the subject.

Include:

1. What the vulnerability is and which service or file it affects
2. Steps to reproduce, with a proof of concept if you have one
3. The impact you expect
4. Optionally, a proposed fix

Please do not exploit a vulnerability beyond what is needed to show it, and do
not access or modify data that is not yours.

### What Happens Next

| Timeframe | Action |
| --- | --- |
| 48 hours | Acknowledgment of your report |
| 7 days | Severity assessment and status update |
| 14 to 90 days | Fix developed and tested, depending on severity |
| After the fix | Public disclosure coordinated with you |

| Severity | Target response | Examples |
| --- | --- | --- |
| Critical | 24 to 48 hours | Authentication bypass, remote code execution, secrets in shipped code |
| High | 3 to 7 days | SQL injection, XSS, privilege escalation, insecure defaults exposing data |
| Medium | 14 days | CSRF, information disclosure, missing security headers, weak cryptography |
| Low | 30 days | Minor information leaks, non-exploitable edge cases |

Fixes are published as GitHub Security Advisories and recorded in
[CHANGELOG.md](CHANGELOG.md). Reporters are credited, with their permission,
in the advisory and the release notes.

---

## Current Security State

What is known to be wrong today, and how each claim was checked, is published
on the [security status page](https://www.wildbox.io/security/status/). It is
the authoritative list of open issues; this file does not repeat it.

---

## Deploying Securely

The guides on the documentation site are the reference; in short:

- **Secrets**: generate every secret with `make generate-secrets` and check
  them with `make validate-secrets`. There are no default credentials; never
  copy a secret from documentation. Rotate with `scripts/rotate_secrets.sh`.
  See [Credentials](https://www.wildbox.io/guides/credentials/).
- **Exposure**: only the gateway is published (443, plus 80 and 8080 for
  `/health` and the redirect to HTTPS). Backends are bound to `127.0.0.1`,
  PostgreSQL and Redis publish no port, and the gateway's internal port 8081
  is not published. Open only 443 (and 80 if you want the redirect) in your
  firewall. See [Service ports](https://www.wildbox.io/guides/ports/).
- **TLS**: replace the self-signed development certificate with a real one.
  See the [Deployment guide](https://www.wildbox.io/guides/deployment/).
- **Environment**: keep `ENVIRONMENT=production` (the generated default) and
  `DEBUG=false`; identity, agents and responder then stop serving their API
  documentation, and cspm serves it only with `DEBUG=true`.
- **Updates**: rebuild the images after pulling a release, and read
  [UPGRADING.md](UPGRADING.md) first.
- **Backups**: `make backup` (PostgreSQL and Redis) and
  `make restore-drill`; backups contain sensitive data, so encrypt them
  (`GPG_RECIPIENT`) and keep them off the server.

---

## Security Features

Authentication (details in
[Authentication and sessions](https://www.wildbox.io/guides/authentication/)):

- Every API request is authenticated at the gateway, which validates JWTs and
  API keys with the identity service; each backend rejects requests that do
  not carry the gateway's `GATEWAY_INTERNAL_SECRET`.
- JWT access tokens are signed with HS256, last 30 minutes and cannot be
  refreshed. Logout revokes the token in Redis and drops it from the
  gateway's authorization cache.
- Five failed password logins lock an email address for 15 minutes.
- Passwords are hashed with Argon2id; API keys are stored as HMAC-SHA256
  digests keyed by `API_KEY_HASH_SECRET`.
- Team roles (owner, admin, member) and platform superusers.

Platform:

- Rate limiting at the gateway, per client address and per team.
- Security headers at the gateway (HSTS, `X-Frame-Options`,
  `X-Content-Type-Options`, `Permissions-Policy`, Content Security Policy).
- Security tools verify TLS certificates by default.
- Cloud credentials stored by CSPM are encrypted with `CSPM_CREDENTIAL_KEY`.
- Wildbox has no multi-factor authentication.

Development and CI:

- Hash-pinned Python lock files; `PR Validation` blocks pull requests that add a
  critical advisory, and `Main Advisories` checks `main` daily.
- `pip-audit`, Trivy, Bandit, Gitleaks and GitHub code scanning run in CI.
- Python security upgrades: `make lock-security` and the weekly
  `Pip Security Upgrades` workflow. npm, Docker and GitHub Actions updates:
  Dependabot.

---

## Further Reading

- [Security status](https://www.wildbox.io/security/status/)
- [Security policy and practices](https://www.wildbox.io/security/policy/)
- [Secrets rotation](docs/SECURITY_SECRETS_ROTATION.md)
- [Engineering standards](docs/ENGINEERING_STANDARDS.md)
