# Wildbox Security Policy & Best Practices

**Maturity**: Early Evaluation Phase

This page states the security requirements and practices Wildbox aims for.
Where the code does not meet them yet, the gap is listed under
"Known Open Issues" in the [Security status](status.md).

## Quick Navigation

- [Critical Security Requirements](#critical-security-requirements)
- [Security Features Implemented](#security-features-implemented)
- [Security Incident Contacts](#security-incident-contacts)
- [Additional Resources](#additional-resources)
- [Version History](#version-history)

---

## CRITICAL SECURITY REQUIREMENTS

### Before Production Deployment

**NEVER deploy Wildbox to production without completing ALL security requirements below!**

### Recent Security Improvements (2024)

- ✓ Fixed critical eval() RCE vulnerability
- ✓ Resolved 13 Dependabot security alerts
- ✓ Implemented security headers middleware
- ✓ Fixed CORS configuration across all services
- ✓ Added authentication to critical endpoints
- ✓ Removed default secrets from docker-compose
- ✓ Created comprehensive security documentation
- ✓ Implemented environment-based configuration

### 1. Environment Variables Configuration

Generate `.env` with random values for every secret, then check it:

```bash
make generate-secrets    # scripts/generate_secrets.py, writes .env with mode 0600
make validate-secrets    # refuses placeholders and known weak values
```

Then set the values that describe your deployment: `INITIAL_ADMIN_EMAIL`
and `CORS_ORIGINS` (your HTTPS origins only). Do not write secrets by hand or
copy them from documentation.

### 2. Critical Security Variables

The [Credentials guide](../guides/credentials.md) lists every generated value
and what it protects. The most sensitive are:

| Variable | Description | Security Level |
| ---------- | ------------- | ---------------- |
| `JWT_SECRET_KEY` | Signs every login token | **CRITICAL** |
| `API_KEY_HASH_SECRET` | Keys the HMAC of stored API keys | **CRITICAL** |
| `GATEWAY_INTERNAL_SECRET` | Proves to the backends that a request came through the gateway | **CRITICAL** |
| `INITIAL_ADMIN_PASSWORD` | Password of the first administrator | **CRITICAL** |
| `POSTGRES_PASSWORD`, `REDIS_PASSWORD` | Datastore passwords | **CRITICAL** |
| `CSPM_CREDENTIAL_KEY` | Encrypts stored cloud credentials | **CRITICAL** |
| `API_KEY` | Static key for the tools API | **CRITICAL** |

### 3. Password Security Requirements

- **Change the first administrator's password** after the first login
- **Use long, unique passwords** for every account
- **Rotate secrets** with `scripts/rotate_secrets.sh`, which knows which ones
  depend on each other

### 4. Secure Key Generation

`scripts/generate_secrets.py` uses Python's `secrets` module and refuses to
emit a value that the services' own validators would reject. To rotate one
secret later, use `./scripts/rotate_secrets.sh --secret <NAME>`.

### 5. Production Security Checklist

- [ ] **All default passwords changed**
- [ ] **All secret keys generated with secure randomness**
- [ ] **Environment variables properly configured**
- [ ] **CORS origins restricted to your domains only**
- [ ] **DEBUG mode disabled (`DEBUG=false`)**
- [ ] **HTTPS enabled for all public endpoints**
- [ ] **Database access restricted to application only**
- [ ] **Firewall rules configured**
- [ ] **Regular security updates scheduled**
- [ ] **Backup strategy implemented**
- [ ] **Log monitoring configured**
- [ ] **Intrusion detection enabled**

### 6. Network Security

#### Required Firewall Rules

- **Port 22**: SSH access (restrict to admin IPs only)
- **Port 80/443**: HTTP/HTTPS (public, with proper SSL)
- **Port 5432**: PostgreSQL (internal network only)
- **Port 6379**: Redis (internal network only)
- **All other ports**: Blocked from external access

#### SSL/TLS Configuration

- **Use Let's Encrypt or commercial SSL certificates**
- **Enable HTTP to HTTPS redirect**
- **Configure strong cipher suites**
- **Enable HSTS headers**

### 7. Database Security

#### PostgreSQL Hardening

```sql
-- Create dedicated user for application
CREATE USER wildbox_app WITH PASSWORD '<generated password>';

-- Grant minimal required permissions
GRANT CONNECT ON DATABASE wildbox_main TO wildbox_app;
GRANT USAGE ON SCHEMA public TO wildbox_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO wildbox_app;

-- Remove default postgres user access if not needed
```

#### Redis Security

- **Enable authentication** (`requirepass` directive)
- **Bind to localhost only** unless clustering
- **Disable dangerous commands** (`rename-command` directive)

### 8. Application Security

#### Authentication

What Wildbox enforces (details in
[Authentication and sessions](../guides/authentication.md)):

- **Access tokens last 30 minutes**, with no refresh token
- **Logout revokes the token** at identity and at the gateway
- **Account lockout**: 5 failed password logins lock an email for 15 minutes

What it does not provide, so plan around it:

- **No multi-factor authentication**: restrict who can reach the gateway
- **No email verification requirement** at login: limit who can register

#### API Security

- **Rate limiting** enabled on all endpoints
- **API key rotation** every 90 days
- **Input validation** on all user inputs
- **SQL injection protection** via parameterized queries

### 9. Monitoring & Logging

#### Required Monitoring

- **Authentication failures**
- **Unauthorized access attempts**
- **Database connection anomalies**
- **High resource usage**
- **Service health status**

#### Log Requirements

- **Centralized logging** (ELK stack, Splunk, etc.)
- **Log retention** policy (minimum 90 days)
- **Log integrity** protection
- **Automated alerting** on security events

### 10. Backup & Recovery

#### Backup Strategy

- **Daily automated backups** of all databases
- **Encrypted backup storage**
- **Off-site backup replication**
- **Regular restore testing**
- **Recovery time objective**: < 4 hours
- **Recovery point objective**: < 1 hour

### 11. Incident Response

#### Preparation

- **Document incident response procedures**
- **Define roles and responsibilities**
- **Establish communication channels**
- **Create contact lists for emergencies**
- **Regular tabletop exercises**

### 12. Compliance Considerations

Depending on your use case, ensure compliance with:

- **GDPR** (EU data protection)
- **SOC 2** (security controls)
- **ISO 27001** (information security)
- **NIST Cybersecurity Framework**
- **Industry-specific regulations**

### 13. Managing Dependency Vulnerabilities

How dependencies are kept free of known advisories:

- **Python**: every service installs from a hash-pinned `requirements.txt`
  compiled from `requirements.in` (`make lock`). `make lock-security`
  (`scripts/upgrade_vulnerable_requirements.sh`) moves only the packages with
  a known advisory, and the weekly `Pip Security Upgrades` workflow opens a
  pull request with the result. Dependabot does not handle pip.
- **npm, Docker base images and GitHub Actions**: Dependabot opens the update
  pull requests.
- **Gates**: `PR Validation` fails a pull request that introduces a critical
  advisory; the `Main Advisories` workflow checks `main` daily and keeps one
  issue open while any critical advisory is present.

The current state is on the [Security status](status.md) page and in the
repository's [Dependabot alerts](https://github.com/fabriziosalmi/wildbox/security/dependabot).

**Your deployment:**

- Rebuild the images after every update; they are built from the repository,
  so pulling the code alone changes nothing that is running (see
  [Updating](../guides/deployment.md#8-updating)).
- Subscribe to [GitHub Security Advisories](https://github.com/fabriziosalmi/wildbox/security/advisories)
  and the releases page.
- Test updates in staging before production.

## Security Features Implemented

### 1. Authentication & Authorization

- JWT tokens signed with HS256 (minimum 32-character secret), valid for 30 minutes, without refresh
- Revocation on logout: the token's `jti` is blacklisted in Redis and purged from the gateway's cache
- Failed-login lockout: 5 failures lock an email for 15 minutes
- Password hashing with Argon2id through fastapi-users' `PasswordHelper`; see [Authentication and sessions](../guides/authentication.md)
- Bearer token authentication on all protected endpoints
- API keys, stored as HMAC-SHA256 digests
- Team roles (owner, admin, member) and platform superusers

### 2. API Security

- Restricted CORS (environment-configured, never wildcard)
- Security headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP
- Input validation on all endpoints
- Parameterized queries (no SQL injection)
- XXE protection (defusedxml)
- Rate limiting at the gateway, per client address and per team

### 3. Code Security

- No eval() calls (secure JSON serialization)
- No hardcoded secrets in code
- No plaintext password logging (the initial administrator password is no longer printed)
- Secure random generation for tokens/keys
- Error handling without exposing internals

### 4. Infrastructure Security

- Secrets required (no defaults in docker-compose)
- Environment-based configuration
- TLS/SSL support
- Network segmentation in the production configuration (`docker-compose.prod.yml`; verified in CI, see the [Security status](status.md))
- Health checks configured
- Monitoring hooks ready

---

## Security Incident Contacts

If you discover a security vulnerability:

1. **Do NOT** create a public issue
2. **Email security team** at: fabrizio.salmi@gmail.com
3. **Include** detailed reproduction steps
4. **Provide** your contact information
5. **Allow** 48 hours for initial response

### Bug Bounty Program

We value security researchers! Valid vulnerability reports receive:

- **Critical**: Recognition + merchandise
- **High**: Recognition
- **Medium**: Recognition
- **Low**: Acknowledgment

## Additional Resources

- [OWASP Security Guidelines](https://owasp.org/www-project-top-ten/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
- [Redis Security](https://redis.io/topics/security)

---


## Version History

### 2.0 (November 7, 2024)

- Fixed critical eval() RCE vulnerability
- Resolved 13 Dependabot security alerts
- Implemented comprehensive security headers middleware
- Fixed CORS configuration across all services
- Added authentication to critical endpoints
- Removed all default secrets from docker-compose.yml
- Created shared authentication utilities
- Added production deployment guidance

### 1.0 (October 2024)

- Initial security policy and best practices guide
