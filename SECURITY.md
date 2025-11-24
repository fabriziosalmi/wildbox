# Security Policy

**Wildbox Security Platform**  
**Version:** 2.1  
**Last Updated:** 2025-11-24

---

## 🔒 Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in Wildbox, please report it responsibly through our private disclosure process.

### How to Report

**Email**: security@wildbox.dev

**Subject Format**: `[SECURITY] <Brief Description>`

**Required Information**:
1. **Vulnerability Description**: Clear explanation of the security issue
2. **Affected Components**: Which services/files are impacted
3. **Reproduction Steps**: Detailed steps to reproduce the vulnerability
4. **Proof of Concept**: Code snippet or configuration demonstrating the issue
5. **Impact Assessment**: Potential security impact and attack scenarios
6. **Suggested Fix**: (Optional) Your proposed remediation

**What NOT to do**:
- ❌ Do not open public GitHub issues for security vulnerabilities
- ❌ Do not discuss vulnerabilities in public channels (Discord, Twitter, etc.)
- ❌ Do not exploit vulnerabilities beyond verification
- ❌ Do not access or modify data that isn't yours

### Response Timeline

| Timeframe | Action |
|-----------|--------|
| **48 hours** | Initial acknowledgment of your report |
| **7 days** | Detailed status update and severity assessment |
| **14-90 days** | Fix development and testing (based on severity) |
| **After fix** | Public disclosure coordinated with reporter |

### Severity Classification

| Severity | Response Time | Examples |
|----------|---------------|----------|
| **Critical** | 24-48 hours | Authentication bypass, Remote Code Execution, Hardcoded secrets in production code |
| **High** | 3-7 days | SQL Injection, XSS, Privilege escalation, Insecure defaults exposing sensitive data |
| **Medium** | 14 days | CSRF, Information disclosure, Missing security headers, Weak cryptography |
| **Low** | 30 days | Minor information leaks, UI-only issues, Non-exploitable edge cases |

### Recognition

Security researchers who responsibly disclose vulnerabilities will be:
- Credited in our SECURITY.md Hall of Fame (with permission)
- Mentioned in release notes for the fix
- Eligible for swag/recognition (for significant findings)

---

## 🛡️ Security Best Practices

### For Deployment

#### 1. Secret Management (CRITICAL)

**Never use default secrets in production.**

Generate secure secrets for all services:

```bash
# Generate JWT secret (256-bit recommended)
openssl rand -hex 32

# Generate database password (strong passphrase)
openssl rand -base64 32

# Generate API keys
openssl rand -hex 32
```

Update your `.env` file:

```bash
# REQUIRED: Change these from defaults
JWT_SECRET_KEY=<generated-secret-here>
DATABASE_PASSWORD=<generated-password-here>
GATEWAY_INTERNAL_SECRET=<generated-secret-here>

# Optional: External service keys
OPENAI_API_KEY=sk-<your-openai-key>
STRIPE_SECRET_KEY=sk_live_<your-stripe-key>
```

**Never commit `.env` files to version control!**
openssl rand -base64 24 > .secrets/n8n_password
openssl rand -base64 32 > .secrets/db_password
```

**Required environment variables:**

```bash
# .env (NEVER commit this file)
JWT_SECRET_KEY=<generate with: openssl rand -hex 32>
NEXTAUTH_SECRET=<generate with: openssl rand -base64 32>
GATEWAY_INTERNAL_SECRET=<generate with: openssl rand -hex 32>
POSTGRES_PASSWORD=<generate with: openssl rand -base64 32>
N8N_BASIC_AUTH_PASSWORD=<generate with: openssl rand -base64 24>
GRAFANA_ADMIN_PASSWORD=<generate with: openssl rand -base64 24>
API_KEY=<generate with: openssl rand -hex 32>
```

**Validation:**
```bash
# Verify no hardcoded secrets
./security_validation_v2.sh
```

#### 2. Network Security

**Production deployment MUST:**
- Use HTTPS/TLS for all external traffic
- Route all requests through the gateway (port 80/443)
- Block direct access to backend services (ports 8000-8019)
- Enable firewall rules limiting access to necessary ports

**Firewall Configuration:**
```bash
# Allow only gateway and dashboard
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3000/tcp

# Deny direct backend access from external
ufw deny 8000:8019/tcp
```

#### 3. Database Security

**PostgreSQL:**
- Change default password immediately
- Use strong passwords (min 24 chars, cryptographically random)
- Limit connections to localhost/internal network
- Enable SSL/TLS for database connections
- Regular backups with encryption

**Configuration:**
```yaml
postgres:
  environment:
    - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
  # Limit connections
  command: -c max_connections=100 -c shared_buffers=256MB
  # Enable SSL (production)
  volumes:
    - ./ssl/server.crt:/var/lib/postgresql/server.crt:ro
    - ./ssl/server.key:/var/lib/postgresql/server.key:ro
```

#### 4. Authentication & Authorization

**JWT Security:**
- Rotate `JWT_SECRET_KEY` regularly (every 90 days)
- Use strong signing algorithms (RS256 for production)
- Set appropriate token expiration (15 min access, 7 day refresh)
- Implement token revocation (Redis denylist)

**API Key Management:**
- Generate cryptographically secure API keys
- Store only hashed versions in database (SHA256)
- Implement rate limiting (enforced at gateway)
- Rotate keys on security events

#### 5. Rate Limiting

**Gateway Configuration:**
```nginx
# Per IP rate limiting
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

location /api/ {
    limit_req zone=api_limit burst=20;
}
```

**Service-level limits (via environment):**
```bash
RATE_LIMIT_REQUESTS=500
RATE_LIMIT_WINDOW=60
```

---

## 🔍 Security Validation

### Pre-Deployment Checklist

- [ ] Run `./security_validation_v2.sh` - must pass
- [ ] All secrets generated with cryptographic randomness
- [ ] `.env` file NOT in version control
- [ ] HTTPS/TLS certificates installed
- [ ] Firewall configured (external access to 80/443/3000 only)
- [ ] Database passwords changed from defaults
- [ ] API keys rotated from development keys
- [ ] Rate limiting configured
- [ ] Monitoring/alerting configured (Grafana)

### Automated Checks

```bash
# Security validation (must pass before deployment)
./security_validation_v2.sh

# Dependency vulnerability scanning
make security-check

# Container scanning (requires trivy)
trivy image --severity HIGH,CRITICAL wildbox-gateway
```

### Manual Review

1. **Code Review:**
   - No hardcoded secrets
   - Input validation on all user data
   - Proper error handling (no information leakage)
   - SQL injection prevention (parameterized queries)
   - XSS prevention (output encoding)

2. **Configuration Review:**
   - `docker-compose.yml` - all secrets use `${VARIABLE}`
   - `nginx` - security headers enabled
   - Services - resource limits configured

---

## 📋 Security Features

### Authentication

- **JWT-based authentication** with refresh tokens
- **API key authentication** for service-to-service
- **Gateway-enforced authorization** (all requests validated)
- **Team-based access control** (multi-tenancy)

### Data Protection

- **TLS/HTTPS** for all external communications
- **Password hashing** with bcrypt (12 rounds)
- **API key hashing** with SHA256
- **Database encryption** (optional, recommended for production)

### Network Security

- **API Gateway** (OpenResty/Nginx with Lua authentication)
- **Request validation** before reaching backend services
- **Rate limiting** per IP and per user
- **CORS policies** enforced

### Monitoring & Auditing

- **Structured logging** (all services use structlog)
- **Access logs** (gateway tracks all requests)
- **Metrics collection** (Prometheus)
- **Alerting** (Grafana)

---

## 🚨 Known Security Considerations

### Current Limitations

1. **Development Mode:**
   - Default `docker-compose.yml` is for **development only**
   - Uses `POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-postgres}` (fallback for local dev)
   - **Production MUST set all secrets explicitly**

2. **TLS Certificates:**
   - Self-signed certificates in `open-security-gateway/ssl/`
   - **Production MUST use valid certificates** (Let's Encrypt, purchased certs)

3. **Session Management:**
   - Sessions stored in Redis
   - **Production MUST persist Redis** (`redis.conf` with AOF)

4. **Backup Security:**
   - Database backups created with `make backup`
   - **Backups contain sensitive data - encrypt and secure**

---

## 📚 Security Resources

### Standards & Compliance

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Tools Used

- **Secret Management:** Environment variables, never hardcoded
- **Dependency Scanning:** `pip-audit` (Python), `trivy` (Docker)
- **Static Analysis:** `bandit` (Python security)
- **Container Scanning:** `trivy` (vulnerabilities)
- **Network Testing:** `nmap`, `sqlmap` (penetration testing)

### Internal Documentation

- `docs/ENGINEERING_STANDARDS.md` - Secure coding practices
- `docs/GATEWAY_AUTHENTICATION_GUIDE.md` - Authentication flow
- `.env.example` - Required secrets with generation commands

---

## 🔄 Security Update Process

### Dependency Updates

```bash
# Check for vulnerabilities
make security-check

# Update dependencies (review changelog first)
make update

# Test after updates
make test
```

### Security Patches

1. Security team notified via security@wildbox.dev
2. Severity assessed (Critical/High/Medium/Low)
3. Fix developed and tested
4. Security advisory published (GitHub Security Advisories)
5. Patch released with version bump
6. Users notified (email, GitHub releases)

---

## 📞 Contact

**Security Team:** security@wildbox.dev  
**GitHub Security Advisories:** https://github.com/fabriziosalmi/wildbox/security/advisories  
**GPG Key:** [Available on request]

---

## 🙏 Acknowledgments

We appreciate responsible disclosure from security researchers. Contributors who report valid vulnerabilities will be acknowledged (with permission) in:

- Security advisories
- Release notes
- This document

---

**Last Security Audit:** November 23, 2025 (Brutal Rep Auditor)  
**Remediation Status:** Critical issues resolved (see AUDIT_REMEDIATION_REPORT.md)  
**Next Audit:** Q1 2026
