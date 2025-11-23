# Security Policy

**Wildbox Security Platform**  
**Version:** 2.0  
**Last Updated:** November 23, 2025

---

## 🔒 Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in Wildbox, please report it responsibly.

### Reporting Process

1. **Email:** security@wildbox.dev
2. **Subject:** `[SECURITY] Brief description of issue`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 7 days
- **Fix Timeline:** Based on severity (see below)

### Severity Levels

| Severity | Examples | Fix Timeline |
|----------|----------|--------------|
| **Critical** | Authentication bypass, RCE, hardcoded secrets | 24-48 hours |
| **High** | XSS, SQL injection, privilege escalation | 3-7 days |
| **Medium** | Information disclosure, CSRF | 14 days |
| **Low** | Minor information leaks, UI issues | 30 days |

---

## 🛡️ Security Best Practices

### For Deployment

#### 1. Secret Management (CRITICAL)

**Never use default secrets in production.**

```bash
# Generate secure secrets
openssl rand -hex 32 > .secrets/jwt_secret
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
- Implement token revocation (Redis blacklist)

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
