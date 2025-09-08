# 🛡️ Wildbox Security Best Practices & Configuration Guide

## 🚨 CRITICAL SECURITY REQUIREMENTS

### Before Production Deployment

**NEVER deploy Wildbox to production without completing ALL security requirements below!**

### 1. Environment Variables Configuration

Copy `.env.example` to `.env` and configure all variables:

```bash
cp .env.example .env
```

**Required changes:**

1. **Generate secure random values** for all keys and passwords
2. **Change all default credentials** 
3. **Use strong, unique passwords** for all services
4. **Configure proper CORS origins** for your domain

### 2. Critical Security Variables to Change

| Variable | Description | Security Level |
|----------|-------------|----------------|
| `JWT_SECRET_KEY` | JWT token signing key | **CRITICAL** |
| `INITIAL_ADMIN_PASSWORD` | Default admin password | **CRITICAL** |
| `POSTGRES_PASSWORD` | Database password | **CRITICAL** |
| `API_KEY` | Main API authentication key | **CRITICAL** |
| `STRIPE_SECRET_KEY` | Payment processing key | **CRITICAL** |
| `ENCRYPTION_KEY` | Data encryption key | **CRITICAL** |

### 3. Password Security Requirements

- **Minimum 16 characters**
- **Mix of uppercase, lowercase, numbers, symbols**
- **No dictionary words**
- **Unique per service**
- **Rotated regularly**

### 4. Secure Key Generation

Use secure random generators:

```bash
# Generate JWT secret (64 characters)
openssl rand -base64 48

# Generate API key
openssl rand -hex 32

# Generate encryption key
openssl rand -base64 32

# Generate secure password
openssl rand -base64 24
```

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

#### Required Firewall Rules:
- **Port 22**: SSH access (restrict to admin IPs only)
- **Port 80/443**: HTTP/HTTPS (public, with proper SSL)
- **Port 5432**: PostgreSQL (internal network only)
- **Port 6379**: Redis (internal network only)
- **All other ports**: Blocked from external access

#### SSL/TLS Configuration:
- **Use Let's Encrypt or commercial SSL certificates**
- **Enable HTTP to HTTPS redirect**
- **Configure strong cipher suites**
- **Enable HSTS headers**

### 7. Database Security

#### PostgreSQL Hardening:
```sql
-- Create dedicated user for application
CREATE USER wildbox_app WITH PASSWORD 'secure_random_password';

-- Grant minimal required permissions
GRANT CONNECT ON DATABASE wildbox_main TO wildbox_app;
GRANT USAGE ON SCHEMA public TO wildbox_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO wildbox_app;

-- Remove default postgres user access if not needed
```

#### Redis Security:
- **Enable authentication** (`requirepass` directive)
- **Bind to localhost only** unless clustering
- **Disable dangerous commands** (`rename-command` directive)

### 8. Application Security

#### Authentication:
- **Enable MFA** for admin accounts
- **Set session timeouts** (default: 1 hour)
- **Implement account lockout** after failed attempts
- **Require email verification** for new accounts

#### API Security:
- **Rate limiting** enabled on all endpoints
- **API key rotation** every 90 days
- **Input validation** on all user inputs
- **SQL injection protection** via parameterized queries

### 9. Monitoring & Logging

#### Required Monitoring:
- **Authentication failures**
- **Unauthorized access attempts**
- **Database connection anomalies**
- **High resource usage**
- **Service health status**

#### Log Requirements:
- **Centralized logging** (ELK stack, Splunk, etc.)
- **Log retention** policy (minimum 90 days)
- **Log integrity** protection
- **Automated alerting** on security events

### 10. Backup & Recovery

#### Backup Strategy:
- **Daily automated backups** of all databases
- **Encrypted backup storage**
- **Off-site backup replication**
- **Regular restore testing**
- **Recovery time objective**: < 4 hours
- **Recovery point objective**: < 1 hour

### 11. Incident Response

#### Preparation:
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

## 🚨 Security Incident Contacts

If you discover a security vulnerability:

1. **Do NOT** create a public issue
2. **Email security team** at: security@wildbox.security
3. **Include** detailed reproduction steps
4. **Provide** your contact information
5. **Allow** 48 hours for initial response

## 📚 Additional Resources

- [OWASP Security Guidelines](https://owasp.org/www-project-top-ten/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)
- [Redis Security](https://redis.io/topics/security)

---

**Last Updated**: September 2025  
**Version**: 1.0  
**Review Frequency**: Quarterly  