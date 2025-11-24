# Security Secrets Rotation Guide

**CRITICAL**: Git history contains hardcoded secrets. All credentials must be rotated immediately.

## Compromised Secrets Inventory

### 1. JWT Secrets
**Location**: `.env.example`, `.env.template`, service-specific configs  
**Risk**: Token forgery, privilege escalation  
**Action Required**:
```bash
# Generate new secure JWT secret (256-bit minimum)
openssl rand -base64 64 > /tmp/new_jwt_secret.txt

# Update in .env (DO NOT COMMIT)
JWT_SECRET_KEY=$(cat /tmp/new_jwt_secret.txt)
```

### 2. Database Passwords
**Location**: `docker-compose.yml`, `.env.example`, hardcoded in connection strings  
**Risk**: Full database compromise  
**Action Required**:
```bash
# Generate strong database password
POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Update docker-compose.yml environment variables
# Update service DATABASE_URL connection strings
# Recreate database containers with new credentials
```

### 3. API Keys
**Location**: Test files, example configurations  
**Risk**: Unauthorized API access  
**Action Required**:
- Revoke all API keys generated before secret rotation
- Force re-generation of all team API keys
- Implement key rotation policy (90-day expiry)

### 4. Redis Passwords
**Location**: Service configurations, docker-compose  
**Risk**: Cache poisoning, session hijacking  
**Action Required**:
```bash
# Generate Redis password
REDIS_PASSWORD=$(openssl rand -hex 32)

# Update redis.conf requirepass directive
# Update all service REDIS_URL connection strings
```

### 5. Stripe API Keys (if production)
**Location**: `.env.example`  
**Risk**: Payment data exposure, financial fraud  
**Action Required**:
- Rotate keys in Stripe Dashboard
- Update webhook signing secrets
- Audit transaction logs for unauthorized access

## Rotation Procedure

### Phase 1: Immediate Lockdown (0-2 hours)
1. **Revoke all known API keys** in identity service database
2. **Invalidate all JWT tokens** by changing JWT_SECRET_KEY (forces re-login)
3. **Reset all service-to-service authentication** tokens
4. **Audit access logs** for suspicious activity during compromise window

### Phase 2: Credential Rotation (2-6 hours)
1. Generate new secrets using cryptographically secure methods (above)
2. Update secrets in production environment (secrets manager, NOT git)
3. Restart all services with new credentials
4. Verify health checks and authentication flows

### Phase 3: Git History Sanitization (6-24 hours)
```bash
# WARNING: This rewrites git history. Coordinate with all developers.
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch .env .env.local open-security-*/.env" \
  --prune-empty --tag-name-filter cat -- --all

# Force push to remote (requires team coordination)
git push origin --force --all
git push origin --force --tags
```

**Alternative**: Treat repository as compromised, create fresh repository with sanitized code.

### Phase 4: Prevention (Ongoing)
1. **Implement pre-commit hooks** to block secret commits:
   ```bash
   # Install gitleaks or detect-secrets
   pip install detect-secrets
   detect-secrets scan --baseline .secrets.baseline
   ```

2. **Use environment-specific secret management**:
   - Development: `.env.local` (git-ignored)
   - Staging: AWS Secrets Manager / Azure Key Vault
   - Production: Kubernetes Secrets / HashiCorp Vault

3. **Enforce secret rotation policies**:
   - JWT secrets: Rotate quarterly
   - Database passwords: Rotate semi-annually
   - API keys: 90-day expiry, auto-revocation

4. **Audit secret access**:
   ```bash
   # Add to CI/CD pipeline
   git log -p | grep -i 'password\|secret\|key' | grep -v '.example'
   ```

## Verification Checklist

- [ ] All JWT_SECRET_KEY values rotated across services
- [ ] POSTGRES_PASSWORD changed and database reconnected
- [ ] REDIS_PASSWORD updated and services reconnected
- [ ] All API keys revoked and regenerated
- [ ] Stripe keys rotated (if applicable)
- [ ] Git history scanned with `git-secrets` or `gitleaks`
- [ ] Pre-commit hooks installed on developer machines
- [ ] Secrets stored in proper secrets manager (not .env files)
- [ ] Documentation updated with secret management best practices
- [ ] Incident postmortem completed (how secrets leaked, prevention measures)

## Detection of Exposed Secrets

Run these commands to audit for exposed secrets:

```bash
# Scan git history for secrets
docker run --rm -v "$(pwd):/path" zricethezav/gitleaks:latest detect \
  --source="/path" --verbose --redact

# Search for common secret patterns
git log -p | grep -E 'sk_live_|sk_test_|AKIA|ghp_|pk_live_|pk_test_'

# Check for hardcoded passwords
git grep -i 'password.*=' | grep -v '.example' | grep -v '.md'
```

## Post-Rotation Monitoring

1. **Monitor authentication failures** (spike indicates leaked credentials still in use)
2. **Track API key usage patterns** (anomalies indicate compromise)
3. **Alert on database connection errors** (verify password rotation successful)
4. **Verify JWT signature validation** (ensure no tokens signed with old secret)

## Contact for Security Incidents

Report security incidents immediately:
- **Email**: security@wildbox.security (if configured)
- **GitHub Security Advisory**: Use "Report a vulnerability" in repository settings
- **Slack**: #security-incidents (if team workspace exists)

---

**Last Updated**: 2025-11-24  
**Next Rotation Due**: Set based on policy (quarterly recommended)  
**Responsible Team**: Security / DevOps
