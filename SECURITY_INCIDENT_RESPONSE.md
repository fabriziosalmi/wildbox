# Security Incident Response - Secret Exposure

**Status:** CRITICAL  
**Date:** November 23, 2025  
**Severity:** HIGH  
**Incident Type:** Exposed Secrets in Git History

---

## Executive Summary

A security audit revealed that `.env` files containing secrets were previously committed to the git repository history. While these files have been untracked (commit `b9852f80`), **the secrets remain exposed in git history and must be considered compromised**.

## Exposed Secrets Identified

### Git History Analysis

**Command Used:**
```bash
git log --all --full-history -p -- "**/.env" | grep -E "(SECRET|PASSWORD|KEY)"
```

**Findings:**

1. **JWT_SECRET_KEY** - Exposed in multiple commits
   - Commit `469a35be` (Nov 15, 2025): Changed from `INSECURE-DEFAULT-JWT-SECRET-CHANGE-THIS` to placeholder
   - Commit `a0d716a0` (Nov 15, 2025): Changed from `your-super-secret-jwt-key-change-this-in-production`
   - **Impact:** All JWT tokens signed with this key are potentially compromised

2. **Stripe API Keys** - Exposed in commit history
   - `STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key_here`
   - `STRIPE_PUBLISHABLE_KEY=pk_test_your_stripe_publishable_key_here`
   - `STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret_here`
   - **Impact:** Test keys (not production), but should be rotated

3. **API Keys** - Multiple instances
   - `API_KEY="UrZMId_lkb_-9TcWSicVPCVNqSvnwr8e2VS9iXTAfxw"`
   - `API_KEY="wildbox-security-api-key-2025"`
   - **Impact:** Service-to-service authentication potentially compromised

4. **Default Passwords**
   - `INITIAL_ADMIN_PASSWORD=TestPassword123!`
   - **Impact:** If this was used to create admin accounts, those accounts are compromised

5. **Hardcoded Secrets in Docker Compose**
   - `NEXTAUTH_SECRET=wildbox-dashboard-secret-for-testing` (docker-compose.yml)
   - `NEXTAUTH_SECRET=wildbox-dev-secret` (docker-compose.override.yml)
   - `JWT_SECRET_KEY=${JWT_SECRET_KEY:-INSECURE-DEFAULT-JWT-SECRET}` (identity docker-compose.yml)
   - `GATEWAY_INTERNAL_SECRET=${GATEWAY_INTERNAL_SECRET:-changeme-in-production}` (gateway docker-compose.yml)
   - `DATABASE_URL=postgresql+asyncpg://postgres:postgres@postgres:5432/identity` (identity docker-compose.yml)
   - **Impact:** Default fallback values expose production systems to known credentials

---

## Immediate Actions Taken (November 23, 2025)

### 1. ✅ Code Fixes Implemented

- **Removed hardcoded NEXTAUTH_SECRET** from `docker-compose.yml`
  - Changed to: `NEXTAUTH_SECRET=${NEXTAUTH_SECRET:?NEXTAUTH_SECRET environment variable is required}`
  - Enforces required environment variable, fails fast if not set

- **Updated docker-compose.override.yml**
  - Changed from: `NEXTAUTH_SECRET=wildbox-dev-secret`
  - To: `NEXTAUTH_SECRET=${NEXTAUTH_SECRET:-wildbox-dev-secret-CHANGE-IN-PRODUCTION}`
  - Adds warning suffix to prevent production use

- **Removed postgres:postgres default credentials**
  - Changed identity service docker-compose.yml to require `DATABASE_URL` environment variable
  - Changed from: `DATABASE_URL=postgresql+asyncpg://postgres:postgres@postgres:5432/identity`
  - To: `DATABASE_URL=${DATABASE_URL:?DATABASE_URL environment variable is required}`

- **Enforced JWT_SECRET_KEY requirement**
  - Changed from: `JWT_SECRET_KEY=${JWT_SECRET_KEY:-INSECURE-DEFAULT-JWT-SECRET}`
  - To: `JWT_SECRET_KEY=${JWT_SECRET_KEY:?JWT_SECRET_KEY environment variable is required}`

### 2. ✅ Removed Hardcoded Superadmin Email

- **Files Modified:**
  - `open-security-dashboard/src/app/admin/page.tsx`
  - `open-security-dashboard/src/components/main-layout.tsx`

- **Changes:**
  - Removed all `user?.email === 'superadmin@wildbox.com'` checks
  - Replaced with proper RBAC using `user?.is_superuser` JWT claim
  - Prevents frontend authorization bypass

### 3. ✅ Fixed Fake Metrics

- **File:** `open-security-dashboard/src/app/admin/page.tsx`
- **Removed:** `const avgResponseTime = servicesOnline > 0 ? 142 : 0`
- **Replaced with:** `const avgResponseTime = 0 // Real metrics not yet implemented`
- **Impact:** Prevents "vibe coding" - displaying fake data to appear professional

---

## REQUIRED IMMEDIATE ACTIONS (Within 24 Hours)

### Priority 1: Secret Rotation (CRITICAL)

**All secrets that were ever in git history MUST be rotated:**

1. **JWT_SECRET_KEY**
   ```bash
   # Generate new secret
   openssl rand -hex 32
   
   # Update in .env file
   JWT_SECRET_KEY=<new-secret>
   
   # Restart all services
   docker-compose restart identity gateway tools data guardian responder agents
   ```
   **Impact:** All existing user sessions will be invalidated

2. **NEXTAUTH_SECRET**
   ```bash
   # Generate new secret (32+ characters)
   openssl rand -base64 32
   
   # Update in .env file
   NEXTAUTH_SECRET=<new-secret>
   
   # Restart dashboard
   docker-compose restart dashboard
   ```
   **Impact:** All dashboard sessions will be invalidated

3. **GATEWAY_INTERNAL_SECRET**
   ```bash
   # Generate new secret
   openssl rand -hex 32
   
   # Update in .env file
   GATEWAY_INTERNAL_SECRET=<new-secret>
   
   # Restart gateway and all backend services
   docker-compose restart gateway identity tools data guardian responder agents cspm
   ```
   **Impact:** Gateway will reject all internal service requests until all services restart

4. **Database Passwords**
   ```bash
   # Generate new password
   openssl rand -base64 32
   
   # Update POSTGRES_PASSWORD in .env
   # Update all DATABASE_URL connection strings
   # Restart database and all services
   docker-compose down
   # Update docker volume or recreate database with new password
   docker-compose up -d
   ```
   **Impact:** DESTRUCTIVE - Requires database recreation or ALTER USER command

5. **API Keys**
   ```bash
   # Revoke all existing API keys via admin panel
   # Generate new API keys for each service/user
   # Update service configurations
   ```

6. **Stripe Keys** (if using production)
   - Rotate Stripe API keys via Stripe Dashboard
   - Update webhook secrets
   - **Note:** Test keys shown in git history are safe to leave if not used in production

7. **Initial Admin Password**
   ```bash
   # Force password reset for admin@wildbox.security
   # Or delete and recreate admin account with new password
   ```

### Priority 2: Git History Cleanup

**WARNING:** This is destructive and requires coordination with all contributors.

#### Option A: BFG Repo-Cleaner (Recommended)

```bash
# Install BFG
brew install bfg  # macOS
# or download from https://rtyley.github.io/bfg-repo-cleaner/

# Clone fresh copy
git clone --mirror https://github.com/fabriziosalmi/wildbox.git

# Remove .env files from history
bfg --delete-files .env wildbox.git

# Clean up
cd wildbox.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push (DESTRUCTIVE)
git push --force
```

#### Option B: Git Filter-Repo (More Control)

```bash
# Install git-filter-repo
pip install git-filter-repo

# Clone fresh copy
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox

# Remove .env files from history
git filter-repo --path .env --invert-paths
git filter-repo --path '**/.env' --invert-paths

# Force push (DESTRUCTIVE)
git push --force --all
```

#### Post-Cleanup Actions

1. **Notify all contributors** to re-clone repository
2. **Update all forks** (they will contain old history)
3. **Update CI/CD pipelines** (they cache old history)
4. **Verify cleanup:**
   ```bash
   git log --all --full-history -- "**/.env"
   # Should return empty
   ```

### Priority 3: Enhanced .gitignore Protection

**Already exists but verify:**

```bash
# Check .gitignore contains:
cat .gitignore | grep -E "\.env$|\.env\.local"

# Expected output:
.env
.env.local
.env.*.local
*.env
```

**Add pre-commit hook to prevent future commits:**

```bash
# Create .git/hooks/pre-commit
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Prevent committing .env files

if git diff --cached --name-only | grep -E "\.env$|\.env\.local"; then
  echo "ERROR: Attempted to commit .env file!"
  echo "Files:"
  git diff --cached --name-only | grep -E "\.env$|\.env\.local"
  echo ""
  echo "Remove these files from staging:"
  echo "  git reset HEAD <file>"
  exit 1
fi

# Scan for potential secrets
if git diff --cached | grep -iE "(SECRET|PASSWORD|API_KEY|TOKEN).*=.*[a-zA-Z0-9]{16,}"; then
  echo "WARNING: Potential secret detected in staged changes!"
  echo "Review carefully before committing."
  echo ""
  git diff --cached | grep -iE "(SECRET|PASSWORD|API_KEY|TOKEN).*=" --color=always
  echo ""
  read -p "Continue anyway? (yes/no): " confirm
  if [ "$confirm" != "yes" ]; then
    exit 1
  fi
fi
EOF

chmod +x .git/hooks/pre-commit
```

---

## Long-Term Remediation (Within 1 Week)

### 1. Secret Management Solution

**Implement one of:**

- **HashiCorp Vault** (recommended for production)
- **AWS Secrets Manager** (if deploying to AWS)
- **Azure Key Vault** (if deploying to Azure)
- **Docker Secrets** (for Docker Swarm deployments)

### 2. Audit Logging

- Enable audit logging for all secret access
- Monitor for unauthorized secret usage
- Alert on authentication failures with old credentials

### 3. Security Monitoring

```bash
# Add to security_validation_v2.sh
check_exposed_secrets() {
  echo "Checking for exposed secrets in git history..."
  
  if git log --all --full-history -- "**/.env" | grep -q "\.env"; then
    echo "✗ CRITICAL: .env files found in git history"
    return 1
  fi
  
  if git log --all --full-history | grep -iE "(SECRET|PASSWORD|API_KEY).*=.*[a-zA-Z0-9]{16,}" | head -5 | grep -q .; then
    echo "✗ WARNING: Potential secrets in git commit messages"
    return 1
  fi
  
  echo "✓ No obvious secrets in git history"
  return 0
}
```

### 4. Incident Postmortem

**Schedule team review to answer:**

1. How did .env files get committed?
2. Why wasn't pre-commit hook in place?
3. How can we prevent this in future?
4. Should we implement secret scanning in CI?

---

## Communication Plan

### Internal Team

**Immediate (Today):**
- ✅ Document incident (this file)
- ⏳ Notify team of secret rotation plan
- ⏳ Schedule rotation window (low-traffic time)

**24 Hours:**
- ⏳ Execute secret rotation
- ⏳ Verify all services operational
- ⏳ Document new secret locations

### External (If Applicable)

**If platform is public/production:**
- Notify users of forced logout (JWT rotation)
- Provide password reset instructions
- Publish security advisory (if customer data potentially exposed)

**If platform is private/dev:**
- No external notification needed
- Focus on prevention

---

## Verification Checklist

After remediation, verify:

- [ ] All secrets rotated and documented
- [ ] Git history cleaned (no .env files)
- [ ] All contributors re-cloned repository
- [ ] Pre-commit hook installed and tested
- [ ] CI/CD pipelines updated with new secrets
- [ ] All services operational with new secrets
- [ ] Old secrets confirmed non-functional
- [ ] Security monitoring in place
- [ ] Incident postmortem scheduled

---

## Additional Hardcoded Issues Identified

### From Brutal Rep Auditor Report:

1. **Fake Metrics (FIXED)**
   - ✅ Removed `avgResponseTime = 142` hardcoded value
   - ✅ Changed to `avgResponseTime = 0` with TODO comment

2. **Hardcoded Superadmin (FIXED)**
   - ✅ Removed `user?.email === 'superadmin@wildbox.com'` checks (13 instances)
   - ✅ Replaced with proper `user?.is_superuser` RBAC from JWT claims

3. **Docker Compose Hardcoded Secrets (FIXED)**
   - ✅ `NEXTAUTH_SECRET=wildbox-dashboard-secret-for-testing` → Required env var
   - ✅ `NEXTAUTH_SECRET=wildbox-dev-secret` → Added warning suffix
   - ✅ `postgres:postgres` credentials → Required env var
   - ✅ `JWT_SECRET_KEY` defaults → Required env var

---

## References

- Original disclosure commit: `b9852f80` (Nov 18, 2025)
- Config alignment commit: `a0d716a0` (Nov 15, 2025)
- JWT update commit: `469a35be` (Nov 15, 2025)
- Brutal Rep Auditor Report: Score 49/100 (Grade D)

---

**Document Status:** DRAFT - Awaiting secret rotation execution  
**Owner:** Security Team  
**Next Review:** After secret rotation completion  
**Classification:** INTERNAL - SECURITY SENSITIVE
