# PostgreSQL Password Alignment Fix

## Problem Identified

Multiple inconsistent PostgreSQL passwords across the codebase:

- `docker-compose.yml`: Uses `CHANGE-THIS-DB-PASSWORD` and `postgres`
- `.env`: Uses `SecureWildboxDB2024!`
- Various services: Use hardcoded passwords

## Standard Configuration

### 1. Single Source of Truth: Environment Variable

ALL services MUST read from: `${POSTGRES_PASSWORD}`

### 2. Updated docker-compose.yml

```yaml
# PostgreSQL Service
postgres:
  environment:
    - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-CHANGE-THIS-DB-PASSWORD}

# Data Service
data:
  environment:
    - DATABASE_URL=${DATA_DATABASE_URL:-postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/data}

# Guardian Service
guardian:
  environment:
    - DATABASE_URL=${GUARDIAN_DATABASE_URL:-postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/guardian}

# Identity Service
identity:
  environment:
    - DATABASE_URL=${IDENTITY_DATABASE_URL:-postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/identity}

# Responder Service
responder:
  environment:
    - DATABASE_URL=${RESPONDER_DATABASE_URL:-postgresql+asyncpg://postgres:${POSTGRES_PASSWORD}@postgres:5432/responder}
```

### 3. .env Configuration

```bash
# PostgreSQL Configuration (CRITICAL - Change in production!)
POSTGRES_USER=postgres
POSTGRES_PASSWORD=SecureWildboxDB2024!  # Change this!
POSTGRES_DB=identity

# Service-specific URLs (inherit from POSTGRES_PASSWORD)
DATA_DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/data
GUARDIAN_DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/guardian
IDENTITY_DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/identity
RESPONDER_DATABASE_URL=postgresql+asyncpg://postgres:${POSTGRES_PASSWORD}@postgres:5432/responder
```

### 4. .env.example Template

```bash
# =================================================================
# PostgreSQL Database Configuration
# =================================================================
# SECURITY WARNING: Change these values in production!
# Generate a secure password using: openssl rand -base64 32
# =================================================================

POSTGRES_USER=postgres
POSTGRES_PASSWORD=generate-secure-database-password-here
POSTGRES_DB=identity

# Service Database URLs
# These inherit from POSTGRES_PASSWORD above - no need to change
DATA_DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/data
GUARDIAN_DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/guardian
IDENTITY_DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/identity
RESPONDER_DATABASE_URL=postgresql+asyncpg://postgres:${POSTGRES_PASSWORD}@postgres:5432/responder
```

## Files Requiring Updates

### Priority 1 (Blocking)
- [ ] `docker-compose.yml` - Lines with hardcoded passwords in DATABASE_URLs
- [ ] `.env.example` - Add ${POSTGRES_PASSWORD} variable substitution

### Priority 2 (High)
- [ ] `docker-compose.override.yml` - Update DATABASE_URLs
- [ ] Service-specific docker-compose files (guardian, data, etc.)

### Priority 3 (Medium)
- [ ] Update documentation (README.md files)
- [ ] Add migration guide for existing deployments

## Migration Path for Existing Deployments

1. **Backup Current Database**:
   ```bash
   docker exec wildbox-postgres pg_dumpall -U postgres > backup.sql
   ```

2. **Update .env File**:
   ```bash
   # Set your chosen password
   POSTGRES_PASSWORD=YourSecurePasswordHere
   ```

3. **Restart Services**:
   ```bash
   docker-compose down
   docker-compose up -d postgres
   # Wait for postgres to start
   docker-compose up -d
   ```

4. **Verify Connection**:
   ```bash
   docker exec wildbox-postgres psql -U postgres -c "\l"
   ```

## Security Best Practices

1. **Password Requirements**:
   - Minimum 16 characters
   - Include uppercase, lowercase, numbers, special characters
   - No dictionary words
   - Generate using: `openssl rand -base64 32`

2. **Production Checklist**:
   - [ ] Password changed from default
   - [ ] Password stored in secure secrets management (not committed)
   - [ ] PostgreSQL exposed only to Docker network (not host)
   - [ ] Backup strategy in place
   - [ ] Regular password rotation policy defined

3. **Docker Secrets** (Recommended for Production):
   ```yaml
   secrets:
     postgres_password:
       file: ./secrets/postgres_password.txt

   services:
     postgres:
       secrets:
         - postgres_password
       environment:
         - POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
   ```

## Testing Verification

After applying fixes, verify:

```bash
# 1. Check all services can connect
docker-compose logs | grep -i "database.*connect"

# 2. Test each service database connection
for svc in identity data guardian responder; do
  echo "Testing $svc..."
  docker exec wildbox-postgres psql -U postgres -d $svc -c "SELECT 1;"
done

# 3. Run integration tests
python3 run_integration_tests.py
```

## Rollback Plan

If issues occur:

1. **Stop all services**: `docker-compose down`
2. **Restore .env backup**: `cp .env.backup .env`
3. **Restore database**: `docker exec -i wildbox-postgres psql -U postgres < backup.sql`
4. **Restart**: `docker-compose up -d`

---

**Status**: Documentation complete, awaiting implementation approval
**Priority**: HIGH - Blocks secure production deployment
**Estimated Time**: 30 minutes implementation + testing
