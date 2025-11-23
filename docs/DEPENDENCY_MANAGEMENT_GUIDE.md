# Dependency Management with pip-tools

**Status:** 📋 IMPLEMENTATION GUIDE  
**Priority:** HIGH (Security Tool)  
**Timeline:** Sprint 2

## Current State

❌ **Problems:**
```txt
# requirements.txt (current)
fastapi
uvicorn
sqlalchemy
# ... no version pins, no hashes
```

**Risks:**
- Dependency confusion attacks
- Supply chain compromises
- Unpredictable builds
- Version drift between environments

## Target State

✅ **With pip-tools:**
```txt
# requirements.in (human-edited)
fastapi>=0.104.0,<0.105.0
uvicorn[standard]>=0.24.0
sqlalchemy>=2.0.0,<3.0.0

# requirements.txt (auto-generated with hashes)
fastapi==0.104.1 \
    --hash=sha256:abc123... \
    --hash=sha256:def456...
uvicorn[standard]==0.24.0.post1 \
    --hash=sha256:ghi789...
sqlalchemy==2.0.23 \
    --hash=sha256:jkl012...
# ... all transitive dependencies with hashes
```

## Implementation Plan

### Step 1: Install pip-tools per Service

**For each service** (identity, tools, data, guardian, responder, cspm, agents):

```bash
cd open-security-[service]
pip install pip-tools
```

### Step 2: Create requirements.in Files

**Rename current requirements.txt to requirements.in:**
```bash
mv requirements.txt requirements.in
```

**Edit requirements.in** - use version ranges for direct dependencies:
```txt
# requirements.in - Human-maintained

# Framework
fastapi>=0.104.0,<0.105.0
uvicorn[standard]>=0.24.0,<0.25.0

# Database
sqlalchemy>=2.0.0,<3.0.0
alembic>=1.12.0,<2.0.0
psycopg2-binary>=2.9.0,<3.0.0

# Security
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
python-multipart>=0.0.6

# Utilities
pydantic>=2.5.0,<3.0.0
pydantic-settings>=2.1.0,<3.0.0
redis>=5.0.0,<6.0.0
httpx>=0.25.0,<0.26.0
```

### Step 3: Generate Locked requirements.txt

```bash
cd open-security-[service]
pip-compile --generate-hashes --resolver=backtracking requirements.in
```

**Output** → `requirements.txt` with:
- ✅ Exact versions pinned
- ✅ SHA256 hashes for every package
- ✅ All transitive dependencies included
- ✅ Reproducible across environments

### Step 4: Update Dockerfiles

**Before:**
```dockerfile
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
```

**After:**
```dockerfile
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
```

The `--require-hashes` flag ensures pip **refuses** to install if:
- Package doesn't match hash (tampered/corrupted)
- New dependency added without hash (prevents sneaky additions)

### Step 5: Update Development Workflow

**Add to each service's Makefile:**
```makefile
.PHONY: deps-compile deps-upgrade deps-sync

# Compile locked dependencies from requirements.in
deps-compile:
	pip-compile --generate-hashes --resolver=backtracking requirements.in

# Upgrade dependencies to latest compatible versions
deps-upgrade:
	pip-compile --generate-hashes --resolver=backtracking --upgrade requirements.in

# Sync current environment to match requirements.txt exactly
deps-sync:
	pip-sync requirements.txt
```

**Usage:**
```bash
# After editing requirements.in
make deps-compile

# To upgrade all deps to latest within constraints
make deps-upgrade

# Sync local dev environment
make deps-sync
```

### Step 6: CI/CD Integration

**GitHub Actions workflow** (`.github/workflows/dependency-check.yml`):
```yaml
name: Dependency Security Check

on:
  pull_request:
    paths:
      - '**/requirements.in'
      - '**/requirements.txt'
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2 AM

jobs:
  check-dependencies:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        service:
          - identity
          - tools
          - data
          - guardian
          - responder
          - cspm
          - agents
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install pip-tools
        run: pip install pip-tools pip-audit
      
      - name: Verify requirements.txt is up-to-date
        working-directory: open-security-${{ matrix.service }}
        run: |
          pip-compile --generate-hashes --resolver=backtracking requirements.in --dry-run
          # Fails if requirements.txt doesn't match requirements.in
      
      - name: Security audit
        working-directory: open-security-${{ matrix.service }}
        run: pip-audit -r requirements.txt
```

## Migration Checklist

**For each service:**

- [ ] Install pip-tools: `pip install pip-tools`
- [ ] Create `requirements.in` from current `requirements.txt`
- [ ] Add version constraints to direct dependencies
- [ ] Run `pip-compile --generate-hashes`
- [ ] Update Dockerfile to use `--require-hashes`
- [ ] Add Makefile targets for dependency management
- [ ] Test build: `docker-compose build [service]`
- [ ] Commit both `.in` and `.txt` files
- [ ] Update service README with new workflow

## Service-Specific Notes

### Identity Service
```bash
cd open-security-identity
pip install pip-tools
mv requirements.txt requirements.in
# Edit requirements.in - add version constraints
pip-compile --generate-hashes --resolver=backtracking requirements.in
git add requirements.in requirements.txt
git commit -m "feat(deps): Pin dependencies with hashes for identity service"
```

### Django Services (Guardian, Data)
```bash
cd open-security-guardian
pip install pip-tools
mv requirements.txt requirements.in
# May need separate requirements-dev.in for testing deps
pip-compile --generate-hashes requirements.in
git add requirements.in requirements.txt
```

### Frontend (Dashboard)
**Use package-lock.json** (already hash-verified):
```bash
cd open-security-dashboard
npm ci  # Uses package-lock.json with integrity hashes
```

Already secure! ✅ No action needed for Node.js dependencies.

## Verification

**After implementation, verify:**

```bash
# Check all requirements.txt have hashes
for service in identity tools data guardian responder cspm agents; do
  echo "Checking open-security-$service..."
  grep -q "^--hash=" "open-security-$service/requirements.txt" && \
    echo "✓ Has hashes" || echo "✗ Missing hashes"
done

# Try to build all services
docker-compose build

# Check for vulnerable dependencies
for service in identity tools data guardian responder cspm agents; do
  pip-audit -r "open-security-$service/requirements.txt"
done
```

## Handling Updates

### Updating a Single Dependency

```bash
# Edit requirements.in
vim open-security-identity/requirements.in
# Change: fastapi>=0.104.0,<0.105.0
# To:     fastapi>=0.105.0,<0.106.0

# Regenerate requirements.txt
cd open-security-identity
pip-compile --generate-hashes requirements.in

# Test
docker-compose build identity
docker-compose up -d identity
# Run tests
```

### Monthly Security Updates

```bash
# Upgrade all deps to latest within constraints
for service in identity tools data guardian responder cspm agents; do
  cd "open-security-$service"
  pip-compile --generate-hashes --upgrade requirements.in
  cd ..
done

# Run security audit
for service in identity tools data guardian responder cspm agents; do
  pip-audit -r "open-security-$service/requirements.txt"
done

# Build and test
docker-compose build
docker-compose up -d
# Run integration tests
```

## Benefits Achieved

✅ **Security:**
- Prevents dependency confusion attacks
- Detects package tampering
- No surprise upgrades

✅ **Reliability:**
- Reproducible builds across dev/CI/prod
- Explicit transitive dependencies
- No "works on my machine" issues

✅ **Compliance:**
- Full SBOM (Software Bill of Materials)
- Auditable dependency history
- Meets security tool standards

## Timeline

| Service | Priority | Estimated Time | Assignee |
|---------|----------|----------------|----------|
| identity | P0 | 1 hour | Sprint 2 |
| tools | P0 | 1 hour | Sprint 2 |
| data | P1 | 1 hour | Sprint 2 |
| guardian | P1 | 1 hour | Sprint 2 |
| responder | P2 | 1 hour | Sprint 2 |
| cspm | P2 | 1 hour | Sprint 2 |
| agents | P2 | 1 hour | Sprint 2 |
| **CI/CD** | P0 | 2 hours | Sprint 2 |

**Total:** ~9 hours for complete implementation

## References

- [pip-tools Documentation](https://github.com/jazzband/pip-tools)
- [PEP 665 - Lockfile Specification](https://peps.python.org/pep-0665/)
- [pip-audit](https://pypi.org/project/pip-audit/)
- [SLSA Framework](https://slsa.dev/) - Supply chain security

---

**Next Step:** Start with identity service as proof-of-concept
**Owner:** DevSecOps Team
**Review Date:** After Sprint 2 completion
