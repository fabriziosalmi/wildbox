# GitHub Actions CI Configuration

## Issue: Missing Required Environment Variables

The CI workflow is correctly validating that all required secrets are present. However, GitHub Actions needs these secrets configured.

## Error Messages
```
time="2025-11-23T17:59:35Z" level=warning msg="The \"DATABASE_URL\" variable is not set. Defaulting to a blank string."
time="2025-11-23T17:59:35Z" level=warning msg="The \"NEXTAUTH_SECRET\" variable is not set. Defaulting to a blank string."
error while interpolating services.dashboard.environment.[]: required variable NEXTAUTH_SECRET is missing a value
```

## Solution: Configure GitHub Secrets

### Required Secrets for CI

Navigate to: `https://github.com/fabriziosalmi/wildbox/settings/secrets/actions`

Add the following secrets:

#### Critical Secrets (Generate locally first)
```bash
# Generate all secrets
cd /Users/fab/GitHub/wildbox
make generate-secrets

# View generated values (DO NOT commit this file!)
cat .env
```

Then add to GitHub Actions Secrets:

| Secret Name | How to Generate | Example Format |
|-------------|----------------|----------------|
| `JWT_SECRET_KEY` | `openssl rand -hex 32` | 64-char hex string |
| `POSTGRES_PASSWORD` | `openssl rand -base64 32` | 43-char base64 string |
| `GATEWAY_INTERNAL_SECRET` | `openssl rand -hex 32` | 64-char hex string |
| `API_KEY` | `echo "wsk_test.$(openssl rand -hex 32)"` | wsk_test.<64-char-hex> |
| `INITIAL_ADMIN_PASSWORD` | `openssl rand -base64 24` | 32-char base64 string |
| `NEXTAUTH_SECRET` | `openssl rand -base64 32` | 43-char base64 string |
| `N8N_BASIC_AUTH_PASSWORD` | `openssl rand -base64 16` | 22-char base64 string |

#### Database URLs (Constructed)
```bash
# Use the POSTGRES_PASSWORD from above
DATABASE_URL=postgresql+asyncpg://postgres:YOUR_POSTGRES_PASSWORD@postgres:5432/identity
DATA_DATABASE_URL=postgresql://postgres:YOUR_POSTGRES_PASSWORD@postgres:5432/data
GUARDIAN_DATABASE_URL=postgresql://postgres:YOUR_POSTGRES_PASSWORD@postgres:5432/guardian
RESPONDER_DATABASE_URL=postgresql+asyncpg://postgres:YOUR_POSTGRES_PASSWORD@postgres:5432/responder
```

#### Other Required Variables
```bash
REDIS_URL=redis://wildbox-redis:6379/0
INITIAL_ADMIN_EMAIL=admin@wildbox.security
CREATE_INITIAL_ADMIN=true
N8N_BASIC_AUTH_USER=admin
```

#### Optional Secrets (Can be blank for CI)
```bash
STRIPE_SECRET_KEY=
STRIPE_PUBLISHABLE_KEY=
STRIPE_WEBHOOK_SECRET=
GRAFANA_ADMIN_PASSWORD=
```

---

## Alternative: Use Repository Environment File

Instead of individual secrets, create a `.env` file in GitHub Actions:

### Step 1: Create Local .env
```bash
cd /Users/fab/GitHub/wildbox
make generate-secrets
```

### Step 2: Base64 Encode It
```bash
cat .env | base64 > env.base64
```

### Step 3: Add as GitHub Secret
1. Go to: https://github.com/fabriziosalmi/wildbox/settings/secrets/actions
2. Create new secret: `DOTENV_BASE64`
3. Paste contents of `env.base64`

### Step 4: Update Workflow

Add this step to `.github/workflows/integration-tests.yml` **before** "Validate docker-compose.yml":

```yaml
- name: Create .env file from secret
  run: |
    echo "${{ secrets.DOTENV_BASE64 }}" | base64 --decode > .env
    echo "✓ .env file created"
```

---

## Quick Fix for Current CI Run

### Option 1: Add Minimal Secrets (Fastest)

Add only these 7 secrets to get CI passing:

```bash
# Generate on your machine:
openssl rand -hex 32  # For JWT_SECRET_KEY
openssl rand -base64 32  # For POSTGRES_PASSWORD
openssl rand -hex 32  # For GATEWAY_INTERNAL_SECRET
echo "wsk_ci.$(openssl rand -hex 32)"  # For API_KEY
openssl rand -base64 24  # For INITIAL_ADMIN_PASSWORD
openssl rand -base64 32  # For NEXTAUTH_SECRET
openssl rand -base64 16  # For N8N_BASIC_AUTH_PASSWORD
```

Then construct DATABASE_URLs using the POSTGRES_PASSWORD above.

### Option 2: Use Example Values (Testing Only)

**⚠️ WARNING**: Only for CI testing, NEVER for production!

```bash
JWT_SECRET_KEY=0000000000000000000000000000000000000000000000000000000000000000
POSTGRES_PASSWORD=ci_test_postgres_password_change_in_production
GATEWAY_INTERNAL_SECRET=1111111111111111111111111111111111111111111111111111111111111111
API_KEY=wsk_cits.2222222222222222222222222222222222222222222222222222222222222222
INITIAL_ADMIN_PASSWORD=ci_test_admin_password
NEXTAUTH_SECRET=ci_test_nextauth_secret_value_here
N8N_BASIC_AUTH_PASSWORD=ci_test_n8n_password
```

---

## Verification

After adding secrets, the CI workflow should:

1. ✅ `docker-compose config --quiet` - No warnings
2. ✅ Services start successfully
3. ✅ `./scripts/wait-for-services.sh` - All services healthy
4. ✅ `pytest tests/integration/` - Tests pass

---

## Security Notes

1. **Never commit `.env` file** - Already in `.gitignore`
2. **Rotate secrets regularly** - Especially after testing
3. **Use different secrets for CI vs production** - Separate environments
4. **Validate with**: `make validate-secrets` before deployment

---

**Related Files**:
- `.env.template` - Template with all required variables
- `scripts/generate_secrets.py` - Automated secret generation
- `scripts/validate_secrets.py` - Security validation
- `.github/workflows/integration-tests.yml` - CI workflow

**Status**: Commit `9d2e85c` fixes docker-compose.yml patterns, but CI still needs secrets configured.
