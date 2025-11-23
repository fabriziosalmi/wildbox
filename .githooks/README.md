# Git Hooks Installation

This directory contains git hooks to enhance security and prevent accidental secret commits.

## Installation

Git hooks in this directory are not automatically active. You need to either:

### Option 1: Copy to .git/hooks (Manual)

```bash
cp .githooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Option 2: Configure Git to Use This Directory (Recommended)

```bash
git config core.hooksPath .githooks
```

This will make Git use hooks from `.githooks/` directory instead of `.git/hooks/`.

## Available Hooks

### pre-commit

**Purpose:** Prevent secrets from being committed to the repository.

**Checks:**
1. ✅ Blocks .env files from being committed
2. ✅ Scans for common secret patterns (API keys, tokens, passwords)
3. ✅ Detects JWT tokens
4. ✅ Detects AWS access keys
5. ✅ Detects private keys
6. ✅ Detects database connection strings with passwords
7. ✅ Detects Stripe API keys
8. ✅ Ensures .env.example files only contain placeholders
9. ✅ Warns about hardcoded secrets in docker-compose files

**Bypass (Not Recommended):**
```bash
git commit --no-verify -m "message"
```

## Testing the Hook

After installation, test it by:

```bash
# Try to commit a fake .env file
echo "SECRET_KEY=test" > test.env
git add test.env
git commit -m "test"
# Should be blocked

# Clean up
git reset HEAD test.env
rm test.env
```

## Maintenance

If you update hooks in `.githooks/`, contributors will need to:

1. Pull the changes
2. Re-run the installation command (if using Option 2, this is automatic)

---

**Note:** These hooks run locally on each developer's machine. They provide a safety net but are not a substitute for:
- Proper `.gitignore` configuration
- Code review processes
- Automated secret scanning in CI/CD
- Security awareness training
