# Pre-commit Hooks Setup

**Status:** ✅ CONFIGURED  
**Install Time:** 2 minutes

## What Are Pre-commit Hooks?

Git hooks that **automatically run checks before each commit**, preventing:
- ❌ Debug statements (`console.log`, `print()`) in production code
- ❌ Hardcoded secrets/passwords
- ❌ Trailing whitespace and formatting issues
- ❌ Large files (>1MB) being committed
- ❌ Python/TypeScript linting errors
- ❌ Security vulnerabilities (via bandit)

## Quick Start

### 1. Install pre-commit

**macOS/Linux:**
```bash
pip install pre-commit
# or
brew install pre-commit
```

**Verify:**
```bash
pre-commit --version
# Should show: pre-commit 3.x.x
```

### 2. Install hooks in repository

```bash
cd /Users/fab/GitHub/wildbox
pre-commit install
```

**Output:**
```
pre-commit installed at .git/hooks/pre-commit
```

### 3. (Optional) Run on all files now

```bash
pre-commit run --all-files
```

**This will:**
- Format all Python files with Black
- Sort imports with isort
- Run flake8 linting
- Check for secrets
- Format TypeScript/JS with Prettier
- Run ESLint
- ... and 15+ more checks

**First run takes 2-5 minutes** (installs hook environments).  
Subsequent commits are fast (<10 seconds).

## What Happens on Each Commit

**Before (old workflow):**
```bash
git add .
git commit -m "Quick fix"
# ✓ Committed (might have debug code, secrets, etc.)
```

**After (with pre-commit):**
```bash
git add .
git commit -m "Quick fix"

# Pre-commit runs automatically:
Trim Trailing Whitespace...................Passed
Fix End of Files...........................Passed
Check Yaml.................................Passed
Check for added large files................Passed
Check JSON.................................Passed
Detect Private Key.........................Passed
black......................................Failed
- hook id: black
- files were modified by this hook

reformatted open-security-identity/app/auth.py

Prevent debug statements...................Failed
- hook id: prevent-debug-statements
- exit code: 1

open-security-dashboard/src/lib/api-client.ts:32:  console.log('Debug info')

# ❌ Commit blocked! Fix issues first.
```

**Fix and retry:**
```bash
# Remove the console.log
vim open-security-dashboard/src/lib/api-client.ts
# Black already auto-fixed formatting

git add .
git commit -m "Quick fix"
# ✓ All checks passed - commit successful
```

## Configured Checks

### Python Checks
- **Black** - Code formatter (120 char lines)
- **isort** - Import sorting
- **Flake8** - Linting (PEP 8 compliance)
- **Bandit** - Security vulnerability scanner
- **Detect-secrets** - Finds hardcoded credentials

### TypeScript/JavaScript Checks
- **Prettier** - Code formatter
- **ESLint** - Linting (Next.js config)

### General Checks
- **Trailing whitespace** removal
- **End-of-file** fixer (ensures newline)
- **Large files** blocker (>1MB)
- **YAML/JSON** syntax validation
- **Private key** detection
- **Merge conflict** markers
- **Dockerfile** linting (hadolint)
- **Shell script** linting (shellcheck)

### Custom Checks
- **Prevent debug statements** - Blocks `console.log`, `print()`
- **Prevent hardcoded secrets** - Regex for password/token patterns
- **Requirements sync** - Ensures `requirements.txt` matches `.in`

## Bypassing Hooks (Emergency Only)

**If absolutely necessary:**
```bash
git commit --no-verify -m "Emergency hotfix"
```

⚠️ **WARNING**: Only use for critical production issues. CI/CD will still catch violations.

## Skipping Specific Checks

**Temporary skip for one commit:**
```bash
SKIP=black,flake8 git commit -m "WIP: refactoring"
```

**Permanent skip in config:**
Edit `.pre-commit-config.yaml` and remove the hook.

## Updating Hooks

**Check for updates:**
```bash
pre-commit autoupdate
```

**Manually update to specific version:**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 24.1.0  # Update version here
```

## Troubleshooting

### "command not found: pre-commit"
```bash
pip install --user pre-commit
# Add ~/.local/bin to PATH
export PATH="$HOME/.local/bin:$PATH"
```

### "Hook failed with code 127"
```bash
# Reinstall hooks
pre-commit clean
pre-commit install
pre-commit run --all-files
```

### "ESLint cannot find module"
```bash
cd open-security-dashboard
npm install
cd ..
pre-commit run eslint --all-files
```

### "Detect-secrets baseline missing"
```bash
# Generate initial baseline
detect-secrets scan > .secrets.baseline
git add .secrets.baseline
```

## CI/CD Integration

**GitHub Actions already runs these checks!**

See `.github/workflows/lint.yml`:
```yaml
- name: Run pre-commit
  run: pre-commit run --all-files --show-diff-on-failure
```

Even if you bypass locally, CI will catch violations and fail the build.

## Configuration Files

| File | Purpose |
|------|---------|
| `.pre-commit-config.yaml` | Hook configuration |
| `.secrets.baseline` | Known false-positive secrets |
| `pyproject.toml` | Black/isort settings (if exists) |
| `.flake8` | Flake8 configuration (if exists) |
| `.eslintrc.json` | ESLint rules (in dashboard/) |

## Performance

**Initial setup:** ~3-5 minutes (downloads hook environments)  
**Per commit:** ~5-15 seconds (only runs on changed files)  
**Full repo scan:** ~60-90 seconds (`pre-commit run --all-files`)

**Tips for speed:**
- Hooks only run on staged files by default
- Use `--no-verify` sparingly
- Keep hook environments updated: `pre-commit gc`

## Benefits

✅ **Prevents issues before they reach code review**  
✅ **Automatic formatting** - no more "fix whitespace" comments  
✅ **Security enforcement** - catches secrets/vulnerabilities early  
✅ **Consistent code style** across all contributors  
✅ **Faster CI/CD** - fewer lint failures in CI  
✅ **Educational** - teaches best practices through feedback

## Team Adoption

**For new contributors:**
1. Clone repo
2. `pip install pre-commit`
3. `pre-commit install`
4. Done!

**Include in onboarding docs:**
```markdown
## Setup Development Environment

1. Clone repository
2. Install pre-commit: `pip install pre-commit`
3. Enable hooks: `pre-commit install`
4. Run initial check: `pre-commit run --all-files`
```

## Example Output

**Successful commit:**
```
$ git commit -m "feat: Add new API endpoint"

Trim Trailing Whitespace...................Passed
Fix End of Files...........................Passed
Check Yaml.................................Passed
black......................................Passed
isort......................................Passed
flake8.....................................Passed
bandit.....................................Passed
detect-secrets.............................Passed
Prevent debug statements...................Passed
Prevent hardcoded secrets..................Passed

[main abc1234] feat: Add new API endpoint
 3 files changed, 45 insertions(+), 2 deletions(-)
```

**Failed commit (needs fixes):**
```
$ git commit -m "WIP: testing"

black......................................Failed
- hook id: black
- files were modified by this hook

reformatted app/auth.py
All done! ✨ 🍰 ✨
1 file reformatted.

Prevent debug statements...................Failed
- hook id: prevent-debug-statements
- exit code: 1

app/api.py:45:    print("Debug info")
app/api.py:67:    console.log('Testing')

# Fix these issues and try again
```

---

**Setup Status:** ✅ Configured and ready  
**Team Adoption:** Recommended for all contributors  
**CI Enforcement:** Active in GitHub Actions
