# Pre-commit Hooks Setup

**Status:** ✅ CONFIGURED  
**Install Time:** 2 minutes

## What Are Pre-commit Hooks?

Git hooks that **automatically run checks before each commit**, preventing:

- ❌ Debug statements (`console.log`, `print()`) in production code
- ❌ Hardcoded secrets/passwords
- ❌ Trailing whitespace and formatting issues
- ❌ Large files (>1MB) being committed
- ❌ Python formatting and lint errors (Black, isort, Flake8)
- ❌ Shell script errors (ShellCheck)

The hooks are opt-in: they run only in a clone where someone ran
`pre-commit install`, and no CI workflow runs them. See
[CI Coverage](#ci-coverage) for what CI checks instead.

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
cd wildbox   # the repository root
pre-commit install
```

**Output:**

```text
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
- Check for secrets against `.secrets.baseline`
- Run ShellCheck on shell scripts
- Run the general file checks listed below

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

This is the complete list in `.pre-commit-config.yaml`. Files under
`migrations/`, `node_modules/`, `.next/`, virtual environments and
`*-lock.json` are excluded globally.

### General Checks (pre-commit-hooks v4.5.0)

- **trailing-whitespace** (skips `.md` files)
- **end-of-file-fixer**
- **check-yaml** (with `--unsafe`, so custom tags are accepted)
- **check-added-large-files** (over 1000 KB)
- **check-json**
- **check-merge-conflict**
- **detect-private-key** (skips `tests/fixtures/`)
- **mixed-line-ending** (rewrites to LF)

### Python Checks

- **Black** 23.12.1 - Code formatter
- **isort** 5.13.2 - Import sorting, Black profile
- **Flake8** 6.1.0 - `--max-line-length=120`, ignores E203, W503 and E501

### Secrets

- **detect-secrets** v1.4.0 - Compares against `.secrets.baseline`; skips
  `package-lock.json`, `.env.example` and `requirements.txt`

### Shell Scripts

- **ShellCheck** (shellcheck-py v0.9.0.6) - Severity `warning` and above

### Custom Checks

- **Prevent debug statements** - Fails on `console.log` or `print(` in
  `.py`, `.js`, `.ts`, `.jsx` and `.tsx` files, except test files

There is no Bandit, Prettier, ESLint or hadolint hook. ESLint runs in the
dashboard with `npm run lint` (`open-security-dashboard/eslint.config.mjs`).

A separate, older hook script lives in `.githooks/pre-commit` (it blocks
`.env` files and scans staged changes for secret patterns). It runs only if
you set `git config core.hooksPath .githooks`; git then ignores the hook in
`.git/hooks` that `pre-commit install` writes, so use one or the other.

## Bypassing Hooks (Emergency Only)

**Only when there is no alternative:**

```bash
git commit --no-verify -m "Emergency hotfix"
```

⚠️ **WARNING**: Only use for critical production issues. CI does not run these hooks; only its own checks (see [CI Coverage](#ci-coverage)) apply.

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

### detect-secrets flags a file that was only moved or renamed

`.secrets.baseline` records findings by file path, so a known false positive
in a moved file is reported again under its new path. Refresh the baseline
and review the diff before committing it:

```bash
detect-secrets scan --baseline .secrets.baseline
git diff .secrets.baseline
```

## CI Coverage

No GitHub Actions workflow runs `pre-commit`, so a commit made with
`--no-verify`, or from a clone without the hooks, is not caught by these
hooks. CI has its own, different checks, among them:

- **Gitleaks** (`.github/workflows/secret-scan.yml`) scans the checked-out
  tree for secrets on every pull request and on pushes to `main`.
- **Security Scanning** (`.github/workflows/test.yml`) runs Trivy and Bandit;
  Bandit reports to code scanning and does not gate.
- **Documentation Quality** (`.github/workflows/documentation-quality.yml`)
  runs markdownlint, cspell and proselint on Markdown files.

## Configuration Files

| File | Purpose |
| ------ | --------- |
| `.pre-commit-config.yaml` | Hook configuration |
| `.secrets.baseline` | Known false-positive secrets |
| `.githooks/pre-commit` | Optional standalone hook (see above) |
| `open-security-dashboard/eslint.config.mjs` | Dashboard ESLint rules (not a hook) |

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
✅ **Fewer surprises in review**  
✅ **Educational** - teaches best practices through feedback

## Team Adoption

**For new contributors:**

1. Clone repo
2. `pip install pre-commit`
3. `pre-commit install`
4. Done.

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

```bash
$ git commit -m "feat: Add new API endpoint"

Trim Trailing Whitespace...................Passed
Fix End of Files...........................Passed
Check Yaml.................................Passed
black......................................Passed
isort......................................Passed
flake8.....................................Passed
detect-secrets.............................Passed
Prevent debug statements...................Passed

[main abc1234] feat: Add new API endpoint
 3 files changed, 45 insertions(+), 2 deletions(-)
```

**Failed commit (needs fixes):**

```bash
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
**CI Enforcement:** None; the hooks run locally only
