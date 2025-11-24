# Git Commit Squash Strategy

**Purpose**: Clean up git history by consolidating related commits into logical units. This improves code review, bisectability, and project professionalism.

## Why Squash Commits?

### Bad Commit History (Current State)
```
fix
fix
fix typo
actually fix
fix the fix
fix
WIP
fix tests
```

**Problems**:
- Unprofessional appearance
- Difficult to identify what changed in each commit
- Impossible to bisect bugs
- Clutters `git log` output

### Good Commit History (Target State)
```
feat(identity): Add API key expiration and rotation
fix(gateway): Resolve upstream timeout on service restart  
refactor(admin): Extract SystemHealth and StatsCards components
docs: Add service lifecycle and secrets rotation guides
```

**Benefits**:
- Clear, descriptive commit messages
- Each commit represents a logical unit of work
- Easy to understand project evolution
- Enables effective `git bisect` for debugging

## Interactive Rebase Workflow

### Step 1: Identify Commits to Squash

```bash
# View last 20 commits
git log --oneline -20

# Example output:
# a1b2c3d fix
# e4f5g6h fix
# i7j8k9l fix tests
# m0n1o2p actually fix the thing
# q3r4s5t Add feature X
```

### Step 2: Start Interactive Rebase

```bash
# Squash last 20 commits
git rebase -i HEAD~20

# Or rebase from specific commit
git rebase -i q3r4s5t^
```

This opens your editor with:
```
pick q3r4s5t Add feature X
pick m0n1o2p actually fix the thing
pick i7j8k9l fix tests
pick e4f5g6h fix
pick a1b2c3d fix

# Rebase instructions:
# p, pick = use commit
# r, reword = use commit, but edit message
# e, edit = use commit, but stop for amending
# s, squash = use commit, but meld into previous commit
# f, fixup = like "squash", but discard this commit's log message
# d, drop = remove commit
```

### Step 3: Mark Commits for Squashing

**Change to**:
```
pick q3r4s5t Add feature X
fixup m0n1o2p actually fix the thing
fixup i7j8k9l fix tests
fixup e4f5g6h fix
fixup a1b2c3d fix
```

Or use `squash` (alias `s`) to preserve commit messages for editing:
```
pick q3r4s5t Add feature X
squash m0n1o2p actually fix the thing
squash i7j8k9l fix tests
```

**Difference**:
- `fixup` (f): Discards commit message, only keeps code changes
- `squash` (s): Opens editor to combine/edit all commit messages

### Step 4: Edit Combined Commit Message

If using `squash`, editor opens with all messages:
```
# This is a combination of 5 commits.
# The first commit's message is:
Add feature X

# This is the 2nd commit message:
actually fix the thing

# This is the 3rd commit message:
fix tests

# Please enter the commit message for your changes. Lines starting
# with '#' will be ignored, and an empty message aborts the commit.
```

**Replace with clean message**:
```
feat(identity): Add API key expiration and auto-rotation

- Implement 90-day expiration policy for API keys
- Add automatic rotation workflow with email notifications
- Update database schema with expiry_date column
- Add tests for expiration logic

Resolves #47
```

### Step 5: Complete Rebase

```bash
# Save and exit editor
# Git will replay commits

# If conflicts occur:
git status
# Fix conflicts in files
git add <conflicted-files>
git rebase --continue

# If you mess up:
git rebase --abort  # Start over
```

### Step 6: Force Push (DANGER)

```bash
# WARNING: Rewrites history. Coordinate with team first!
git push --force-with-lease origin main

# Safer alternative (fails if remote has new commits):
git push --force-with-lease origin main
```

## Conventional Commits Format

Use structured commit messages for automated changelog generation:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code restructuring without behavior change
- `test`: Add or modify tests
- `chore`: Build process, dependencies, tooling
- `perf`: Performance improvement
- `ci`: CI/CD configuration changes

### Scopes (Wildbox-specific)
- `identity`: Identity service
- `gateway`: API gateway
- `tools`: Security tools service
- `data`: Threat intelligence service
- `guardian`: Vulnerability management
- `dashboard`: Frontend
- `admin`: Admin panel
- `deps`: Dependency updates

### Examples

```bash
# Feature
feat(tools): Add DNS zone transfer detection

Implement AXFR request detection in DNS enumeration tool.
Includes wildcard subdomain expansion and rate limiting.

Resolves #123

# Bug fix
fix(gateway): Prevent race condition in auth header injection

Lua auth handler was clearing headers before backend injection.
Now uses ngx.ctx to preserve authentication context.

Fixes #456

# Refactoring
refactor(admin): Extract AdminPage into atomic components

- Create SystemHealth component for service status
- Create SystemStatsCards for metrics display  
- Create useSystemStats hook for data fetching
- Separate presentation from data logic

Improves testability and reduces component complexity from 1174 to ~300 lines.

# Documentation
docs: Add service lifecycle and secrets rotation guides

Document service startup order, health checks, and decommissioning process.
Add critical secrets rotation procedure after git history exposure.

# Chore
chore(deps): Pin Python dependencies to exact versions

Replace unpinned requirements with locked versions to prevent
supply chain attacks and ensure reproducible builds.
```

## Squash Strategies by Situation

### Daily WIP Commits (Squash Before PR)
```bash
# You made 10 commits while developing feature
git rebase -i HEAD~10

# Squash all into 1-3 logical commits
pick <first-commit>
fixup <all-other-commits>
```

### Fixing PR Review Comments
```bash
# Don't create "Address review comments" commits
# Squash fixes into original commits

git rebase -i origin/main
# Mark review fix commits as fixup into original feature commits
```

### Hotfix Commits
```bash
# Emergency production fix had multiple attempts
git rebase -i HEAD~5

# Squash into single commit
pick <initial-fix>
fixup <fix-the-fix>
fixup <actually-fix>
```

## Automated Squash via GitHub/GitLab

### GitHub: Squash and Merge
When merging PR, select "Squash and merge":
- All commits squashed into one
- Preserves PR number in commit message
- Clean main branch history

### Pre-Merge Squash Script
```bash
#!/bin/bash
# scripts/squash-branch.sh

MAIN_BRANCH="main"
CURRENT_BRANCH=$(git branch --show-current)

# Fetch latest main
git fetch origin $MAIN_BRANCH

# Count commits ahead of main
COMMITS_AHEAD=$(git rev-list --count origin/$MAIN_BRANCH..$CURRENT_BRANCH)

echo "Squashing $COMMITS_AHEAD commits on $CURRENT_BRANCH"

# Interactive rebase from main
git rebase -i origin/$MAIN_BRANCH

echo "Squash complete. Force push with: git push --force-with-lease origin $CURRENT_BRANCH"
```

## Pre-Commit Hook to Enforce Commit Message Format

```bash
#!/bin/bash
# .git/hooks/commit-msg

commit_msg_file=$1
commit_msg=$(cat "$commit_msg_file")

# Check for conventional commit format
if ! echo "$commit_msg" | grep -qE "^(feat|fix|docs|refactor|test|chore|perf|ci)(\(.+\))?: .+"; then
    echo "ERROR: Commit message does not follow Conventional Commits format"
    echo ""
    echo "Format: <type>(<scope>): <subject>"
    echo ""
    echo "Valid types: feat, fix, docs, refactor, test, chore, perf, ci"
    echo "Example: feat(identity): Add API key rotation"
    echo ""
    echo "Your message: $commit_msg"
    exit 1
fi

# Check message length
if [ ${#commit_msg} -lt 10 ]; then
    echo "ERROR: Commit message too short (minimum 10 characters)"
    exit 1
fi
```

Install:
```bash
chmod +x .git/hooks/commit-msg
```

## Common Mistakes to Avoid

### ❌ Squashing Already-Pushed Commits Without Team Coordination
- Causes conflicts for teammates
- Use `--force-with-lease` instead of `--force`
- Notify team before force-pushing

### ❌ Squashing Too Much
- Don't squash unrelated changes
- Each commit should be atomic (one logical change)
- Bad: Squash feature + unrelated bug fix
- Good: Separate commits for feature and bug fix

### ❌ Losing Important Context
- Use `squash` instead of `fixup` when commit messages have value
- Preserve issue/ticket references
- Include co-authors if applicable

### ❌ Rebasing Public/Protected Branches
- Never rebase `main` or `production`
- Only rebase feature branches before merge

## Recovery from Bad Squash

### If Rebase Goes Wrong
```bash
# Abort during rebase
git rebase --abort

# Undo completed rebase (within 30 days)
git reflog
# Find pre-rebase commit SHA (e.g., abc123)
git reset --hard abc123
```

### If Already Force-Pushed
```bash
# Find previous state in reflog
git reflog

# Example reflog output:
# abc123 HEAD@{0}: rebase -i (finish): returning to refs/heads/feature
# def456 HEAD@{1}: rebase -i (start): checkout HEAD~20

# Reset to before rebase
git reset --hard def456
git push --force-with-lease origin feature
```

## Team Workflow Recommendations

1. **Feature Branches**: Squash before merging to main
2. **Main Branch**: Never squash, always linear history
3. **Release Branches**: No rebasing, only merges
4. **Hotfixes**: Squash immediately after fix is verified
5. **Documentation**: Squash typo fixes, keep substantial changes separate

## CI Integration

Add to `.github/workflows/pr-checks.yml`:

```yaml
name: Commit Message Validation

on: [pull_request]

jobs:
  commitlint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for commitlint
          
      - uses: wagoid/commitlint-github-action@v5
        with:
          configFile: .commitlintrc.json
```

`.commitlintrc.json`:
```json
{
  "extends": ["@commitlint/config-conventional"],
  "rules": {
    "scope-enum": [2, "always", [
      "identity", "gateway", "tools", "data", "guardian",
      "dashboard", "admin", "deps", "ci"
    ]]
  }
}
```

---

**Last Updated**: 2025-11-24  
**Related**:
- [Conventional Commits Spec](https://www.conventionalcommits.org/)
- [Git Documentation - Rewriting History](https://git-scm.com/book/en/v2/Git-Tools-Rewriting-History)
- Project: `CONTRIBUTING.md` (commit message guidelines)
