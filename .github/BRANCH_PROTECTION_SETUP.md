# Branch Protection Setup Guide

This guide explains how to set up branch protection rules to prevent breaking changes from being merged directly into the `main` branch.

## Why Branch Protection?

Branch protection ensures:
- All changes go through pull requests
- Automated tests must pass before merging
- Critical files cannot be accidentally deleted
- Code review is enforced
- Main branch stays stable and deployable

## Setting Up Branch Protection on GitHub

### Step 1: Navigate to Repository Settings

1. Go to your repository on GitHub
2. Click on **Settings** tab
3. Click on **Branches** in the left sidebar
4. Click **Add rule** button

### Step 2: Configure Protection Rules for `main` Branch

Configure the following settings:

#### Branch name pattern
```
main
```

#### Protect matching branches

Enable these options:

- ✅ **Require a pull request before merging**
  - ✅ Require approvals: **1** (or more for critical repos)
  - ✅ Dismiss stale pull request approvals when new commits are pushed
  - ✅ Require review from Code Owners (if you have CODEOWNERS file)

- ✅ **Require status checks to pass before merging**
  - ✅ Require branches to be up to date before merging
  - **Select required status checks:**
    - `Validate Docker Compose`
    - `Validate Project Structure`
    - `Security Scan`
    - `Python Code Quality`
    - `Integration Tests`
    - `PR Validation Summary`

- ✅ **Require conversation resolution before merging**
  - All PR comments must be resolved

- ✅ **Require linear history**
  - Prevents merge commits, enforces rebase or squash

- ✅ **Do not allow bypassing the above settings**
  - Even admins must follow these rules

- ✅ **Restrict who can push to matching branches**
  - Add specific users/teams who can push (usually CI/CD only)

- ❌ **Allow force pushes** - Leave UNCHECKED
- ❌ **Allow deletions** - Leave UNCHECKED

### Step 3: Save Changes

Click **Create** or **Save changes** button at the bottom.

## Protection for `develop` Branch (Optional)

For a more robust workflow, also protect the `develop` branch:

1. Create another rule with pattern: `develop`
2. Use similar settings but may allow:
   - Fewer required approvals (maybe 0-1)
   - Slightly relaxed checks
   - More people can push

## Testing Branch Protection

After setup, test by trying to:

1. **Direct push to main** (should fail):
   ```bash
   git checkout main
   git commit --allow-empty -m "test"
   git push
   # Should get: remote: error: GH006: Protected branch update failed
   ```

2. **Create PR** (should succeed):
   ```bash
   git checkout -b test-branch
   git commit --allow-empty -m "test"
   git push -u origin test-branch
   # Then create PR on GitHub - should work
   ```

## GitHub Actions Required

The following workflow must exist and be enabled:
- `.github/workflows/pr-validation.yml` ✓ (Already created)

## PR Workflow

With branch protection enabled:

### 1. Create Feature Branch
```bash
git checkout -b feature/your-feature-name
# Make changes
git add .
git commit -m "Description of changes"
git push -u origin feature/your-feature-name
```

### 2. Create Pull Request
- Go to GitHub and create a PR from your branch to `main`
- Add description explaining changes
- Request reviewers if needed

### 3. Automated Checks Run
- Docker validation
- Project structure validation
- Security scanning
- Python code quality checks
- Integration tests

### 4. Review and Fix
- If checks fail, fix issues in your branch
- Push fixes (checks will re-run automatically)
- Resolve any review comments

### 5. Merge
- Once all checks pass and reviews are approved
- Click "Squash and merge" or "Rebase and merge"
- Delete the feature branch after merge

## Monitoring

### View Protection Status
- Go to Settings → Branches
- See active rules and their configuration

### View Failed Checks
- In any PR, scroll to "Checks" section
- Click on failed check to see details
- Review logs to understand failure

### Override Protection (Emergency Only)
If you must override protection:
1. Temporarily disable the rule in Settings → Branches
2. Make the urgent change
3. **Immediately re-enable the rule**
4. Document why override was needed

## Common Issues and Solutions

### Issue: "Required status check is expected"
**Solution:** Push a commit to trigger the workflow

### Issue: "Branch is out of date"
**Solution:** Update your branch:
```bash
git checkout your-branch
git fetch origin
git rebase origin/main
git push --force-with-lease
```

### Issue: "Checks are taking too long"
**Solution:** Check GitHub Actions status page, or cancel and re-trigger

### Issue: "I need to push to main urgently"
**Solution:** Don't. Use branch protection override process above, but this should be extremely rare.

## Best Practices

1. **Always work in feature branches**
2. **Keep branches small and focused**
3. **Commit often, push frequently**
4. **Write clear commit messages**
5. **Test locally before pushing**
6. **Keep PRs small (< 400 lines changed)**
7. **Review your own PR before requesting review**
8. **Run `docker-compose config` before committing docker-compose.yml**

## Additional Security

Consider also:
- **CODEOWNERS file** - Auto-assign reviewers for specific paths
- **Required signed commits** - Ensure commit authenticity
- **Dependabot** - Auto-update dependencies
- **Secret scanning** - Detect committed secrets
- **Code scanning** - Static analysis security testing

## Resources

- [GitHub Branch Protection Docs](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Docker Compose Best Practices](https://docs.docker.com/compose/production/)
