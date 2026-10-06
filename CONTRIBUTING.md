# Contributing to Wildbox

We welcome contributions from the security community. This guide will help you get started with contributing to Wildbox.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Code Contribution Process](#code-contribution-process)
- [Contribution Areas](#contribution-areas)
- [Security Contributions](#security-contributions)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Getting Help](#getting-help)

---

## Development Environment Setup

### Prerequisites

- **Docker** with the Compose plugin (`docker compose`)
- **Python** 3.11 (the version CI uses)
- **Node.js** 24 (the dashboard image and CI use node 24 LTS)
- **Git** >= 2.30
- **8GB RAM minimum** (16GB recommended for full stack)

### Initial Setup

```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/YOUR-USERNAME/wildbox.git
cd wildbox

# 3. Add upstream remote
git remote add upstream https://github.com/fabriziosalmi/wildbox.git

# 4. Generate .env with random secrets (also for local development: the
#    services reject short or weak values), set INITIAL_ADMIN_EMAIL in it,
#    then check it
make generate-secrets
make validate-secrets

# 5. Start all services and wait until they report healthy
docker compose up -d --wait --wait-timeout 600

# 6. Verify
curl http://localhost/health
curl http://localhost:8001/health

# 7. Open the dashboard at https://localhost (through the gateway) and log in
#    with INITIAL_ADMIN_EMAIL / INITIAL_ADMIN_PASSWORD from .env
```

### Running Tests

```bash
# Integration tests run in CI via .github/workflows/integration-tests.yml,
# which starts the backend services and runs `pytest tests/integration/`.
# To run them locally, start the stack and point pytest at it:
#   docker compose up -d
#   pytest tests/integration/

# Unit tests for a specific service
cd open-security-identity
pytest tests/

# E2E tests (Playwright; requires running services)
cd open-security-dashboard
npm run test:e2e

# identity's and guardian's suites inside the running containers
make test
```

### Working on Specific Services

```bash
# Frontend development (hot reload enabled)
cd open-security-dashboard
npm install
npm run dev
# Visit http://localhost:3000

# Backend service development (identity example)
cd open-security-identity
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001

# Run migrations
alembic upgrade head

# Create new migration
alembic revision -m "description"
```

---

## Code Contribution Process

### 1. Find or Create an Issue

- Check [existing issues](https://github.com/fabriziosalmi/wildbox/issues)
- For new features, create a feature request first
- Comment on the issue to claim it

### 2. Create a Feature Branch

```bash
# Sync with upstream
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/my-feature-name
# or for bug fixes:
git checkout -b fix/bug-description
```

### 3. Make Changes

- Write clear, focused commits
- Follow the code style guidelines (see below)
- Add tests for new functionality
- Update documentation as needed

### 4. Commit Your Changes

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: <type>(<scope>): <description>
git commit -m "feat(identity): add OAuth2 provider support"
git commit -m "fix(gateway): resolve rate limiting edge case"
git commit -m "docs(api): add authentication examples"
git commit -m "test(agents): add unit tests for analysis engine"
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### 5. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/my-feature-name

# Create PR on GitHub with:
# - Clear title following conventional commits
# - Detailed description of changes
# - Link to related issue(s)
# - Screenshots (if UI changes)
# - Test results
```

### 6. Code Review

- Address reviewer feedback promptly
- Keep the PR scope focused
- Update branch if main has changed: `git rebase upstream/main`

---

## Contribution Areas

### Good First Issues (New Contributors)

- Documentation improvements and typo fixes
- Adding code examples and tutorials
- Writing unit tests for existing code
- Improving error messages
- Adding type hints to Python code
- Creating Docker Compose variations

### Intermediate Contributions

- New SOAR playbook examples
- Additional threat intelligence feed integrations
- Dashboard UI enhancements
- API client libraries (Go, Rust, Java)
- Performance optimizations
- Adding cloud provider connectors

### Advanced Contributions

- Multi-tenancy architecture
- High-availability clustering
- Advanced analytics and ML features
- Custom authentication backends
- Distributed tracing implementation
- Kubernetes operator development

---

## Security Contributions

**Found a security vulnerability?**

**DO NOT create a public GitHub issue.**

Follow our [Security Policy](SECURITY.md):

1. Report it privately on GitHub (Security tab, "Report a vulnerability"), or
   by email to the address in
   [`security.txt`](https://www.wildbox.io/.well-known/security.txt)
2. Include: description, reproduction steps, impact assessment
3. Expect an acknowledgment within 48 hours

---

## Conventions that will bite you

Three rules are load-bearing and were previously discoverable only by reading
source (or by shipping a defect):

1. **Tools are Python packages.** A tool lives at `app/tools/<name>/` with
   `__init__.py`, `main.py` (exporting `execute_tool` and `TOOL_INFO`) and
   `schemas.py`. Import within a tool with relative imports -- `from .schemas
   import X`, `from ..wordlists import load_wordlist` -- and load tools only
   through `app.tool_loader`. Never add a `sys.path` entry: the old loader did,
   which silently disabled one tool's wordlists and made another unloadable.

2. **Integration test classes must be named `Test*` and must not define
   `__init__`.** `pytest.ini` sets `python_classes = Test*`, and pytest cannot
   instantiate a class with a constructor. A class named `FooTester`, or one with
   `__init__`, is collected as zero tests and your suite passes without running
   them. Put setup in `setup_method(self, method)`.

3. **Import the shared package by its installed name**: `from
   open_security_shared.gateway_auth import ...`, never a bare module name with a
   `sys.path` insert. The bare form resolves during local development and fails
   inside the image, where the ImportError branch silently disables whatever it
   guards.

Every service also installs the shared error contract and observability in its
application module:

```python
from open_security_shared.errors import install_error_handlers
from open_security_shared.observability import install_observability

install_error_handlers(app)
install_observability(app, service_name="myservice", service_version=SERVICE_VERSION)
```

## Service Layout

Backend services are FastAPI apps under `open-security-*/`. **`open-security-identity` is the reference layout** — new services and refactors should converge on it:

```text
open-security-<name>/
├── app/
│   ├── main.py          # FastAPI app, routers wired, health endpoint
│   ├── config.py        # Settings (env-driven; no hardcoded secrets)
│   ├── auth.py          # Gateway auth dependency (see note below)
│   ├── database.py      # DB engine/session setup
│   ├── models.py        # ORM models
│   ├── schemas.py       # Pydantic request/response schemas
│   └── api_v1/          # Versioned routers (endpoints grouped by resource)
├── alembic/             # DB migrations (services with their own database)
├── tests/               # Service tests
├── requirements.txt
└── Dockerfile
```

Conventions:

- Authentication goes through the shared gateway dependency
  (`open_security_shared.gateway_auth`); services trust the gateway-stamped
  `X-Wildbox-*` headers and the `GATEWAY_INTERNAL_SECRET` proof-of-origin. Don't
  reimplement auth per service.
- Settings come from the environment via `config.py`; never hardcode secrets,
  ports, or credentials.
- Django services (e.g. `open-security-guardian`) keep their framework layout but
  follow the same env/auth conventions.

The FastAPI services (agents, cspm, data, responder, tools) import the gateway
dependency from the packaged `open_security_shared.gateway_auth`; identity is
the authority the gateway asks, and guardian applies the same headers through
its own Django authentication.

---

## Code Style Guidelines

### Python

- Follow **PEP 8**
- Use **Black** for formatting: `black .`
- Use **isort** for imports: `isort .`
- Use **mypy** for type checking: `mypy .`
- Add type hints to all functions
- Write docstrings in Google style

```python
def process_threat(ioc: str, severity: int) -> ThreatAnalysis:
    """Process and analyze threat indicator.
    
    Args:
        ioc: Indicator of Compromise (IP, domain, hash)
        severity: Severity level (1-10)
        
    Returns:
        ThreatAnalysis object with enriched data
        
    Raises:
        ValueError: If IOC format is invalid
    """
    pass
```

### TypeScript/JavaScript

- Follow project **ESLint** configuration
- Use **Prettier** for formatting: `npm run format`
- Prefer `const` over `let`, avoid `var`
- Use async/await over promises
- Add JSDoc for public functions

```typescript
/**
 * Fetches threat intelligence data from the API
 * @param ioc - Indicator of Compromise
 * @returns Promise resolving to threat data
 * @throws ApiError if request fails
 */
async function fetchThreatData(ioc: string): Promise<ThreatData> {
  // implementation
}
```

### Commit Messages

```bash
# Good
feat(identity): add multi-factor authentication support
fix(gateway): resolve race condition in token refresh
docs(api): document rate limiting behavior

# Bad
update code
fixed bug
changes
```

---

## Testing Requirements

### Required for All PRs

- ✅ All existing tests pass
- ✅ New code has unit tests (>80% coverage)
- ✅ Integration tests for API changes
- ✅ E2E tests for UI changes

### Running Tests Locally

```bash
# Python unit tests, from a service directory
pytest tests/ -v --cov

# Dashboard: there are no JavaScript unit tests; lint and type-check it
cd open-security-dashboard
npm run lint
npm run type-check
cd ..

# Integration tests (run in CI via .github/workflows/integration-tests.yml).
# Locally: start the stack, then run pytest against it.
docker compose up -d
pytest tests/integration/

# E2E tests (Playwright, against the running stack)
cd open-security-dashboard
npm run test:e2e
```

### Writing Tests

```python
# Python test example
import pytest
from app.services.threat_intel import enrich_ioc

def test_enrich_ioc_with_valid_ip():
    """Test IOC enrichment with valid IP address."""
    result = enrich_ioc("8.8.8.8", ioc_type="ip")
    assert result.status == "success"
    assert result.data.asn is not None
```

Dashboard tests are Playwright specs in `open-security-dashboard/tests/e2e/`;
follow an existing spec, such as `team-members.spec.ts`, for logging in and
creating test data.

---

## Getting Help

- **Questions?** [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions)
- **Feature Ideas?** [Ideas Discussion Category](https://github.com/fabriziosalmi/wildbox/discussions/categories/ideas)
- **Found a Bug?** [Create an Issue](https://github.com/fabriziosalmi/wildbox/issues/new?template=bug_report.md)
- **Want to Help?** [Good First Issues](https://github.com/fabriziosalmi/wildbox/labels/good%20first%20issue)

---

## Recognition

Contributors are recognized in:

- Release notes for their contributions
- GitHub contributor graphs
- Community highlights in discussions

Thank you for contributing to Wildbox.
