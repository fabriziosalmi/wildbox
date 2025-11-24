# 🤝 Contributing to Wildbox

We welcome contributions from the security community! This guide will help you get started with contributing to Wildbox.

## 📋 Table of Contents

- [Development Environment Setup](#-development-environment-setup)
- [Code Contribution Process](#-code-contribution-process)
- [Contribution Areas](#-contribution-areas)
- [Security Contributions](#-security-contributions)
- [Code Style Guidelines](#-code-style-guidelines)
- [Testing Requirements](#-testing-requirements)
- [Getting Help](#-getting-help)

---

## 🛠️ Development Environment Setup

### Prerequisites

- **Docker** >= 20.10 and Docker Compose >= 2.0
- **Python** >= 3.11 (for local development/testing)
- **Node.js** >= 18.0 (for dashboard development)
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

# 4. Create environment file
cp .env.example .env

# 5. Generate development secrets
# Use weak secrets for local dev, but NEVER in production
echo "JWT_SECRET_KEY=dev-secret-change-in-production" >> .env
echo "DATABASE_PASSWORD=dev-password" >> .env
echo "GATEWAY_INTERNAL_SECRET=dev-gateway-secret" >> .env

# 6. Start all services
docker-compose up -d

# 7. Wait for services to initialize (2-3 minutes)
docker-compose logs -f identity gateway

# 8. Verify services are running
curl http://localhost/health
curl http://localhost:8001/health

# 9. Access the dashboard
# Open http://localhost:3000
# Login: admin@wildbox.security / CHANGE-THIS-PASSWORD
```

### Running Tests

```bash
# Integration tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit

# Unit tests for a specific service
cd open-security-identity
pytest tests/

# E2E tests (requires running services)
cd open-security-dashboard
npm test

# Run all tests
make test  # See Makefile for all test commands
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

## 💻 Code Contribution Process

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

## 💡 Contribution Areas

### 🟢 Good First Issues (New Contributors)

- Documentation improvements and typo fixes
- Adding code examples and tutorials
- Writing unit tests for existing code
- Improving error messages
- Adding type hints to Python code
- Creating Docker Compose variations

### 🟡 Intermediate Contributions

- New SOAR playbook examples
- Additional threat intelligence feed integrations
- Dashboard UI enhancements
- API client libraries (Go, Rust, Java)
- Performance optimizations
- Adding cloud provider connectors

### 🔴 Advanced Contributions

- Multi-tenancy architecture
- High-availability clustering
- Advanced analytics and ML features
- Custom authentication backends
- Distributed tracing implementation
- Kubernetes operator development

---

## 🔒 Security Contributions

**Found a security vulnerability?**

**DO NOT create a public GitHub issue!**

Follow our [Security Policy](SECURITY.md):

1. Email: **security@wildbox.dev**
2. Subject: `[SECURITY] Brief Description`
3. Include: Description, reproduction steps, impact assessment
4. Expect response within 48 hours

---

## 🎨 Code Style Guidelines

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

## ✅ Testing Requirements

### Required for All PRs

- ✅ All existing tests pass
- ✅ New code has unit tests (>80% coverage)
- ✅ Integration tests for API changes
- ✅ E2E tests for UI changes

### Running Tests Locally

```bash
# Python unit tests
pytest tests/ -v --cov

# JavaScript tests
npm test

# Integration tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit

# E2E tests
cd open-security-dashboard
npx playwright test
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

```typescript
// TypeScript test example
describe('Authentication', () => {
  it('should login with valid credentials', async () => {
    const response = await login('admin@example.com', 'password');
    expect(response.token).toBeDefined();
    expect(response.user.email).toBe('admin@example.com');
  });
});
```

---

## 💬 Getting Help

- **Questions?** [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions)
- **Feature Ideas?** [Ideas Discussion Category](https://github.com/fabriziosalmi/wildbox/discussions/categories/ideas)
- **Found a Bug?** [Create an Issue](https://github.com/fabriziosalmi/wildbox/issues/new?template=bug_report.md)
- **Want to Help?** [Good First Issues](https://github.com/fabriziosalmi/wildbox/labels/good%20first%20issue)

---

## 🎖️ Recognition

Contributors are recognized in:
- [AUTHORS.md](AUTHORS.md) file
- Release notes for their contributions
- GitHub contributor graphs
- Community highlights in discussions

**Thank you for contributing to Wildbox! 🙏**

## 🔥 High Priority Contributions (Evaluation Phase)

As we are in an early evaluation phase, we are looking for feedback on the following:

**Testing & Feedback** (No coding required)
- [ ] Deploy Wildbox and share your experience.
- [ ] Test different deployment scenarios (Docker, cloud, on-premise).
- [ ] Try various security integrations and workflows.
- [ ] Report bugs and edge cases you discover.
- [ ] Suggest features based on your security needs.
- [ ] Performance testing in different environments.

**Issues & Bug Reports**
- [ ] Compatibility issues (OS, Python, Node versions).
- [ ] Documentation gaps or unclear sections.
- [ ] Error messages that need improvement.
- [ ] Configuration options that are confusing.
- [ ] Performance bottlenecks you discover.

**Real-World Feedback**
- [ ] Share your deployment architecture.
- [ ] Document security use cases you implement.
- [ ] Suggest integrations with your tools.
- [ ] Provide scaling feedback (10, 100, 1000+ events/sec).
- [ ] Report operational issues and solutions.

## 💻 Code Contribution Process

1.  **Fork** the repository on GitHub.
2.  **Create** a feature branch: `git checkout -b feature/my-feature`.
3.  **Make** your changes with clear, descriptive commits.
4.  **Test** your changes thoroughly.
5.  **Push** to your fork: `git push origin feature/my-feature`.
6.  **Create** a Pull Request with a detailed description of your changes.

## 💡 Contribution Areas

### Easy Wins for New Contributors
- [ ] Documentation improvements and clarifications.
- [ ] README translations to other languages.
- [ ] Additional example configurations.
- [ ] Docker Compose variations for different scenarios.
- [ ] Helpful scripts and automation.
- [x] **API Documentation** - Document service endpoints ([Contributing Guide](docs/api/CONTRIBUTING.md)).
  - [x] Guardian Service API endpoints and examples.
  - [x] Agents Service AI analysis endpoints.
  - [x] Data Service aggregation endpoints.
  - [x] Tools Service execution endpoints.
  - [x] Responder Service playbook endpoints.
  - [ ] CSPM Service cloud security endpoints.

### Medium-Level Contributions
- [ ] New SOAR playbook examples.
- [ ] Additional threat intelligence sources.
- [ ] Cloud provider integrations (starter).
- [ ] Dashboard improvements and visualizations.
- [ ] API client libraries in different languages.

### Advanced Contributions
- [ ] Multi-tenancy support.
- [ ] High-availability clustering.
- [ ] Advanced analytics features.
- [ ] Custom authentication backends.
- [ ] Performance optimizations.

## 🔒 Security Contributions

Found a security vulnerability?

**Please report security issues privately:**
- Email: fabrizio.salmi@gmail.com
- **Do NOT create public GitHub issues for security vulnerabilities.**
- Include: description, reproduction steps, and impact assessment.
- Allow 48 hours for an initial response.

## 🎨 Code Style

- **Python**: Follow PEP 8 and use Black for formatting.
- **TypeScript**: Follow the ESLint configuration and use Prettier.
- **Commits**: Use clear, descriptive messages following the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.
- **Documentation**: Update relevant documentation with your changes.

## ✅ Testing Requirements

- Write unit tests for all new code.
- Add integration tests for API changes.
- Create E2E tests for user-facing features.
- Maintain >80% code coverage.

## 💬 Getting Help

- **Questions?** Ask in [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions).
- **Feature Ideas?** Post in [Discussions > Ideas](https://github.com/fabriziosalmi/wildbox/discussions/categories/ideas).
- **Found a Bug?** Create an [Issue](https://github.com/fabriziosalmi/wildbox/issues) with details.
- **Want to Help?** Check [open issues](https://github.com/fabriziosalmi/wildbox/issues) marked as `help-wanted`.
