# Wildbox Test Suite - Execution Guide

**Last Updated**: 16 November 2025  
**Test Inventory**: 30 test files (24 Python + 6 TypeScript)

---

## Quick Start

### Run All Tests

```bash
# From repository root
cd /Users/fab/GitHub/wildbox

# Python integration tests (recommended first)
pytest tests/integration/ -v

# TypeScript E2E tests
cd open-security-dashboard
npx playwright test
```

---

## Python Tests

### Prerequisites

```bash
# Install pytest if not already installed
pip install pytest pytest-asyncio httpx

# Ensure services are running
docker-compose up -d
sleep 30  # Wait for services to initialize
```

### Integration Tests (11 files)

Test service-to-service communication and API endpoints.

```bash
# Run all integration tests
pytest tests/integration/ -v

# Run specific service test
pytest tests/integration/test_gateway_security.py -v
pytest tests/integration/test_identity_comprehensive.py -v
pytest tests/integration/test_tools_execution.py -v

# Run with async support
pytest tests/integration/ -v --asyncio-mode=auto

# Run with output capture disabled (see print statements)
pytest tests/integration/ -v -s

# Run specific test method
pytest tests/integration/test_agents_ai.py::AgentsAITester::test_ioc_analysis -v
```

**Available Integration Tests:**
- `test_agents_ai.py` - AI-powered security analysis
- `test_automations_workflow.py` - n8n workflow automation
- `test_cspm_compliance.py` - Cloud security compliance checks
- `test_dashboard_frontend.py` - Frontend API integration
- `test_data_integration.py` - Threat intelligence data
- `test_gateway_security.py` - API gateway authentication & routing
- `test_guardian_monitoring.py` - Vulnerability monitoring
- `test_identity_comprehensive.py` - Auth, teams, subscriptions
- `test_responder_metrics.py` - Incident response metrics
- `test_sensor_telemetry.py` - Endpoint telemetry
- `test_tools_execution.py` - Security tool execution (55+ tools)

### Unit Tests (7 files)

Test isolated components and business logic.

```bash
# Run all unit tests
pytest tests/ -v --ignore=tests/integration/

# Specific unit tests
pytest tests/test_identity_comprehensive.py -v
pytest tests/test_pulse_check_system.py -v
pytest open-security-identity/tests/test_basic.py -v
pytest open-security-agents/tests/test_basic.py -v
```

**Available Unit Tests:**
- `tests/test_identity_comprehensive.py` - Identity service logic (457 lines!)
- `tests/test_pulse_check_system.py` - System health monitoring
- `tests/utils/test_data_generator.py` - Test data generation utilities
- `open-security-identity/tests/test_basic.py` - Identity service basics
- `open-security-agents/tests/test_basic.py` - Agents service schemas
- `open-security-responder/test_basic.py` - Responder models & parsers

### Script-Based Tests (2 files)

Executable test scripts with custom test runners.

```bash
# Agents service comprehensive test
python open-security-agents/scripts/test_agents.py

# Responder service playbook test
python open-security-responder/scripts/test_responder.py
```

### E2E Tests (1 Python file)

```bash
# Responder end-to-end workflow
python open-security-responder/test_e2e.py
```

---

## TypeScript/JavaScript Tests

### Prerequisites

```bash
cd open-security-dashboard

# Install dependencies
npm install

# Install Playwright browsers (first time only)
npx playwright install
```

### E2E Tests (6 Playwright files)

```bash
# Run all E2E tests
npx playwright test

# Run in headed mode (see browser)
npx playwright test --headed

# Run specific test file
npx playwright test tests/e2e/login-flow.spec.ts
npx playwright test tests/e2e/admin-comprehensive.spec.ts
npx playwright test tests/e2e/threat-intel-lookup.spec.ts

# Run tests matching pattern
npx playwright test --grep "login"
npx playwright test --grep "admin"

# Run in UI mode (interactive)
npx playwright test --ui

# Run on specific browser
npx playwright test --project=chromium
npx playwright test --project=firefox
npx playwright test --project=webkit

# Debug mode
npx playwright test --debug

# View test report
npx playwright show-report
```

**Available E2E Tests:**
- `admin-comprehensive.spec.ts` - Admin panel workflows (4 tests)
- `admin-ui-only.spec.ts` - Admin UI interactions (6 tests)
- `login-flow.spec.ts` - Authentication flows (8 tests)
- `quick-login-test.spec.ts` - Quick smoke test (1 test)
- `settings-management.spec.ts` - User settings (14 tests)
- `threat-intel-lookup.spec.ts` - Threat intelligence queries (9 tests)

**Total E2E Test Cases**: 42 tests

---

## Test by Service

### Agents Service

```bash
# Integration test
pytest tests/integration/test_agents_ai.py -v

# Unit test
pytest open-security-agents/tests/test_basic.py -v

# Script test
python open-security-agents/scripts/test_agents.py
```

### Automations Service

```bash
pytest tests/integration/test_automations_workflow.py -v
```

### CSPM Service

```bash
pytest tests/integration/test_cspm_compliance.py -v
```

### Dashboard Service

```bash
# Integration test
pytest tests/integration/test_dashboard_frontend.py -v

# E2E tests (all)
cd open-security-dashboard
npx playwright test
```

### Data Service

```bash
# Integration test
pytest tests/integration/test_data_integration.py -v

# Unit test
pytest tests/utils/test_data_generator.py -v
```

### Gateway Service

```bash
pytest tests/integration/test_gateway_security.py -v
```

### Guardian Service

```bash
pytest tests/integration/test_guardian_monitoring.py -v
```

### Identity Service

```bash
# Integration test
pytest tests/integration/test_identity_comprehensive.py -v

# Unit tests
pytest tests/test_identity_comprehensive.py -v
pytest open-security-identity/tests/test_basic.py -v

# Migration test
python open-security-identity/test_migration.py
```

### Responder Service

```bash
# Integration test
pytest tests/integration/test_responder_metrics.py -v

# Unit test
pytest open-security-responder/test_basic.py -v

# Advanced scenarios
python open-security-responder/test_advanced.py

# E2E workflow
python open-security-responder/test_e2e.py

# Script test
python open-security-responder/scripts/test_responder.py
```

### Sensor Service

```bash
pytest tests/integration/test_sensor_telemetry.py -v
```

### Tools Service

```bash
# Integration test
pytest tests/integration/test_tools_execution.py -v

# Standalone test
python open-security-tools/integration_test.py
```

---

## Advanced Testing

### Parallel Execution

```bash
# Pytest with xdist (requires pytest-xdist)
pip install pytest-xdist
pytest tests/integration/ -n auto -v

# Playwright parallel
npx playwright test --workers=4
```

### Specific Test Selection

```bash
# Pytest - by marker
pytest -m "slow" -v
pytest -m "integration" -v

# Pytest - by keyword
pytest -k "auth" -v
pytest -k "test_login" -v

# Playwright - by title
npx playwright test --grep "should login successfully"
```

### Coverage Analysis

```bash
# Python coverage
pip install pytest-cov
pytest tests/ --cov=app --cov-report=html --cov-report=term

# View HTML report
open htmlcov/index.html
```

### Debugging

```bash
# Pytest with pdb
pytest tests/integration/test_identity_comprehensive.py --pdb

# Pytest with print statements
pytest tests/integration/test_gateway_security.py -s

# Playwright debug
npx playwright test --debug

# Playwright headed mode with slow-mo
npx playwright test --headed --slow-mo=1000
```

---

## Test Configuration

### Pytest Configuration

Create `pytest.ini` in repository root:

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test* *Tester
python_functions = test_*
asyncio_mode = auto
addopts = 
    -v
    --strict-markers
    --tb=short
    --capture=no
markers =
    slow: marks tests as slow
    integration: integration tests
    unit: unit tests
    e2e: end-to-end tests
```

### Playwright Configuration

Already configured in `open-security-dashboard/playwright.config.ts`:
- Base URL: `http://localhost:3000`
- Retries: 2 on CI
- Timeout: 30 seconds
- Projects: chromium, firefox, webkit

---

## Continuous Integration

### GitHub Actions Example

```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  python-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-asyncio pytest-cov
      - name: Start services
        run: docker-compose up -d
      - name: Wait for services
        run: sleep 60
      - name: Run tests
        run: pytest tests/integration/ -v --cov --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Install dependencies
        run: |
          cd open-security-dashboard
          npm ci
      - name: Install Playwright
        run: npx playwright install --with-deps
      - name: Start services
        run: docker-compose up -d
      - name: Wait for services
        run: sleep 60
      - name: Run E2E tests
        run: |
          cd open-security-dashboard
          npx playwright test
      - name: Upload test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: playwright-report
          path: open-security-dashboard/playwright-report/
```

---

## Pre-Commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat << EOF > .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pytest-quick
        name: pytest-quick
        entry: pytest tests/ -v --tb=short -x
        language: system
        pass_filenames: false
        always_run: true
EOF

# Install hooks
pre-commit install
```

---

## Troubleshooting

### Services Not Ready

```bash
# Check service health
./comprehensive_health_check.sh

# Restart specific service
docker-compose restart gateway
docker-compose restart identity

# View logs
docker-compose logs -f gateway
docker-compose logs -f identity
```

### Port Conflicts

```bash
# Check port usage
lsof -i :8000  # Gateway
lsof -i :8001  # Identity
lsof -i :3000  # Dashboard

# Kill process on port
kill -9 $(lsof -t -i:8000)
```

### Database Issues

```bash
# Reset database
docker-compose down -v
docker-compose up -d postgres wildbox-redis
sleep 10
docker-compose up -d

# Run migrations
docker-compose exec identity alembic upgrade head
docker-compose exec guardian python manage.py migrate
```

### Playwright Browser Issues

```bash
# Reinstall browsers
npx playwright install --force

# Clear cache
rm -rf ~/.cache/ms-playwright
npx playwright install
```

---

## Test Development Guidelines

### Writing New Tests

1. **Choose appropriate type**:
   - Unit: Isolated logic, mocked dependencies
   - Integration: Service interaction, real databases
   - E2E: Complete user workflows

2. **Follow naming conventions**:
   - Python: `test_*.py` or `*_test.py`
   - TypeScript: `*.spec.ts` or `*.test.ts`

3. **Use pytest for new Python tests**:
```python
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_api_endpoint():
    async with AsyncClient(base_url="http://localhost:8001") as client:
        response = await client.get("/health")
        assert response.status_code == 200
```

4. **Use Page Objects for E2E tests**:
```typescript
import { test, expect } from '@playwright/test';
import { LoginPage } from './page-objects/login-page';

test('User can login', async ({ page }) => {
  const loginPage = new LoginPage(page);
  await loginPage.goto();
  await loginPage.login('admin@wildbox.local', 'password');
  expect(page).toHaveURL('/dashboard');
});
```

---

## Resources

- **Test Inventory**: `test_inventory.json` (machine-readable)
- **Audit Report**: `TEST_SUITE_AUDIT_REPORT.md` (comprehensive analysis)
- **Coverage Matrix**: `TEST_COVERAGE_MATRIX.md` (quick reference)
- **Inventory Tool**: `tests/test_inventory_mapper.py` (reusable scanner)

---

## Support

For questions or issues with tests:
- Check `TROUBLESHOOTING.md`
- Review service-specific README files
- Contact: fabrizio.salmi@gmail.com

---

**Last Updated**: 16 November 2025  
**Test Framework**: Pytest + Playwright  
**Total Tests**: 30 files + 42 E2E test cases
