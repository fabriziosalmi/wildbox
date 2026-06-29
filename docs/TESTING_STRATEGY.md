# Containerized Testing Strategy

**Status:** ✅ IMPLEMENTED (Framework Ready)  
**Migration:** 🔄 IN PROGRESS  
**Priority:** HIGH

## Current State

### ✅ **Good:**
- Pytest configuration in place (`pytest.ini`)
- Test markers for categorization (unit, integration, e2e)
- HTML reporting configured
- Coverage tracking ready
- Tests directory structure exists

### ❌ **Bad:**
- Debug scripts in production (`scripts/debug/*.py`)
- Shell scripts duplicating pytest functionality (`test_*.sh`)
- Tests not containerized - rely on local environment
- No CI/CD test matrix
- Manual test execution required

## Target Architecture

### Test Execution in Containers

```yaml
# docker-compose.test.yml (new file)
version: '3.8'

services:
  test-runner:
    build:
      context: .
      dockerfile: tests/Dockerfile
    environment:
      - POSTGRES_HOST=postgres-test
      - REDIS_HOST=redis-test
      - GATEWAY_URL=http://gateway-test
    depends_on:
      postgres-test:
        condition: service_healthy
      redis-test:
        condition: service_healthy
    volumes:
      - ./tests:/app/tests
      - ./tests/reports:/app/reports
    command: pytest tests/ -v --html=reports/report.html

  postgres-test:
    image: postgres:15-alpine
    environment:
      POSTGRES_PASSWORD: test_password
      POSTGRES_DB: wildbox_test
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis-test:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

  # Minimal service replicas for integration tests
  identity-test:
    build: ./open-security-identity
    environment:
      DATABASE_URL: postgresql://postgres:test_password@postgres-test/wildbox_test
      REDIS_URL: redis://redis-test:6379/0
      JWT_SECRET_KEY: test-secret-key-do-not-use-in-production
    depends_on:
      - postgres-test
      - redis-test

  gateway-test:
    build: ./open-security-gateway
    environment:
      IDENTITY_SERVICE_URL: http://identity-test:8001
    depends_on:
      - identity-test
```

## Test Organization

```
tests/
├── unit/                           # No external dependencies
│   ├── test_auth_logic.py
│   ├── test_validators.py
│   └── test_utilities.py
├── integration/                    # Service-level tests
│   ├── test_identity_service.py
│   ├── test_gateway_routing.py
│   ├── test_database_operations.py
│   └── test_redis_caching.py
├── e2e/                           # Full-stack tests
│   ├── test_authentication_flow.py
│   ├── test_vulnerability_lifecycle.py
│   └── test_dashboard_integration.py
├── performance/                    # Load tests
│   ├── test_api_throughput.py
│   └── test_database_queries.py
├── security/                       # Security tests
│   ├── test_auth_bypass.py
│   ├── test_injection_attacks.py
│   └── test_rate_limiting.py
├── conftest.py                    # Shared fixtures
├── Dockerfile                     # Test runner container
└── requirements.txt               # Test dependencies
```

## Migration Plan

### Phase 1: Consolidate Existing Tests ✅

**Move debug scripts to proper tests:**

```bash
# Delete (moved to scripts/debug/ already)
scripts/debug/debug_identity_test.py
scripts/debug/test_api_keys.py
scripts/debug/test_identity_single.py
scripts/debug/test_rate_limit.py

# Convert to proper pytest tests in tests/integration/
```

**Example conversion:**

**Before** (`scripts/debug/test_api_keys.py`):
```python
# Debug script - manual execution
def test_api_key_generation():
    response = requests.post("http://localhost:8001/api/v1/auth/api-keys")
    print(f"Response: {response.json()}")
    assert response.status_code == 200

if __name__ == "__main__":
    test_api_key_generation()
```

**After** (`tests/integration/test_identity_service.py`):
```python
import pytest
from httpx import AsyncClient

@pytest.mark.integration
@pytest.mark.asyncio
async def test_api_key_generation(identity_client, admin_token):
    """Test API key generation endpoint"""
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    async with AsyncClient(base_url="http://identity-test:8001") as client:
        response = await client.post(
            "/api/v1/auth/api-keys",
            headers=headers,
            json={"name": "Test Key", "expires_days": 90}
        )
    
    assert response.status_code == 200
    data = response.json()
    assert data["api_key"].startswith("wsk_")
    assert len(data["api_key"]) == 72  # 4-char prefix + 64-char key + 2 dots
```

### Phase 2: Create Test Fixtures ✅

**tests/conftest.py additions:**

```python
import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from redis import Redis

@pytest.fixture(scope="session")
def postgres_url():
    """Test database URL"""
    return "postgresql://postgres:test_password@postgres-test/wildbox_test"

@pytest.fixture(scope="session")
def redis_url():
    """Test Redis URL"""
    return "redis://redis-test:6379/0"

@pytest.fixture
async def identity_client():
    """Async HTTP client for identity service"""
    async with AsyncClient(base_url="http://identity-test:8001") as client:
        yield client

@pytest.fixture
async def admin_token(identity_client):
    """Generate admin JWT token for tests"""
    response = await identity_client.post(
        "/api/v1/auth/login",
        json={"email": "admin@wildbox.security", "password": "test-password"}
    )
    return response.json()["access_token"]

@pytest.fixture
def test_vulnerability():
    """Sample vulnerability object for tests"""
    return {
        "cve_id": "CVE-2024-TEST-001",
        "severity": "HIGH",
        "description": "Test vulnerability",
        "affected_systems": ["system-1"],
    }

@pytest.fixture(autouse=True)
async def clean_database(postgres_url):
    """Clean database before each test"""
    engine = create_engine(postgres_url)
    # Truncate tables or use transactions
    yield
    # Cleanup after test
```

### Phase 3: Containerized Execution ✅

**Run tests in containers:**

```bash
# Run all tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit

# Run specific test file
docker-compose -f docker-compose.test.yml run --rm test-runner pytest tests/integration/test_identity_service.py

# Run with specific marker
docker-compose -f docker-compose.test.yml run --rm test-runner pytest -m integration

# Generate coverage report
docker-compose -f docker-compose.test.yml run --rm test-runner pytest --cov=. --cov-report=html
```

### Phase 4: CI/CD Integration ✅

**GitHub Actions** (`.github/workflows/test.yml`):

```yaml
name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        test-type: [unit, integration, e2e]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Start test services
        run: docker-compose -f docker-compose.test.yml up -d
      
      - name: Wait for services
        run: sleep 30
      
      - name: Run ${{ matrix.test-type }} tests
        run: |
          docker-compose -f docker-compose.test.yml run --rm test-runner \
            pytest -m ${{ matrix.test-type }} -v \
            --junitxml=reports/junit-${{ matrix.test-type }}.xml \
            --html=reports/report-${{ matrix.test-type }}.html
      
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-reports-${{ matrix.test-type }}
          path: tests/reports/
      
      - name: Publish test results
        if: always()
        uses: EnricoMi/publish-unit-test-result-action@v2
        with:
          files: tests/reports/junit-*.xml
```

## Example Test Suite

**tests/integration/test_authentication_flow.py:**

```python
import pytest
from httpx import AsyncClient

@pytest.mark.integration
@pytest.mark.asyncio
class TestAuthenticationFlow:
    """Test complete authentication workflow"""
    
    async def test_user_registration(self, identity_client):
        """Test new user registration"""
        response = await identity_client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "SecurePass123!",
                "full_name": "Test User"
            }
        )
        assert response.status_code == 201
        assert "user_id" in response.json()
    
    async def test_login_with_valid_credentials(self, identity_client):
        """Test login with correct password"""
        response = await identity_client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@wildbox.security",
                "password": "test-password"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
    
    async def test_login_with_invalid_credentials(self, identity_client):
        """Test login with wrong password returns 401"""
        response = await identity_client.post(
            "/api/v1/auth/login",
            json={
                "email": "admin@wildbox.security",
                "password": "wrong-password"
            }
        )
        assert response.status_code == 401
    
    async def test_access_protected_endpoint(self, identity_client, admin_token):
        """Test accessing protected resource with token"""
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = await identity_client.get(
            "/api/v1/auth/me",
            headers=headers
        )
        assert response.status_code == 200
        user_data = response.json()
        assert user_data["email"] == "admin@wildbox.security"
    
    async def test_token_expiration(self, identity_client):
        """Test expired token returns 401"""
        expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired"
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = await identity_client.get(
            "/api/v1/auth/me",
            headers=headers
        )
        assert response.status_code == 401
```

## Running Tests Locally

```bash
# Start test environment
make test-setup
# OR
docker-compose -f docker-compose.test.yml up -d

# Run all tests
make test
# OR
docker-compose -f docker-compose.test.yml run --rm test-runner pytest

# Run specific markers
pytest -m unit           # Fast, no services needed
pytest -m integration    # Requires services
pytest -m e2e            # Full stack tests
pytest -m smoke          # Quick validation

# Run with coverage
pytest --cov=. --cov-report=html
# View coverage: open htmlcov/index.html

# Run specific file
pytest tests/integration/test_identity_service.py -v

# Run specific test
pytest tests/integration/test_identity_service.py::test_api_key_generation -v

# Stop test environment
docker-compose -f docker-compose.test.yml down -v
```

## Makefile Integration

**Add to Makefile:**

```makefile
.PHONY: test test-setup test-teardown test-unit test-integration test-e2e test-coverage

test-setup:
	@echo "$(BLUE)Starting test environment...$(NC)"
	@docker-compose -f docker-compose.test.yml up -d
	@echo "Waiting for services..."
	@sleep 20

test: test-setup
	@echo "$(BLUE)Running all tests...$(NC)"
	@docker-compose -f docker-compose.test.yml run --rm test-runner pytest -v
	@$(MAKE) test-teardown

test-unit:
	@pytest -m unit -v

test-integration: test-setup
	@docker-compose -f docker-compose.test.yml run --rm test-runner pytest -m integration -v
	@$(MAKE) test-teardown

test-e2e: test-setup
	@docker-compose -f docker-compose.test.yml run --rm test-runner pytest -m e2e -v
	@$(MAKE) test-teardown

test-coverage: test-setup
	@docker-compose -f docker-compose.test.yml run --rm test-runner \
		pytest --cov=. --cov-report=html --cov-report=term
	@$(MAKE) test-teardown
	@echo "$(GREEN)Coverage report: htmlcov/index.html$(NC)"

test-teardown:
	@docker-compose -f docker-compose.test.yml down -v
```

## Benefits

✅ **Isolation:** Tests don't pollute production databases  
✅ **Reproducibility:** Same environment in dev/CI/prod  
✅ **Parallelization:** CI can run test types concurrently  
✅ **No local setup:** Just Docker - works on any machine  
✅ **Clean state:** Each test run starts fresh  
✅ **CI/CD ready:** Drop-in replacement for manual scripts  

## Timeline

| Task | Status | Owner |
|------|--------|-------|
| Move debug scripts to archive | ✅ Completed | Sprint 1 |
| Create docker-compose.test.yml | 📋 Planned | Sprint 2 |
| Convert debug scripts to pytest | 📋 Planned | Sprint 2 |
| Add conftest.py fixtures | 📋 Planned | Sprint 2 |
| Setup CI/CD test matrix | 📋 Planned | Sprint 2 |
| Add coverage reporting | 📋 Planned | Sprint 2 |

---

**Current Test Count:** ~15 ad-hoc scripts  
**Target Test Count:** 100+ proper pytest tests  
**Test Coverage Goal:** >80%
