"""
Pytest configuration and shared fixtures for Wildbox integration tests
"""

import os
import pytest
import time
from typing import Dict


def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "smoke: Smoke tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "slow: Slow-running tests")


@pytest.fixture(scope="session")
def service_urls() -> Dict[str, str]:
    """Get service URLs from environment"""
    return {
        "identity": os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001"),
        "tools": os.getenv("TOOLS_SERVICE_URL", "http://localhost:8000"),
        "data": os.getenv("DATA_SERVICE_URL", "http://localhost:8002"),
        "guardian": os.getenv("GUARDIAN_SERVICE_URL", "http://localhost:8013"),
        "responder": os.getenv("RESPONDER_SERVICE_URL", "http://localhost:8018"),
        "agents": os.getenv("AGENTS_SERVICE_URL", "http://localhost:8006"),
        "cspm": os.getenv("CSPM_SERVICE_URL", "http://localhost:8019"),
        "gateway": os.getenv("GATEWAY_SERVICE_URL", "http://localhost:80"),
    }


@pytest.fixture(scope="session")
def test_credentials() -> Dict[str, str]:
    """Get test credentials from environment"""
    return {
        "admin_email": os.getenv("TEST_ADMIN_EMAIL", "admin@wildbox.io"),
        "admin_password": os.getenv("TEST_ADMIN_PASSWORD", "ChangeMe123!"),
        "api_key": os.getenv("TEST_API_KEY", "test-api-key-for-ci-only"),
    }


@pytest.fixture(scope="session")
def admin_token(service_urls: Dict[str, str], test_credentials: Dict[str, str]) -> str:
    """Get admin authentication token for tests"""
    import requests

    identity_url = service_urls["identity"]
    login_data = f"username={test_credentials['admin_email']}&password={test_credentials['admin_password']}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(
            f"{identity_url}/api/v1/auth/jwt/login",
            data=login_data,
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            token = response.json().get("access_token")
            return token
    except Exception as e:
        pytest.fail(f"Could not get admin token: {e}")

    pytest.fail("Admin authentication failed - verify credentials in test environment")


@pytest.fixture(scope="function")
def api_client(service_urls: Dict[str, str], test_credentials: Dict[str, str]):
    """Create authenticated API client"""
    import requests

    class APIClient:
        def __init__(self, service: str):
            self.base_url = service_urls[service]
            self.api_key = test_credentials["api_key"]
            self.session = requests.Session()
            self.session.headers.update({
                "X-API-Key": self.api_key,
                "Content-Type": "application/json"
            })

        def get(self, path: str, **kwargs):
            return self.session.get(f"{self.base_url}{path}", **kwargs)

        def post(self, path: str, **kwargs):
            return self.session.post(f"{self.base_url}{path}", **kwargs)

        def put(self, path: str, **kwargs):
            return self.session.put(f"{self.base_url}{path}", **kwargs)

        def delete(self, path: str, **kwargs):
            return self.session.delete(f"{self.base_url}{path}", **kwargs)

    return APIClient


@pytest.fixture(scope="session")
def wait_for_services(service_urls: Dict[str, str]):
    """Wait for services to be ready before running tests"""
    import requests

    max_wait = 60  # seconds
    start_time = time.time()

    # Only check critical services
    critical_services = ["identity", "tools"]

    for service_name in critical_services:
        service_url = service_urls.get(service_name)
        if not service_url:
            continue

        ready = False
        while not ready and (time.time() - start_time) < max_wait:
            try:
                response = requests.get(f"{service_url}/health", timeout=5)
                if response.status_code == 200:
                    ready = True
                    print(f"✅ {service_name} service is ready")
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(2)

        if not ready:
            pytest.fail(f"{service_name} service not available - ensure docker-compose.test.yml is running")


@pytest.fixture(autouse=True)
def ensure_services_ready(wait_for_services):
    """Automatically ensure services are ready before each test"""
    pass


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test location"""
    for item in items:
        # Add integration marker to all tests in integration folder
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Add smoke marker to health check tests
        if "health" in item.name.lower():
            item.add_marker(pytest.mark.smoke)

        # Add security marker to security-related tests
        if any(keyword in item.name.lower() for keyword in ["auth", "jwt", "rbac", "security"]):
            item.add_marker(pytest.mark.security)
