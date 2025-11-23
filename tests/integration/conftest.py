"""
Pytest configuration and fixtures for Wildbox integration tests

This module provides shared fixtures for testing across all Wildbox services,
including resilient HTTP clients, service URL configuration, and common utilities.
"""

import os
import pytest
import asyncio
import httpx
from typing import AsyncGenerator, Generator
from urllib.parse import urljoin


# ============================================================================
# Event Loop Configuration
# ============================================================================

@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """
    Create an event loop for async tests
    
    Provides a session-scoped event loop that all async tests can share,
    preventing event loop creation/cleanup overhead for each test.
    """
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Service URL Configuration
# ============================================================================

@pytest.fixture(scope="session")
def gateway_url() -> str:
    """Base URL for gateway service"""
    return os.getenv("GATEWAY_URL", "http://localhost")


@pytest.fixture(scope="session")
def identity_url() -> str:
    """Base URL for identity service"""
    return os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")


@pytest.fixture(scope="session")
def api_url() -> str:
    """Base URL for tools/API service"""
    return os.getenv("TOOLS_SERVICE_URL", "http://localhost:8000")


@pytest.fixture(scope="session")
def data_url() -> str:
    """Base URL for data service"""
    return os.getenv("DATA_SERVICE_URL", "http://localhost:8002")


@pytest.fixture(scope="session")
def guardian_url() -> str:
    """Base URL for guardian service"""
    return os.getenv("GUARDIAN_SERVICE_URL", "http://localhost:8003")


@pytest.fixture(scope="session")
def responder_url() -> str:
    """Base URL for responder service"""
    return os.getenv("RESPONDER_SERVICE_URL", "http://localhost:8018")


@pytest.fixture(scope="session")
def agents_url() -> str:
    """Base URL for AI agents service"""
    return os.getenv("AGENTS_SERVICE_URL", "http://localhost:8006")


@pytest.fixture(scope="session")
def cspm_url() -> str:
    """Base URL for CSPM service"""
    return os.getenv("CSPM_SERVICE_URL", "http://localhost:8019")


# ============================================================================
# Authentication Configuration
# ============================================================================

@pytest.fixture(scope="session")
def test_api_key() -> str:
    """API key for testing"""
    return os.getenv("TEST_API_KEY", "test-api-key-for-ci-only")


@pytest.fixture(scope="session")
def test_jwt_secret() -> str:
    """JWT secret for testing"""
    return os.getenv("JWT_SECRET_KEY", "test-jwt-secret-for-ci-only")


# ============================================================================
# HTTP Client Fixtures with Automatic Retries
# ============================================================================

@pytest.fixture(scope="session")
async def http_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """
    Provide a resilient HTTP client with automatic retries
    
    Features:
    - Automatic retry on connection errors (max 3 attempts)
    - 10-second timeout per request
    - Connection pooling for better performance
    - Proper async cleanup
    """
    transport = httpx.AsyncHTTPTransport(
        retries=3,  # Retry failed requests up to 3 times
        http2=False  # Disable HTTP/2 for better compatibility
    )
    
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=5.0),
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        transport=transport,
        follow_redirects=True
    ) as client:
        yield client


@pytest.fixture(scope="function")
async def identity_client(http_client: httpx.AsyncClient, identity_url: str, test_api_key: str) -> httpx.AsyncClient:
    """HTTP client configured for identity service with auth"""
    http_client.base_url = identity_url
    http_client.headers.update({"X-API-Key": test_api_key})
    return http_client


@pytest.fixture(scope="function")
async def api_client(http_client: httpx.AsyncClient, api_url: str, test_api_key: str) -> httpx.AsyncClient:
    """HTTP client configured for tools/API service with auth"""
    http_client.base_url = api_url
    http_client.headers.update({"X-API-Key": test_api_key})
    return http_client


@pytest.fixture(scope="function")
async def data_client(http_client: httpx.AsyncClient, data_url: str, test_api_key: str) -> httpx.AsyncClient:
    """HTTP client configured for data service with auth"""
    http_client.base_url = data_url
    http_client.headers.update({"X-API-Key": test_api_key})
    return http_client


# ============================================================================
# Service Health Check Utilities
# ============================================================================

async def wait_for_service(
    client: httpx.AsyncClient,
    url: str,
    timeout: int = 30,
    interval: int = 1
) -> bool:
    """
    Wait for a service to become healthy
    
    Args:
        client: HTTP client to use
        url: Service URL to check
        timeout: Maximum time to wait in seconds
        interval: Seconds between checks
        
    Returns:
        True if service became healthy, False if timeout
    """
    import time
    start = time.time()
    
    while time.time() - start < timeout:
        try:
            response = await client.get(urljoin(url, "/health"))
            if response.status_code == 200:
                return True
        except (httpx.ConnectError, httpx.TimeoutException):
            pass
        
        await asyncio.sleep(interval)
    
    return False


@pytest.fixture(scope="session")
async def ensure_services_ready(
    http_client: httpx.AsyncClient,
    identity_url: str,
    api_url: str
):
    """
    Ensure critical services are ready before running tests
    
    This fixture runs once per test session and validates that
    essential services are healthy before any tests execute.
    """
    services = {
        "Identity": identity_url,
        "API/Tools": api_url,
    }
    
    for name, url in services.items():
        is_ready = await wait_for_service(http_client, url, timeout=60)
        if not is_ready:
            pytest.fail(f"{name} service at {url} did not become ready")
        print(f"✅ {name} service is ready")


# ============================================================================
# Test Data Fixtures
# ============================================================================

@pytest.fixture
def sample_test_user():
    """Sample user data for testing"""
    return {
        "email": "test@wildbox.test",
        "password": "Test123!@#SecurePassword",
        "is_active": True,
        "is_superuser": False
    }


@pytest.fixture
def sample_api_test_data():
    """Sample data for API security testing"""
    return {
        "api_base_url": "https://httpbin.org",
        "authentication_type": "none",
        "test_depth": "quick",
        "max_requests": 10
    }


# ============================================================================
# Cleanup Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def reset_client_state(http_client: httpx.AsyncClient):
    """
    Reset HTTP client state between tests
    
    Clears any custom headers or auth that individual tests may have set,
    ensuring a clean state for the next test.
    """
    yield
    # Reset headers to default after each test
    http_client.headers.clear()
    http_client.cookies.clear()


# ============================================================================
# Pytest Configuration Hooks
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom settings"""
    config.addinivalue_line(
        "markers",
        "asyncio: mark test as async"
    )


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to add markers automatically
    
    Automatically marks async tests and adds skip conditions
    """
    for item in items:
        # Auto-mark async tests
        if asyncio.iscoroutinefunction(item.function):
            item.add_marker(pytest.mark.asyncio)
        
        # Mark all integration tests
        item.add_marker(pytest.mark.integration)
