"""
Pytest configuration and fixtures for Wildbox integration tests

This module provides shared fixtures for testing across all Wildbox services,
including resilient HTTP clients, service URL configuration, and common utilities.
"""

import asyncio
import os
from typing import AsyncGenerator
from urllib.parse import urljoin

import httpx
import pytest
import pytest_asyncio

# ============================================================================
# Event Loop Configuration
# ============================================================================

# No `event_loop` fixture here.
#
# Redefining it is deprecated in pytest-asyncio >= 0.23 and does not do what it
# used to: the loop that async fixtures run on is chosen by `loop_scope`, not by
# overriding this fixture. Loop scope is configured in pytest.ini
# (asyncio_default_fixture_loop_scope) and per-fixture below.


# ============================================================================
# Service URL Configuration
# ============================================================================


# The gateway serves the API over HTTPS only.
#
# conf.d/wildbox_gateway.conf answers /health on port 80 and 301-redirects
# everything else to https -- deliberately, so authentication cannot happen over
# an unencrypted channel. Defaulting these tests to http therefore meant every
# request through the gateway got a 301 and every assertion about status codes,
# headers or bodies failed for a reason unrelated to what it was testing.
if not os.getenv("GATEWAY_URL"):
    os.environ["GATEWAY_URL"] = "https://localhost"

# Verify TLS rather than disabling it.
#
# The gateway generates a self-signed certificate for development, so requests
# needs to be told to trust it; the alternative everyone reaches for --
# verify=False -- means the suite would also pass against a gateway presenting
# no valid certificate at all, which is precisely what these tests exist to
# catch. requests picks REQUESTS_CA_BUNDLE up on its own.
_DEV_CA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "open-security-gateway",
    "ssl",
    "wildbox.crt",
)
if (
    os.environ["GATEWAY_URL"].startswith("https://")
    and not os.getenv("REQUESTS_CA_BUNDLE")
    and os.path.exists(_DEV_CA)
):
    os.environ["REQUESTS_CA_BUNDLE"] = _DEV_CA


# Admin credentials for the integration suite.
#
# Normalised here, in the environment, rather than exposed as helpers: the test
# modules read os.getenv directly and importing across them is what let the
# conftest reachability guard and the tests disagree about an address in the
# first place. Setting the variables means every module sees the same values
# with no coupling.
#
# The defaults were a placeholder pair ("admin@wildbox.io" /
# "CHANGE-THIS-PASSWORD") that exists in no deployment, so every test needing an
# authenticated session skipped with "Admin login failed - check credentials".
# The account the stack provisions comes from INITIAL_ADMIN_EMAIL /
# INITIAL_ADMIN_PASSWORD.
for _test_var, _deploy_var in (
    ("TEST_ADMIN_EMAIL", "INITIAL_ADMIN_EMAIL"),
    ("TEST_ADMIN_PASSWORD", "INITIAL_ADMIN_PASSWORD"),
):
    if not os.getenv(_test_var) and os.getenv(_deploy_var):
        os.environ[_test_var] = os.environ[_deploy_var]


@pytest.fixture(scope="session")
def gateway_url() -> str:
    """Base URL for gateway service"""
    return os.environ["GATEWAY_URL"]


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


@pytest.fixture(scope="session")
def service_urls() -> dict:
    """Get service URLs from environment (compatibility fixture)"""
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
def test_credentials() -> dict:
    """Get test credentials from environment (compatibility fixture)"""
    return {
        "admin_email": os.getenv("TEST_ADMIN_EMAIL", "admin@wildbox.io"),
        "admin_password": os.getenv("TEST_ADMIN_PASSWORD", "CHANGE-THIS-PASSWORD"),
        "api_key": os.getenv("TEST_API_KEY", "test-api-key-for-ci-only"),
    }


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


@pytest_asyncio.fixture(scope="session", loop_scope="session")
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
        http2=False,  # Disable HTTP/2 for better compatibility
    )

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=5.0),
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        transport=transport,
        follow_redirects=True,
    ) as client:
        yield client


@pytest_asyncio.fixture(scope="function", loop_scope="session")
async def identity_client(
    http_client: httpx.AsyncClient, identity_url: str, test_api_key: str
) -> httpx.AsyncClient:
    """HTTP client configured for identity service with auth"""
    http_client.base_url = identity_url
    http_client.headers.update({"X-API-Key": test_api_key})
    return http_client


@pytest_asyncio.fixture(scope="function", loop_scope="session")
async def api_client(
    http_client: httpx.AsyncClient, api_url: str, test_api_key: str
) -> httpx.AsyncClient:
    """HTTP client configured for tools/API service with auth"""
    http_client.base_url = api_url
    http_client.headers.update({"X-API-Key": test_api_key})
    return http_client


@pytest_asyncio.fixture(scope="function", loop_scope="session")
async def data_client(
    http_client: httpx.AsyncClient, data_url: str, test_api_key: str
) -> httpx.AsyncClient:
    """HTTP client configured for data service with auth"""
    http_client.base_url = data_url
    http_client.headers.update({"X-API-Key": test_api_key})
    return http_client


# ============================================================================
# Service Health Check Utilities
# ============================================================================


async def wait_for_service(
    client: httpx.AsyncClient, url: str, timeout: int = 30, interval: int = 1
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


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def ensure_services_ready(
    http_client: httpx.AsyncClient, identity_url: str, api_url: str
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
        "is_superuser": False,
    }


@pytest.fixture
def sample_api_test_data():
    """Sample data for API security testing"""
    return {
        "api_base_url": "https://httpbin.org",
        "authentication_type": "none",
        "test_depth": "quick",
        "max_requests": 10,
    }


# ============================================================================
# Cleanup Fixtures
# ============================================================================


@pytest.fixture
def reset_client_state():
    """
    Placeholder fixture for test cleanup

    Note: HTTP client cleanup is handled by the session-scoped client's
    context manager. This fixture exists for backwards compatibility.
    """
    yield
    # Cleanup handled by async context manager


# ============================================================================
# Pytest Configuration Hooks
# ============================================================================


def pytest_configure(config):
    """Configure pytest with custom settings"""
    config.addinivalue_line("markers", "asyncio: mark test as async")


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


# ---------------------------------------------------------------------------
# Service reachability
# ---------------------------------------------------------------------------
#
# The integration job starts a subset of the stack, and twelve of the test files
# target services outside it. Until WILDBO-TEST-01 was fixed those files were
# never collected, so their absence was invisible; now that they run, an
# unreachable service must produce a visible SKIP rather than a failure that
# says nothing about coverage (WILDBO-TEST-04).

import os as _os  # noqa: E402  (kept beside the guard it belongs to)

import requests  # noqa: E402

# NOTE: the defaults here must match the ones the test modules themselves use,
# or the guard probes one address and the test connects to another -- which is
# how a probe against an unrelated local process on :8001 let identity tests run
# and then fail on a hostname that does not resolve.
_SERVICE_URLS = {
    "gateway": _os.environ["GATEWAY_URL"],
    # localhost:8001, the port docker-compose.yml publishes. The default was
    # "http://identity-test:8001", a hostname from a test-compose file that no
    # longer exists, so anything relying on it resolved nowhere.
    "identity": _os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001"),
    "tools": _os.getenv("TOOLS_SERVICE_URL", "http://localhost:8000"),
    "data": _os.getenv("DATA_SERVICE_URL", "http://localhost:8002"),
    "responder": _os.getenv("RESPONDER_SERVICE_URL", "http://localhost:8018"),
    "cspm": _os.getenv("CSPM_SERVICE_URL", "http://localhost:8019"),
    "agents": _os.getenv("AGENTS_SERVICE_URL", "http://localhost:8006"),
    "guardian": _os.getenv("GUARDIAN_SERVICE_URL", "http://localhost:8013"),
    "sensor": _os.getenv("SENSOR_SERVICE_URL", "http://localhost:8004"),
    "dashboard": _os.getenv("DASHBOARD_URL", "http://localhost:3000"),
    "automations": _os.getenv("AUTOMATIONS_URL", "http://localhost:5678"),
}

# Which service each test module needs. Anything unlisted is assumed to need
# only the gateway.
_MODULE_SERVICE = {
    "test_agents_ai": "agents",
    "test_automations_workflow": "automations",
    "test_cspm_compliance": "cspm",
    "test_cspm_tenancy": "cspm",
    "test_dashboard_frontend": "dashboard",
    "test_data_cross_tenant": "data",
    "test_data_integration": "data",
    "test_data_tenancy": "data",
    "test_gateway_hardening": "gateway",
    "test_gateway_security": "gateway",
    "test_guardian_monitoring": "guardian",
    "test_identity_comprehensive": "identity",
    "test_identity_service": "identity",
    "test_responder_metrics": "responder",
    "test_responder_tenancy": "responder",
    "test_sensor_telemetry": "sensor",
    "test_tools_execution": "tools",
    "test_admin_auth": "identity",
    # Module-level test functions, not classes. These were always collected and
    # always failed locally when the stack was down; they now skip with a reason
    # like everything else (WILDBO-TEST-04).
    "test_ci_integration": "gateway",
}

_reachable_cache: dict = {}


def _is_reachable(service: str) -> bool:
    """
    Is this Wildbox service actually up?

    An HTTP health probe, not a TCP connect: a bare connect only proves that
    *something* holds the port, which on a developer machine is routinely an
    unrelated process, and the tests then run against it and fail for reasons
    that have nothing to do with the code.
    """
    if service in _reachable_cache:
        return _reachable_cache[service]
    url = _SERVICE_URLS.get(service)
    if not url:
        _reachable_cache[service] = False
        return False

    ok = False
    for path in ("/health", "/health/live", "/"):
        try:
            resp = requests.get(f"{url.rstrip('/')}{path}", timeout=3)
        except requests.RequestException:
            continue
        if resp.status_code < 500:
            # Confirm it is a Wildbox service and not whatever else is on the
            # port: our health endpoints answer JSON, and the gateway answers
            # its own health route.
            ctype = resp.headers.get("content-type", "")
            if "json" in ctype or service in ("gateway", "dashboard"):
                ok = True
                break
    _reachable_cache[service] = ok
    return ok


def _mint_api_key() -> str:
    """Create a real API key through identity, or return "" if that is not possible.

    The suite used to authenticate with whatever was in TEST_API_KEY, defaulting
    to the literal string "test-api-key-for-ci-only", and the platform API_KEY
    was substituted for it locally. Neither works: the gateway validates a key
    against the ones identity has issued, so both produced
    {"error":"invalid_token"} and every gateway test failed on authentication
    before reaching what it meant to assert.

    Minting one here makes the suite self-provisioning -- it authenticates the
    way a real client does, through the same code path -- instead of depending
    on a secret someone has to place by hand.
    """
    import requests as _requests

    identity = _os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
    email = _os.getenv("TEST_ADMIN_EMAIL", "")
    password = _os.getenv("TEST_ADMIN_PASSWORD", "")
    if not email or not password:
        return ""
    try:
        login = _requests.post(
            f"{identity}/api/v1/auth/jwt/login",
            data={"username": email, "password": password},
            timeout=10,
        )
        if login.status_code != 200:
            return ""
        token = login.json().get("access_token")
        if not token:
            return ""
        created = _requests.post(
            f"{identity}/api/v1/api-keys",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": "integration-suite"},
            timeout=10,
        )
        if created.status_code not in (200, 201):
            return ""
        return created.json().get("key") or ""
    except _requests.RequestException:
        return ""


@pytest.fixture(scope="session", autouse=True)
def provision_api_key():
    """Put a usable API key in TEST_API_KEY before any test reads it."""
    existing = _os.getenv("TEST_API_KEY", "")
    if existing and existing != "test-api-key-for-ci-only":
        return existing
    minted = _mint_api_key()
    if minted:
        _os.environ["TEST_API_KEY"] = minted
    return minted


def pytest_runtest_setup(item):
    """Skip a test whose service is not running, and say which one."""
    module = item.module.__name__.rsplit(".", 1)[-1]
    service = _MODULE_SERVICE.get(module)
    if service and not _is_reachable(service):
        pytest.skip(
            f"{service} service is not reachable at {_SERVICE_URLS.get(service)} "
            f"- start it to run {module}"
        )
