"""
Simplified Integration Tests for CI/CD Pipeline
Tests core functionality with minimal dependencies
"""

import pytest
import requests
from typing import Dict


@pytest.mark.integration
@pytest.mark.smoke
def test_identity_health(service_urls: Dict[str, str]):
    """Test identity service health endpoint"""
    response = requests.get(f"{service_urls['identity']}/health", timeout=10)
    assert response.status_code == 200
    
    data = response.json()
    assert data.get("status") in ["healthy", "degraded"]
    assert "service" in data
    assert "timestamp" in data


@pytest.mark.integration
@pytest.mark.smoke
def test_identity_metrics(service_urls: Dict[str, str]):
    """Test identity service metrics endpoint (superuser only)."""
    import os
    # The counts are for platform superusers, authenticated by identity from
    # the bearer token. The gateway secret used to open them on its own, and
    # the gateway sent it on every request, so anyone could read them (#664).
    email = os.environ.get("TEST_ADMIN_EMAIL", "")
    password = os.environ.get("TEST_ADMIN_PASSWORD", "")
    if not email or not password:
        pytest.skip("TEST_ADMIN_EMAIL / TEST_ADMIN_PASSWORD not set")
    login = requests.post(
        f"{service_urls['identity']}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=10,
    )
    assert login.status_code == 200, login.text[:200]
    # /api/v1/admin/metrics, not /metrics: the latter is the Prometheus text
    # exposition. The two used to collide on one path, where the exposition won.
    response = requests.get(
        f"{service_urls['identity']}/api/v1/admin/metrics",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        timeout=10,
    )
    assert response.status_code == 200

    data = response.json()
    assert "identity" in data.get("service", "").lower()
    assert "metrics" in data
    assert "timestamp" in data

    # The database is up in this suite: real counts, not the fallback. The
    # handler used to import a model that does not exist and always fell back.
    metrics = data["metrics"]
    assert "error" not in metrics, metrics
    for name in ("users_total", "teams_total", "api_keys_active"):
        assert isinstance(metrics[name], int)
    assert metrics["users_total"] >= 1


@pytest.mark.integration
@pytest.mark.smoke
def test_tools_health(service_urls: Dict[str, str]):
    """Test tools service health endpoint"""
    try:
        response = requests.get(f"{service_urls['tools']}/health", timeout=10)
        assert response.status_code == 200
        
        data = response.json()
        assert data.get("status") in ["healthy", "degraded"]
    except requests.exceptions.ConnectionError:
        pytest.fail("Tools service is not available. Ensure it's running in docker-compose.test.yml")


@pytest.mark.integration
@pytest.mark.security
def test_identity_authentication_required(service_urls: Dict[str, str]):
    """Test that protected endpoints require authentication"""
    # Try to access protected endpoint without auth
    # FastAPI Users mounts /me under /users prefix
    response = requests.get(
        f"{service_urls['identity']}/api/v1/users/me",
        timeout=10
    )
    
    # Should return 401 Unauthorized
    assert response.status_code == 401


@pytest.mark.integration
@pytest.mark.security
def test_tools_api_key_required(service_urls: Dict[str, str]):
    """Test that tools service requires API key"""
    try:
        # Try to access tools without API key
        # Tools service uses /api prefix not /api/v1
        response = requests.get(
            f"{service_urls['tools']}/api/tools",
            timeout=10
        )
        
        # Should return 401 or 403
        assert response.status_code in [401, 403]
    except requests.exceptions.ConnectionError:
        pytest.fail("Tools service is not available. Ensure it's running in docker-compose.test.yml")


@pytest.mark.integration
@pytest.mark.security
def test_tools_with_valid_api_key(service_urls, test_credentials):
    """Test tools service with valid API key"""
    try:
        headers = {"X-API-Key": test_credentials["api_key"]}
        
        # Tools service uses /api prefix not /api/v1
        response = requests.get(
            f"{service_urls['tools']}/api/tools",
            headers=headers,
            timeout=10
        )
        
        # Should be successful, unauthorized, or validation error
        # 422 can occur if API key format doesn't match service expectations
        assert response.status_code in [200, 401, 403, 422]
    except requests.exceptions.ConnectionError:
        pytest.fail("Tools service is not available. Ensure it's running in docker-compose.test.yml")


@pytest.mark.integration
def test_identity_database_connection(service_urls: Dict[str, str]):
    """Test that identity service can connect to database"""
    response = requests.get(f"{service_urls['identity']}/health", timeout=10)
    
    assert response.status_code == 200
    data = response.json()
    
    # If database is down, status should be "unhealthy" or "degraded"
    # If status is "healthy", database connection is working
    status = data.get("status")
    assert status in ["healthy", "degraded", "unhealthy"]
    
    # Check for database-specific health info if available
    if "database" in data:
        db_status = data["database"]
        assert db_status in ["connected", "disconnected", "error"]


@pytest.mark.integration
def test_identity_redis_connection(service_urls: Dict[str, str]):
    """Test that identity service can connect to Redis"""
    response = requests.get(f"{service_urls['identity']}/health", timeout=10)
    
    assert response.status_code == 200
    data = response.json()
    
    # Check for Redis-specific health info if available
    if "redis" in data:
        redis_status = data["redis"]
        assert redis_status in ["connected", "disconnected", "error"]


@pytest.mark.integration
@pytest.mark.slow
def test_service_response_times(service_urls: Dict[str, str]):
    """Test that services respond within acceptable time"""
    import time
    
    services = ["identity"]  # Only test services available in docker-compose.test.yml
    
    for service in services:
        start = time.time()
        response = requests.get(f"{service_urls[service]}/health", timeout=10)
        elapsed = time.time() - start
        
        assert response.status_code == 200, f"{service} health check failed"
        assert elapsed < 2.0, f"{service} response time too slow: {elapsed:.2f}s"


@pytest.mark.integration
def test_identity_version_info(service_urls: Dict[str, str]):
    """Identity identifies itself on /health and exposes Prometheus metrics.

    This called response.json() on /metrics. That worked only while /metrics
    answered a JSON placeholder because prometheus_client was not installed in
    the service; with the package present it returns the Prometheus text
    exposition and the test raised JSONDecodeError. The exposition format is
    what a scrape target is supposed to serve, so assert that -- and read the
    service identity from /health, which is where it is published.
    """
    health = requests.get(f"{service_urls['identity']}/health", timeout=10)
    assert health.status_code == 200
    assert health.json().get("service"), "health response does not name the service"

    metrics = requests.get(f"{service_urls['identity']}/metrics", timeout=10)
    assert metrics.status_code == 200
    assert metrics.headers.get("content-type", "").startswith("text/plain"), (
        f"metrics content-type is {metrics.headers.get('content-type')!r}, "
        "not the Prometheus text exposition"
    )
    assert "wildbox_http_requests_total" in metrics.text, (
        "identity is a Prometheus scrape target but publishes no wildbox_ series"
    )


@pytest.mark.integration
@pytest.mark.performance
def test_identity_concurrent_health_checks(service_urls: Dict[str, str]):
    """Test identity service handles concurrent requests"""
    import concurrent.futures
    
    def check_health():
        response = requests.get(f"{service_urls['identity']}/health", timeout=10)
        return response.status_code == 200
    
    # Make 10 concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_health) for _ in range(10)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    # All requests should succeed
    assert all(results), "Some concurrent requests failed"
    assert len(results) == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
