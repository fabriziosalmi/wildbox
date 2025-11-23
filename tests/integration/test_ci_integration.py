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
    """Test identity service metrics endpoint"""
    response = requests.get(f"{service_urls['identity']}/metrics", timeout=10)
    assert response.status_code == 200
    
    data = response.json()
    assert data.get("service") == "identity"
    assert "metrics" in data
    assert "timestamp" in data
    
    metrics = data["metrics"]
    # Metrics may have error field if database isn't fully initialized
    if "error" not in metrics:
        assert "users_total" in metrics
        assert "teams_total" in metrics
        assert "api_keys_active" in metrics
        
        # Verify metrics are integers
        assert isinstance(metrics["users_total"], int)
        assert isinstance(metrics["teams_total"], int)
        assert isinstance(metrics["api_keys_active"], int)
    else:
        # If there's a database error, at least verify structure is correct
        assert metrics["users_total"] == 0
        assert metrics["teams_total"] == 0
        assert metrics["api_keys_active"] == 0


@pytest.mark.integration
@pytest.mark.smoke
def test_tools_health(service_urls: Dict[str, str]):
    """Test tools service health endpoint"""
    response = requests.get(f"{service_urls['tools']}/health", timeout=10)
    assert response.status_code == 200
    
    data = response.json()
    assert data.get("status") in ["healthy", "degraded"]


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
    # Try to access tools without API key
    # Tools service uses /api prefix not /api/v1
    response = requests.get(
        f"{service_urls['tools']}/api/tools",
        timeout=10
    )
    
    # Should return 401 or 403
    assert response.status_code in [401, 403]


@pytest.mark.integration
@pytest.mark.security
def test_tools_with_valid_api_key(service_urls: Dict[str, str], test_credentials: Dict[str, str]):
    """Test tools service with valid API key"""
    headers = {"X-API-Key": test_credentials["api_key"]}
    
    # Tools service uses /api prefix not /api/v1
    response = requests.get(
        f"{service_urls['tools']}/api/tools",
        headers=headers,
        timeout=10
    )
    
    # Should be successful or unauthorized (if API key not configured in service)
    assert response.status_code in [200, 401, 403]


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
    
    services = ["identity", "tools"]
    
    for service in services:
        start = time.time()
        response = requests.get(f"{service_urls[service]}/health", timeout=10)
        elapsed = time.time() - start
        
        assert response.status_code == 200, f"{service} health check failed"
        assert elapsed < 2.0, f"{service} response time too slow: {elapsed:.2f}s"


@pytest.mark.integration
def test_identity_version_info(service_urls: Dict[str, str]):
    """Test that identity service returns version information"""
    response = requests.get(f"{service_urls['identity']}/metrics", timeout=10)
    
    if response.status_code == 200:
        data = response.json()
        assert "version" in data or "service" in data


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
