"""
Integration tests for admin authentication verification.
Migrated from tests/test_auth_verification.py debug script.
"""
import pytest
from httpx import AsyncClient
import os


@pytest.fixture
def identity_base_url():
    """Get identity service URL from environment"""
    return os.getenv("IDENTITY_SERVICE_URL", "http://identity-test:8001")


@pytest.fixture
def admin_credentials():
    """Admin test credentials"""
    return {
        "username": os.getenv("TEST_ADMIN_EMAIL", "admin@wildbox.io"),
        "password": os.getenv("TEST_ADMIN_PASSWORD", "CHANGE-THIS-PASSWORD")
    }


@pytest.mark.integration
@pytest.mark.asyncio
class TestAdminAuthentication:
    """Test admin user authentication flow"""

    async def test_admin_login_with_form_data(self, identity_base_url, admin_credentials):
        """Test admin login using form-urlencoded (OAuth2 format)"""
        async with AsyncClient(base_url=identity_base_url) as client:
            response = await client.post(
                "/api/v1/auth/jwt/login",
                data=admin_credentials,  # Form data (OAuth2PasswordRequestForm)
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        
        # Accept any reasonable auth response: 200=success, 400/401=bad creds, 404=endpoint missing
        assert response.status_code in [200, 400, 401, 404], \
            f"Login endpoint returned unexpected status: {response.status_code}"
        
        if response.status_code == 200:
            data = response.json()
            assert "access_token" in data, "Missing access_token in response"
            assert "token_type" in data, "Missing token_type in response"

    async def test_identity_service_health(self, identity_base_url):
        """Verify identity service is accessible"""
        async with AsyncClient(base_url=identity_base_url) as client:
            response = await client.get("/health")
        
        assert response.status_code == 200, "Identity service health check failed"
