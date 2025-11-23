"""
Integration tests for Identity Service authentication flow.
Replaces debug scripts like test_api_keys.py, test_identity_single.py
"""
import pytest
from httpx import AsyncClient
import os


@pytest.fixture
def identity_base_url():
    """Identity service URL from environment"""
    return os.getenv("IDENTITY_SERVICE_URL", "http://identity-test:8001")


@pytest.mark.integration
@pytest.mark.asyncio
class TestAuthenticationFlow:
    """Test complete authentication workflow"""

    async def test_health_check(self, identity_base_url):
        """Verify identity service is running"""
        async with AsyncClient(base_url=identity_base_url) as client:
            response = await client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    async def test_login_with_invalid_credentials_returns_401(self, identity_base_url):
        """Test that wrong password returns 401 Unauthorized"""
        async with AsyncClient(base_url=identity_base_url) as client:
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "admin@wildbox.security",
                    "password": "wrong-password"
                }
            )
        
        assert response.status_code == 401
        assert "detail" in response.json()

    async def test_access_protected_endpoint_without_token_returns_401(self, identity_base_url):
        """Test accessing protected resource without authentication"""
        async with AsyncClient(base_url=identity_base_url) as client:
            response = await client.get("/api/v1/auth/me")
        
        assert response.status_code == 401

    async def test_complete_login_flow(self, identity_base_url):
        """Test full authentication flow: register → login → access protected resource"""
        async with AsyncClient(base_url=identity_base_url) as client:
            # 1. Register new user
            register_response = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": f"test{os.getpid()}@example.com",  # Unique email per run
                    "password": "SecureTestPass123!",
                    "full_name": "Test User"
                }
            )
            
            # Might be 201 (created) or 200 (exists), both OK for test
            assert register_response.status_code in [200, 201]
            
            # 2. Login with credentials
            login_response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": f"test{os.getpid()}@example.com",
                    "password": "SecureTestPass123!"
                }
            )
            
            assert login_response.status_code == 200
            login_data = login_response.json()
            assert "access_token" in login_data
            assert login_data["token_type"] == "bearer"
            
            # 3. Access protected endpoint with token
            headers = {"Authorization": f"Bearer {login_data['access_token']}"}
            me_response = await client.get("/api/v1/auth/me", headers=headers)
            
            assert me_response.status_code == 200
            user_data = me_response.json()
            assert user_data["email"] == f"test{os.getpid()}@example.com"


@pytest.mark.integration
@pytest.mark.asyncio
class TestAPIKeyManagement:
    """Test API key generation and validation"""

    @pytest.fixture
    async def admin_token(self, identity_base_url):
        """Get admin JWT token for tests"""
        async with AsyncClient(base_url=identity_base_url) as client:
            response = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": "admin@wildbox.security",
                    "password": os.getenv("ADMIN_PASSWORD", "change-this-password")
                }
            )
            if response.status_code == 200:
                return response.json()["access_token"]
            return None

    async def test_api_key_generation(self, identity_base_url, admin_token):
        """Test generating API key (replaces test_api_keys.py)"""
        if not admin_token:
            pytest.skip("Admin login failed - check credentials")
        
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        async with AsyncClient(base_url=identity_base_url) as client:
            response = await client.post(
                "/api/v1/auth/api-keys",
                headers=headers,
                json={
                    "name": "Test Integration Key",
                    "expires_days": 90
                }
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "api_key" in data
        assert data["api_key"].startswith("wsk_")
        assert len(data["api_key"]) == 72  # wsk_ + 4 chars + . + 64 chars

    async def test_api_key_validation(self, identity_base_url, admin_token):
        """Test that generated API keys can be used for authentication"""
        if not admin_token:
            pytest.skip("Admin login failed")
        
        # Generate API key
        headers = {"Authorization": f"Bearer {admin_token}"}
        async with AsyncClient(base_url=identity_base_url) as client:
            create_response = await client.post(
                "/api/v1/auth/api-keys",
                headers=headers,
                json={"name": "Validation Test Key", "expires_days": 1}
            )
        
        assert create_response.status_code == 200
        api_key = create_response.json()["api_key"]
        
        # Use API key to access protected endpoint
        async with AsyncClient(base_url=identity_base_url) as client:
            api_headers = {"X-API-Key": api_key}
            validate_response = await client.get(
                "/api/v1/auth/me",
                headers=api_headers
            )
        
        # Should successfully authenticate with API key
        assert validate_response.status_code == 200
