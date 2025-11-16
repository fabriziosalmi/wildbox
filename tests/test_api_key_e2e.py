#!/usr/bin/env python3
"""
API Key Authentication End-to-End Test
Sprint 1: Test API key creation, listing, authentication, and revocation
"""

import asyncio
import sys
from datetime import datetime, timedelta
import httpx
from typing import Optional

# Test configuration
GATEWAY_URL = "http://localhost"
IDENTITY_URL = "http://localhost:8001"
USE_GATEWAY = True  # Set to False to test direct identity service

# Test user credentials
TEST_EMAIL = "api-test@wildbox.io"
TEST_PASSWORD = "Test123456!"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

class APIKeyTester:
    def __init__(self):
        self.base_url = GATEWAY_URL if USE_GATEWAY else IDENTITY_URL
        self.access_token: Optional[str] = None
        self.team_id: Optional[str] = None
        self.api_key: Optional[str] = None
        self.api_key_prefix: Optional[str] = None
        self.test_results = []
        
    def log(self, message: str, color: str = Colors.BLUE):
        """Print colored log message"""
        print(f"{color}{message}{Colors.END}")
        
    def success(self, test_name: str):
        """Record successful test"""
        self.log(f"✓ {test_name}", Colors.GREEN)
        self.test_results.append((test_name, True))
        
    def failure(self, test_name: str, error: str):
        """Record failed test"""
        self.log(f"✗ {test_name}: {error}", Colors.RED)
        self.test_results.append((test_name, False))
        
    async def test_01_login(self) -> bool:
        """Test user login to get access token"""
        test_name = "Login and get JWT token"
        try:
            async with httpx.AsyncClient() as client:
                # Login using OAuth2 password flow
                response = await client.post(
                    f"{self.base_url}/auth/jwt/login",
                    data={
                        "username": TEST_EMAIL,
                        "password": TEST_PASSWORD
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                if response.status_code != 200:
                    self.failure(test_name, f"Status {response.status_code}: {response.text}")
                    return False
                
                data = response.json()
                self.access_token = data.get("access_token")
                
                if not self.access_token:
                    self.failure(test_name, "No access token in response")
                    return False
                
                self.success(test_name)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_02_get_user_info(self) -> bool:
        """Test getting user info to retrieve team_id"""
        test_name = "Get user info and team_id"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/auth/users/me",
                    headers={"Authorization": f"Bearer {self.access_token}"}
                )
                
                if response.status_code != 200:
                    self.failure(test_name, f"Status {response.status_code}: {response.text}")
                    return False
                
                data = response.json()
                
                # Get team_id from team_memberships
                if "team_memberships" in data and len(data["team_memberships"]) > 0:
                    self.team_id = data["team_memberships"][0]["team_id"]
                else:
                    self.failure(test_name, "No team memberships found")
                    return False
                
                self.success(test_name)
                self.log(f"  Team ID: {self.team_id}", Colors.YELLOW)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_03_create_api_key(self) -> bool:
        """Test creating a new API key"""
        test_name = "Create API key"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/auth/teams/{self.team_id}/api-keys",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    json={
                        "name": "Test API Key - Sprint 1",
                        "expires_at": (datetime.utcnow() + timedelta(days=90)).isoformat()
                    }
                )
                
                if response.status_code != 200:
                    self.failure(test_name, f"Status {response.status_code}: {response.text}")
                    return False
                
                data = response.json()
                self.api_key = data.get("key")
                self.api_key_prefix = data.get("prefix")
                
                if not self.api_key or not self.api_key.startswith("wsk_"):
                    self.failure(test_name, "Invalid API key format")
                    return False
                
                self.success(test_name)
                self.log(f"  API Key: {self.api_key[:20]}...", Colors.YELLOW)
                self.log(f"  Prefix: {self.api_key_prefix}", Colors.YELLOW)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_04_list_api_keys(self) -> bool:
        """Test listing API keys"""
        test_name = "List API keys"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/auth/teams/{self.team_id}/api-keys",
                    headers={"Authorization": f"Bearer {self.access_token}"}
                )
                
                if response.status_code != 200:
                    self.failure(test_name, f"Status {response.status_code}: {response.text}")
                    return False
                
                data = response.json()
                
                if not isinstance(data, list):
                    self.failure(test_name, "Response is not a list")
                    return False
                
                # Find our newly created key
                found = any(key.get("prefix") == self.api_key_prefix for key in data)
                
                if not found:
                    self.failure(test_name, "Created API key not found in list")
                    return False
                
                self.success(test_name)
                self.log(f"  Found {len(data)} API key(s)", Colors.YELLOW)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_05_authenticate_with_api_key(self) -> bool:
        """Test authenticating with API key via X-API-Key header"""
        test_name = "Authenticate with X-API-Key header"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/auth/users/me",
                    headers={"X-API-Key": self.api_key}
                )
                
                if response.status_code != 200:
                    self.failure(test_name, f"Status {response.status_code}: {response.text}")
                    return False
                
                data = response.json()
                
                if data.get("email") != TEST_EMAIL:
                    self.failure(test_name, "Wrong user returned")
                    return False
                
                self.success(test_name)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_06_invalid_api_key(self) -> bool:
        """Test that invalid API key is rejected"""
        test_name = "Reject invalid API key"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/auth/users/me",
                    headers={"X-API-Key": "wsk_invalid.1234567890abcdef"}
                )
                
                if response.status_code == 200:
                    self.failure(test_name, "Invalid API key was accepted!")
                    return False
                
                if response.status_code != 401:
                    self.failure(test_name, f"Expected 401, got {response.status_code}")
                    return False
                
                self.success(test_name)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_07_revoke_api_key(self) -> bool:
        """Test revoking an API key"""
        test_name = "Revoke API key"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    f"{self.base_url}/auth/teams/{self.team_id}/api-keys/{self.api_key_prefix}",
                    headers={"Authorization": f"Bearer {self.access_token}"}
                )
                
                if response.status_code != 200:
                    self.failure(test_name, f"Status {response.status_code}: {response.text}")
                    return False
                
                self.success(test_name)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_08_revoked_key_rejected(self) -> bool:
        """Test that revoked API key is rejected"""
        test_name = "Reject revoked API key"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/auth/users/me",
                    headers={"X-API-Key": self.api_key}
                )
                
                if response.status_code == 200:
                    self.failure(test_name, "Revoked API key was accepted!")
                    return False
                
                if response.status_code != 401:
                    self.failure(test_name, f"Expected 401, got {response.status_code}")
                    return False
                
                self.success(test_name)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def run_all_tests(self):
        """Run all tests in sequence"""
        self.log("\n" + "="*60, Colors.BLUE)
        self.log("API Key Authentication End-to-End Test", Colors.BLUE)
        self.log(f"Testing against: {self.base_url}", Colors.BLUE)
        self.log("="*60 + "\n", Colors.BLUE)
        
        tests = [
            self.test_01_login,
            self.test_02_get_user_info,
            self.test_03_create_api_key,
            self.test_04_list_api_keys,
            self.test_05_authenticate_with_api_key,
            self.test_06_invalid_api_key,
            self.test_07_revoke_api_key,
            self.test_08_revoked_key_rejected,
        ]
        
        for test in tests:
            result = await test()
            if not result:
                self.log(f"\nTest failed: {test.__name__}", Colors.RED)
                self.log("Stopping test execution\n", Colors.RED)
                break
            await asyncio.sleep(0.5)  # Brief pause between tests
        
        # Print summary
        self.log("\n" + "="*60, Colors.BLUE)
        self.log("Test Summary", Colors.BLUE)
        self.log("="*60, Colors.BLUE)
        
        passed = sum(1 for _, result in self.test_results if result)
        total = len(self.test_results)
        
        self.log(f"Passed: {passed}/{total}", Colors.GREEN if passed == total else Colors.YELLOW)
        
        if passed == total:
            self.log("\n✓ All tests passed!", Colors.GREEN)
            return 0
        else:
            self.log(f"\n✗ {total - passed} test(s) failed", Colors.RED)
            return 1


async def main():
    """Main entry point"""
    tester = APIKeyTester()
    exit_code = await tester.run_all_tests()
    sys.exit(exit_code)


if __name__ == "__main__":
    asyncio.run(main())
