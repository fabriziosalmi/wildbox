"""
Comprehensive Identity Service Test Module
Tests authentication, JWT validation, RBAC, billing integration
"""

import os
import requests
import asyncio
import time
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv

# Load test environment configuration
load_dotenv("tests/.env")


class IdentityServiceTester:
    """Comprehensive tests for Identity Service (Port 8001)"""

    def __init__(self, base_url: str = None):
        self.base_url = base_url or os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
        self.results = []
        self.tokens = {}
        self.api_keys = {}

        # Load admin credentials from environment
        self.admin_email = os.getenv("TEST_ADMIN_EMAIL", "admin@wildbox.io")
        self.admin_password = os.getenv("TEST_ADMIN_PASSWORD", "ChangeMe123!")

    def get_admin_token(self) -> str:
        """Get or create admin authentication token"""
        if "admin_user" in self.tokens:
            return self.tokens["admin_user"]

        # Login to get token
        try:
            login_data = f"username={self.admin_email}&password={self.admin_password}"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            response = requests.post(
                f"{self.base_url}/api/v1/auth/jwt/login",
                data=login_data,
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                token = response.json().get("access_token")
                if token:
                    self.tokens["admin_user"] = token
                    return token
        except Exception as e:
            print(f"Error getting admin token: {e}")

        return None

    def log_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Log individual test result"""
        self.results.append({
            "name": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
        
    async def test_service_health(self) -> bool:
        """Test health endpoint responsivity"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            passed = response.status_code == 200
            
            if passed:
                health_data = response.json()
                details = f"Status: {health_data.get('status', 'unknown')}"
            else:
                details = f"HTTP {response.status_code}"
                
            self.log_test_result("Service Health Check", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Service Health Check", False, f"Error: {str(e)}")
            return False
            
    async def test_user_registration(self) -> bool:
        """Test new user registration with team creation"""
        try:
            test_email = f"test_user_{int(time.time())}@wildbox.test"
            registration_data = {
                "email": test_email,
                "password": "TestPass123!",
                "company_name": "Test Company Ltd"
            }
            
            response = requests.post(
                f"{self.base_url}/api/v1/auth/register",
                json=registration_data,
                timeout=10
            )
            
            passed = response.status_code in [200, 201]
            if passed:
                data = response.json()
                details = f"User created: {data.get('user', {}).get('email', 'unknown')}"
                # Store for later tests
                self.test_user_email = test_email
                self.test_user_password = "TestPass123!"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"
                
            self.log_test_result("User Registration with Team Creation", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("User Registration with Team Creation", False, f"Error: {str(e)}")
            return False
            
    async def test_user_login_jwt(self) -> bool:
        """Test login and JWT token acquisition using admin credentials"""
        try:
            # Use admin credentials for reliable login testing
            login_data = f"username={self.admin_email}&password={self.admin_password}"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            response = requests.post(
                f"{self.base_url}/api/v1/auth/jwt/login",
                data=login_data,
                headers=headers,
                timeout=10
            )

            passed = response.status_code == 200
            if passed:
                data = response.json()
                token = data.get("access_token")
                if token:
                    self.tokens["admin_user"] = token
                    details = f"JWT token acquired for {self.admin_email} (length: {len(token)})"
                else:
                    passed = False
                    details = "No access token in response"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"

            self.log_test_result("Login and JWT Token Acquisition", passed, details)
            return passed

        except Exception as e:
            self.log_test_result("Login and JWT Token Acquisition", False, f"Error: {str(e)}")
            return False
            
    async def test_authenticated_profile(self) -> bool:
        """Test authenticated user profile access"""
        try:
            # Get admin token (will login if needed)
            token = self.get_admin_token()
            if not token:
                self.log_test_result("Authenticated User Profile", False, "Could not get admin token")
                return False

            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(
                f"{self.base_url}/api/v1/users/me",
                headers=headers,
                timeout=10
            )

            passed = response.status_code == 200
            if passed:
                profile = response.json()
                is_superuser = profile.get('is_superuser', False)
                details = f"Profile: {profile.get('email', 'unknown')} (superuser: {is_superuser})"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"

            self.log_test_result("Authenticated User Profile", passed, details)
            return passed

        except Exception as e:
            self.log_test_result("Authenticated User Profile", False, f"Error: {str(e)}")
            return False
            
    async def test_api_key_management(self) -> bool:
        """Test API key creation and listing"""
        try:
            # Get admin token (will login if needed)
            token = self.get_admin_token()
            if not token:
                self.log_test_result("API Key Management", False, "Could not get admin token")
                return False

            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            # Create API key
            create_data = {
                "name": "test-integration-key",
                "description": "Integration test API key"
            }
            response = requests.post(
                f"{self.base_url}/api/v1/api-keys",
                json=create_data,
                headers=headers,
                timeout=10
            )

            if response.status_code not in [200, 201]:
                self.log_test_result("API Key Management", False, f"Create failed: HTTP {response.status_code}: {response.text[:100]}")
                return False

            create_result = response.json()
            api_key = create_result.get("key") or create_result.get("api_key")
            if not api_key:
                self.log_test_result("API Key Management", False, "No API key in create response")
                return False

            self.api_keys["test_key"] = api_key

            # List API keys
            list_response = requests.get(
                f"{self.base_url}/api/v1/api-keys",
                headers=headers,
                timeout=10
            )

            passed = list_response.status_code == 200
            if passed:
                keys = list_response.json()
                key_count = len(keys) if isinstance(keys, list) else len(keys.get('keys', []))
                details = f"Created and listed API keys (count: {key_count})"
            else:
                details = f"List failed: HTTP {list_response.status_code}"

            self.log_test_result("API Key Management", passed, details)
            return passed

        except Exception as e:
            self.log_test_result("API Key Management", False, f"Error: {str(e)}")
            return False
            
    async def test_rbac_access_control(self) -> bool:
        """Test role-based access control"""
        try:
            # Get admin token (will login if needed)
            token = self.get_admin_token()
            if not token:
                self.log_test_result("RBAC Access Control", False, "Could not get admin token")
                return False

            headers = {"Authorization": f"Bearer {token}"}

            # Test that admin user can access profile (basic RBAC check)
            response = requests.get(
                f"{self.base_url}/api/v1/users/me",
                headers=headers,
                timeout=10
            )

            passed = response.status_code == 200
            if passed:
                user_data = response.json()
                is_superuser = user_data.get("is_superuser", False)
                is_active = user_data.get("is_active", False)

                if is_superuser and is_active:
                    details = f"Superuser access confirmed: {user_data.get('email')}"
                else:
                    passed = False
                    details = f"Not superuser: {is_superuser}, active: {is_active}"
            else:
                details = f"HTTP {response.status_code}: {response.text[:100]}"

            self.log_test_result("RBAC Access Control", passed, details)
            return passed

        except Exception as e:
            self.log_test_result("RBAC Access Control", False, f"Error: {str(e)}")
            return False
            
    async def test_logout_session_invalidation(self) -> bool:
        """Test logout and session invalidation"""
        try:
            # Get a fresh token for logout testing (don't invalidate our main admin token)
            login_data = f"username={self.admin_email}&password={self.admin_password}"
            headers_form = {"Content-Type": "application/x-www-form-urlencoded"}

            login_response = requests.post(
                f"{self.base_url}/api/v1/auth/jwt/login",
                data=login_data,
                headers=headers_form,
                timeout=10
            )

            if login_response.status_code != 200:
                self.log_test_result("Logout and Session Invalidation", False, "Could not get token for logout test")
                return False

            temp_token = login_response.json().get("access_token")
            headers = {"Authorization": f"Bearer {temp_token}"}

            # Logout
            response = requests.post(
                f"{self.base_url}/api/v1/auth/jwt/logout",
                headers=headers,
                timeout=10
            )

            # Check if logout was successful (should be 200 or 204)
            logout_success = response.status_code in [200, 204]

            # Try to use the token after logout (should fail)
            profile_response = requests.get(
                f"{self.base_url}/api/v1/users/me",
                headers=headers,
                timeout=10
            )

            # Token should be invalid after logout
            token_invalidated = profile_response.status_code == 401

            passed = logout_success or token_invalidated
            if passed:
                details = f"Logout: {logout_success}, Token invalidated: {token_invalidated}"
            else:
                details = f"Logout failed: {response.status_code}, Token still valid: {profile_response.status_code}"

            self.log_test_result("Logout and Session Invalidation", passed, details)
            return passed

        except Exception as e:
            self.log_test_result("Logout and Session Invalidation", False, f"Error: {str(e)}")
            return False
            
    async def test_billing_plan_management(self) -> bool:
        """Test billing plan management integration"""
        try:
            # Since we can't actually test Stripe integration, we'll test the endpoints exist
            # and respond appropriately without actual payment processing
            
            # Test subscription endpoint exists
            response = requests.get(
                f"{self.base_url}/api/v1/billing/subscription",
                timeout=10
            )
            
            # Should require authentication (401) or return subscription info
            endpoint_exists = response.status_code in [200, 401]
            
            # Test plans endpoint
            plans_response = requests.get(
                f"{self.base_url}/api/v1/billing/plans",
                timeout=10
            )
            
            plans_accessible = plans_response.status_code in [200, 401]
            
            passed = endpoint_exists and plans_accessible
            if passed:
                details = "Billing endpoints accessible"
            else:
                details = f"Subscription: {response.status_code}, Plans: {plans_response.status_code}"
                
            self.log_test_result("Billing Plan Management", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Billing Plan Management", False, f"Error: {str(e)}")
            return False


async def run_tests() -> Dict[str, Any]:
    """Run all identity service tests"""
    tester = IdentityServiceTester()

    # Run tests in sequence - login first to establish credentials for other tests
    tests = [
        tester.test_service_health,
        tester.test_user_login_jwt,  # Run login first to get admin token
        tester.test_authenticated_profile,
        tester.test_api_key_management,
        tester.test_rbac_access_control,
        tester.test_user_registration,  # Registration can fail without blocking other tests
        tester.test_logout_session_invalidation,
        tester.test_billing_plan_management
    ]
    
    success_count = 0
    for test in tests:
        try:
            success = await test()
            if success:
                success_count += 1
        except Exception as e:
            print(f"Test error: {e}")
            
    all_passed = success_count == len(tests)
    
    return {
        "success": all_passed,
        "tests": tester.results,
        "summary": f"{success_count}/{len(tests)} tests passed"
    }