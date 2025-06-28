"""
Comprehensive Identity Service Test Module
Tests authentication, JWT validation, RBAC, billing integration
"""

import requests
import asyncio
import time
from typing import Dict, List, Any, Optional


class IdentityServiceTester:
    """Comprehensive tests for Identity Service (Port 8001)"""
    
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.test_results = []
        self.tokens = {}
        self.api_keys = {}
        
    def log_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Log individual test result"""
        self.test_results.append({
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
        """Test login and JWT token acquisition"""
        try:
            if not hasattr(self, 'test_user_email'):
                self.log_test_result("Login and JWT Token Acquisition", False, "No test user available")
                return False
                
            login_data = f"username={self.test_user_email}&password={self.test_user_password}"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            
            response = requests.post(
                f"{self.base_url}/api/v1/auth/login",
                data=login_data,
                headers=headers,
                timeout=10
            )
            
            passed = response.status_code == 200
            if passed:
                data = response.json()
                token = data.get("access_token")
                if token:
                    self.tokens["test_user"] = token
                    details = f"JWT token acquired (length: {len(token)})"
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
            if "test_user" not in self.tokens:
                self.log_test_result("Authenticated User Profile", False, "No JWT token available")
                return False
                
            headers = {"Authorization": f"Bearer {self.tokens['test_user']}"}
            response = requests.get(
                f"{self.base_url}/api/v1/auth/me",
                headers=headers,
                timeout=10
            )
            
            passed = response.status_code == 200
            if passed:
                profile = response.json()
                details = f"Profile: {profile.get('email', 'unknown')} (role: {profile.get('role', 'unknown')})"
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
            if "test_user" not in self.tokens:
                self.log_test_result("API Key Management", False, "No JWT token available")
                return False
                
            headers = {"Authorization": f"Bearer {self.tokens['test_user']}"}
            
            # Create API key
            create_data = {"name": "test-pulse-check-key"}
            response = requests.post(
                f"{self.base_url}/api/v1/auth/api-keys",
                json=create_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code not in [200, 201]:
                self.log_test_result("API Key Management", False, f"Create failed: HTTP {response.status_code}")
                return False
                
            create_result = response.json()
            api_key = create_result.get("api_key")
            if not api_key:
                self.log_test_result("API Key Management", False, "No API key in create response")
                return False
                
            self.api_keys["test_key"] = api_key
            
            # List API keys
            list_response = requests.get(
                f"{self.base_url}/api/v1/auth/api-keys",
                headers=headers,
                timeout=10
            )
            
            passed = list_response.status_code == 200
            if passed:
                keys = list_response.json()
                details = f"Created and listed API keys (count: {len(keys)})"
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
            if "test_user" not in self.tokens:
                self.log_test_result("RBAC Access Control", False, "No JWT token available")
                return False
                
            headers = {"Authorization": f"Bearer {self.tokens['test_user']}"}
            
            # Test internal authorization endpoint
            auth_test_data = {"headers": {"Authorization": f"Bearer {self.tokens['test_user']}"}}
            response = requests.post(
                f"{self.base_url}/internal/authorize",
                json=auth_test_data,
                timeout=10
            )
            
            passed = response.status_code == 200
            if passed:
                auth_result = response.json()
                is_authenticated = auth_result.get("is_authenticated", False)
                user_role = auth_result.get("role", "unknown")
                permissions = auth_result.get("permissions", [])
                
                if is_authenticated:
                    details = f"Authenticated: {user_role} role, {len(permissions)} permissions"
                else:
                    passed = False
                    details = "Authorization failed"
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
            if "test_user" not in self.tokens:
                self.log_test_result("Logout and Session Invalidation", False, "No JWT token available")
                return False
                
            headers = {"Authorization": f"Bearer {self.tokens['test_user']}"}
            
            # Logout
            response = requests.post(
                f"{self.base_url}/api/v1/auth/logout",
                headers=headers,
                timeout=10
            )
            
            # Check if logout was successful (should be 200 or 204)
            logout_success = response.status_code in [200, 204]
            
            # Try to use the token after logout (should fail)
            profile_response = requests.get(
                f"{self.base_url}/api/v1/auth/me",
                headers=headers,
                timeout=10
            )
            
            # Token should be invalid after logout
            token_invalidated = profile_response.status_code == 401
            
            passed = logout_success and token_invalidated
            if passed:
                details = "Logout successful, token invalidated"
            else:
                details = f"Logout: {logout_success}, Token invalidated: {token_invalidated}"
                
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
    
    # Run tests in sequence
    tests = [
        tester.test_service_health,
        tester.test_user_registration,
        tester.test_user_login_jwt,
        tester.test_authenticated_profile,
        tester.test_api_key_management,
        tester.test_rbac_access_control,
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
        "tests": tester.test_results,
        "summary": f"{success_count}/{len(tests)} tests passed"
    }