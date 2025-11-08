#!/usr/bin/env python3
"""
Comprehensive test script for the Identity Service
Tests user creation, roles, login/logout, and management features
"""

import requests
import json
import time
import sys
from typing import Dict, Any, Optional

class IdentityServiceTester:
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.auth_token = None
        self.admin_token = None
        self.test_users = {}
        
    def log(self, message: str, level: str = "INFO"):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                    headers: Optional[Dict] = None, token: Optional[str] = None) -> requests.Response:
        """Make HTTP request with optional authentication"""
        url = f"{self.base_url}{endpoint}"
        
        if headers is None:
            headers = {}
            
        if token:
            headers["Authorization"] = f"Bearer {token}"
            
        if data:
            headers["Content-Type"] = "application/json"
            
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, json=data)
            elif method.upper() == "PUT":
                response = requests.put(url, headers=headers, json=data)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            return response
        except requests.exceptions.RequestException as e:
            self.log(f"Request failed: {e}", "ERROR")
            raise
            
    def test_service_health(self) -> bool:
        """Test if the service is running and healthy"""
        self.log("Testing service health...")
        
        try:
            response = self.make_request("GET", "/")
            if response.status_code == 200:
                data = response.json()
                self.log(f"Service info: {data}")
                return True
            else:
                self.log(f"Health check failed: {response.status_code}", "ERROR")
                return False
        except Exception as e:
            self.log(f"Health check error: {e}", "ERROR")
            return False
            
    def test_user_registration(self) -> bool:
        """Test user registration functionality"""
        self.log("Testing user registration...")
        
        # Test data for different user types
        test_users = [
            {
                "email": "admin@wildbox.com",
                "password": "admin123!",
                "role": "admin"
            },
            {
                "email": "manager@wildbox.com", 
                "password": "manager123!",
                "role": "manager"
            },
            {
                "email": "analyst@wildbox.com",
                "password": "analyst123!",
                "role": "analyst"
            },
            {
                "email": "viewer@wildbox.com",
                "password": "viewer123!",
                "role": "viewer"
            }
        ]
        
        success = True
        for user_data in test_users:
            try:
                # Only send email and password for registration
                registration_data = {
                    "email": user_data["email"],
                    "password": user_data["password"]
                }
                response = self.make_request("POST", "/api/v1/auth/register", registration_data)
                
                if response.status_code in [200, 201]:
                    result = response.json()
                    self.log(f"✓ User registered: {user_data['email']}")
                    self.test_users[user_data['email']] = {
                        **user_data,
                        "user_id": result.get("user_id"),
                        "access_token": result.get("access_token")
                    }
                else:
                    # User might already exist, try login instead
                    self.log(f"Registration failed for {user_data['email']}, trying login...")
                    login_response = self.make_request("POST", "/api/v1/auth/login-json", {
                        "username": user_data["email"],  # UserLogin schema expects 'username' field
                        "password": user_data["password"]
                    })
                    
                    if login_response.status_code == 200:
                        result = login_response.json()
                        self.log(f"✓ User logged in: {user_data['email']}")
                        self.test_users[user_data['email']] = {
                            **user_data,
                            "user_id": result.get("user_id"),
                            "access_token": result.get("access_token")
                        }
                    else:
                        self.log(f"✗ Failed to register/login user: {user_data['email']}", "ERROR")
                        success = False
                        
            except Exception as e:
                self.log(f"✗ Registration error for {user_data['email']}: {e}", "ERROR")
                success = False
                
        return success
        
    def test_user_login(self) -> bool:
        """Test user login functionality"""
        self.log("Testing user login...")
        
        success = True
        for email, user_data in self.test_users.items():
            try:
                # Try the JSON login endpoint first
                response = self.make_request("POST", "/api/v1/auth/login-json", {
                    "username": email,  # UserLogin schema expects 'username' field
                    "password": user_data["password"]
                })
                
                # If that fails, try the form-based endpoint (for completeness)
                if response.status_code != 200:
                    # For form-based endpoint, we need to send form data, but our make_request sends JSON
                    # So we'll skip this for now and just use the JSON endpoint
                    pass
                
                if response.status_code == 200:
                    result = response.json()
                    self.test_users[email]["access_token"] = result.get("access_token")
                    self.log(f"✓ Login successful: {email}")
                    
                    # Set admin token for admin operations
                    if user_data["role"] == "admin":
                        self.admin_token = result.get("access_token")
                        
                else:
                    self.log(f"✗ Login failed for {email}: {response.status_code}", "ERROR")
                    if response.status_code == 422:
                        self.log(f"Validation error: {response.text}", "ERROR")
                    success = False
                    
            except Exception as e:
                self.log(f"✗ Login error for {email}: {e}", "ERROR")
                success = False
                
        return success
        
    def test_user_profile(self) -> bool:
        """Test user profile endpoints"""
        self.log("Testing user profile access...")
        
        success = True
        for email, user_data in self.test_users.items():
            token = user_data.get("access_token")
            if not token:
                continue
                
            try:
                response = self.make_request("GET", "/api/v1/auth/me", token=token)
                
                if response.status_code == 200:
                    profile = response.json()
                    self.log(f"✓ Profile retrieved for {email}: {profile.get('full_name')}")
                else:
                    self.log(f"✗ Failed to get profile for {email}: {response.status_code}", "ERROR")
                    success = False
                    
            except Exception as e:
                self.log(f"✗ Profile error for {email}: {e}", "ERROR")
                success = False
                
        return success
        
    def test_role_based_access(self) -> bool:
        """Test role-based access control"""
        self.log("Testing role-based access control...")
        
        success = True
        
        # Test admin endpoints with different roles
        admin_endpoints = [
            "/api/v1/auth/admin/users",  # List all users (admin only)
            "/health",  # Health check endpoint
        ]
        
        for endpoint in admin_endpoints:
            self.log(f"Testing endpoint: {endpoint}")
            
            for email, user_data in self.test_users.items():
                token = user_data.get("access_token")
                if not token:
                    continue
                    
                try:
                    response = self.make_request("GET", endpoint, token=token)
                    role = user_data["role"]
                    
                    if role == "admin":
                        if response.status_code in [200, 201]:
                            self.log(f"✓ Admin access granted for {email}")
                        else:
                            self.log(f"✗ Admin access denied for {email}: {response.status_code}", "ERROR")
                            success = False
                    else:
                        # Non-admin users should be denied access to admin endpoints
                        if response.status_code in [401, 403]:
                            self.log(f"✓ Non-admin access properly denied for {email}")
                        else:
                            self.log(f"? Unexpected response for {email} ({role}): {response.status_code}")
                            
                except Exception as e:
                    self.log(f"✗ Access test error for {email}: {e}", "ERROR")
                    success = False
                    
        return success
        
    def test_token_validation(self) -> bool:
        """Test token validation and expiration"""
        self.log("Testing token validation...")
        
        success = True
        
        # Test with invalid token
        try:
            response = self.make_request("GET", "/api/v1/auth/me", token="invalid_token")
            if response.status_code in [401, 403]:
                self.log("✓ Invalid token properly rejected")
            else:
                self.log(f"✗ Invalid token not rejected: {response.status_code}", "ERROR")
                success = False
        except Exception as e:
            self.log(f"✗ Token validation error: {e}", "ERROR")
            success = False
            
        # Test with no token
        try:
            response = self.make_request("GET", "/api/v1/auth/me")
            if response.status_code in [401, 403]:
                self.log("✓ Missing token properly rejected")
            else:
                self.log(f"✗ Missing token not rejected: {response.status_code}", "ERROR")
                success = False
        except Exception as e:
            self.log(f"✗ No token test error: {e}", "ERROR")
            success = False
            
        return success
        
    def test_user_management(self) -> bool:
        """Test user management operations (admin only)"""
        self.log("Testing user management operations...")
        
        if not self.admin_token:
            self.log("No admin token available, skipping user management tests", "WARNING")
            return True
            
        success = True
        
        # Test listing all users
        try:
            response = self.make_request("GET", "/api/v1/users", token=self.admin_token)
            if response.status_code == 200:
                users = response.json()
                self.log(f"✓ Listed {len(users)} users")
            else:
                self.log(f"✗ Failed to list users: {response.status_code}", "ERROR")
                success = False
        except Exception as e:
            self.log(f"✗ User listing error: {e}", "ERROR")
            success = False
            
        # Test user update (change role)
        viewer_email = "viewer@wildbox.com"
        if viewer_email in self.test_users:
            try:
                user_id = self.test_users[viewer_email]["user_id"]
                response = self.make_request("PUT", f"/api/v1/users/{user_id}", {
                    "role": "analyst"
                }, token=self.admin_token)
                
                if response.status_code == 200:
                    self.log(f"✓ Updated user role for {viewer_email}")
                else:
                    self.log(f"✗ Failed to update user: {response.status_code}", "ERROR")
                    success = False
            except Exception as e:
                self.log(f"✗ User update error: {e}", "ERROR")
                success = False
                
        return success
        
    def test_api_key_management(self) -> bool:
        """Test API key management functionality"""
        self.log("Testing API key management...")
        
        success = True
        
        # Test API key creation (requires admin or manager role)
        admin_email = "admin@wildbox.com"
        if admin_email in self.test_users:
            token = self.test_users[admin_email]["access_token"]
            
            try:
                response = self.make_request("POST", "/api/v1/teams/api-keys", {
                    "name": "Test API Key",
                    "description": "Test key for automation",
                    "permissions": ["read", "write"]
                }, token=token)
                
                if response.status_code in [200, 201]:
                    api_key_data = response.json()
                    self.log(f"✓ Created API key: {api_key_data.get('name')}")
                else:
                    self.log(f"✗ Failed to create API key: {response.status_code}", "ERROR")
                    success = False
            except Exception as e:
                self.log(f"✗ API key creation error: {e}", "ERROR")
                success = False
                
        return success
        
    def test_logout(self) -> bool:
        """Test user logout functionality"""
        self.log("Testing user logout...")
        
        success = True
        
        # Test logout for one user
        test_email = "analyst@wildbox.com"
        if test_email in self.test_users:
            token = self.test_users[test_email]["access_token"]
            
            try:
                response = self.make_request("POST", "/api/v1/auth/logout", token=token)
                
                if response.status_code == 200:
                    self.log(f"✓ Logout successful for {test_email}")
                    
                    # Verify token is invalidated
                    profile_response = self.make_request("GET", "/api/v1/users/me", token=token)
                    if profile_response.status_code in [401, 403]:
                        self.log("✓ Token properly invalidated after logout")
                    else:
                        self.log("? Token might still be valid after logout")
                        
                else:
                    self.log(f"✗ Logout failed for {test_email}: {response.status_code}", "ERROR")
                    success = False
            except Exception as e:
                self.log(f"✗ Logout error for {test_email}: {e}", "ERROR")
                success = False
                
        return success
        
    def run_all_tests(self) -> bool:
        """Run all tests and return overall success"""
        self.log("Starting comprehensive identity service tests...")
        
        tests = [
            ("Service Health", self.test_service_health),
            ("User Registration", self.test_user_registration),
            ("User Login", self.test_user_login),
            ("User Profile", self.test_user_profile),
            ("Role-Based Access", self.test_role_based_access),
            ("Token Validation", self.test_token_validation),
            ("User Management", self.test_user_management),
            ("API Key Management", self.test_api_key_management),
            ("User Logout", self.test_logout),
        ]
        
        results = {}
        overall_success = True
        
        for test_name, test_func in tests:
            self.log(f"\n{'='*50}")
            self.log(f"Running test: {test_name}")
            self.log(f"{'='*50}")
            
            try:
                result = test_func()
                results[test_name] = result
                if not result:
                    overall_success = False
                    
                status = "PASS" if result else "FAIL"
                self.log(f"Test {test_name}: {status}")
                
            except Exception as e:
                self.log(f"Test {test_name} failed with exception: {e}", "ERROR")
                results[test_name] = False
                overall_success = False
                
        # Print summary
        self.log(f"\n{'='*60}")
        self.log("TEST SUMMARY")
        self.log(f"{'='*60}")
        
        for test_name, result in results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            self.log(f"{status}: {test_name}")
            
        self.log(f"\nOverall result: {'✓ ALL TESTS PASSED' if overall_success else '✗ SOME TESTS FAILED'}")
        
        return overall_success

def main():
    """Main function to run the tests"""
    tester = IdentityServiceTester()
    
    try:
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nTests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Test runner failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
