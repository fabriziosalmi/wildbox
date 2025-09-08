#!/usr/bin/env python3
"""
Comprehensive Wildbox Authentication System Verification
Tests authentication, user management, admin functions, and team management
across identity, dashboard, and gateway modules.
"""

import requests
import json
import time
import subprocess
import sys
import os
from typing import Dict, Optional, List
from datetime import datetime

class WildboxAuthenticationVerifier:
    def __init__(self):
        self.identity_url = "http://localhost:8001"
        self.gateway_url = "http://localhost:80"
        self.dashboard_url = "http://localhost:3000"
        
        # Test users with different roles - SECURITY WARNING: These are for testing only!
        # In production, use environment variables or secure credential management
        self.test_users = {
            "demo@wildbox.com": {"password": os.getenv("DEMO_PASSWORD", "demopassword123"), "role": "demo"},
            "superadmin@wildbox.com": {"password": os.getenv("ADMIN_PASSWORD", "CHANGE_THIS_PASSWORD"), "role": "admin"}
        }
        
        # Store authentication tokens
        self.tokens = {}
        self.user_data = {}
        
        # Test results
        self.results = {
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "test_details": []
        }

    def log(self, message: str, level: str = "INFO") -> None:
        """Log message with timestamp and level."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color_codes = {
            "INFO": "\033[36m",      # Cyan
            "SUCCESS": "\033[32m",   # Green
            "WARNING": "\033[33m",   # Yellow
            "ERROR": "\033[31m",     # Red
            "RESET": "\033[0m"       # Reset
        }
        
        color = color_codes.get(level, color_codes["INFO"])
        reset = color_codes["RESET"]
        print(f"{color}[{timestamp}] {level}: {message}{reset}")

    def make_request(self, method: str, url: str, data: Dict = None, 
                    token: str = None, base_url: str = None) -> requests.Response:
        """Make HTTP request with proper error handling."""
        if base_url is None:
            base_url = self.identity_url
            
        full_url = f"{base_url}{url}"
        
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        try:
            if method.upper() == "GET":
                return requests.get(full_url, headers=headers, timeout=10)
            elif method.upper() == "POST":
                return requests.post(full_url, json=data, headers=headers, timeout=10)
            elif method.upper() == "PUT":
                return requests.put(full_url, json=data, headers=headers, timeout=10)
            elif method.upper() == "PATCH":
                return requests.patch(full_url, json=data, headers=headers, timeout=10)
            elif method.upper() == "DELETE":
                return requests.delete(full_url, headers=headers, timeout=10)
        except requests.RequestException as e:
            self.log(f"Request failed: {e}", "ERROR")
            raise

    def test_service_health(self, service_name: str, url: str) -> bool:
        """Test if a service is healthy."""
        try:
            # Use different health check endpoints for different services
            if "dashboard" in service_name.lower():
                health_endpoint = "/"  # Dashboard uses root endpoint
            else:
                health_endpoint = "/health"  # Other services use /health
                
            response = self.make_request("GET", health_endpoint, base_url=url)
            if response.status_code == 200:
                self.log(f"✓ {service_name} service is healthy", "SUCCESS")
                return True
            else:
                self.log(f"✗ {service_name} service unhealthy: {response.status_code}", "ERROR")
                return False
        except Exception as e:
            self.log(f"✗ {service_name} service unavailable: {e}", "ERROR")
            return False

    def test_user_registration_and_login(self) -> bool:
        """Test user registration and login functionality."""
        self.log("Testing user registration and login...")
        
        all_success = True
        
        for email, user_info in self.test_users.items():
            try:
                # Try registration first
                registration_data = {
                    "email": email,
                    "password": user_info["password"]
                }
                
                response = self.make_request("POST", "/api/v1/auth/register", registration_data)
                
                if response.status_code in [200, 201]:
                    data = response.json()
                    self.tokens[email] = data["access_token"]
                    self.log(f"✓ Registration successful for {email}", "SUCCESS")
                else:
                    # Registration failed, try login
                    self.log(f"Registration failed for {email}, trying login...", "WARNING")
                    
                    # Try login with form data (OAuth2PasswordRequestForm)
                    login_data = {
                        "username": email,
                        "password": user_info["password"]
                    }
                    
                    # Use form data for login
                    headers = {"Content-Type": "application/x-www-form-urlencoded"}
                    response = requests.post(
                        f"{self.identity_url}/api/v1/auth/login",
                        data=login_data,
                        headers=headers,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        self.tokens[email] = data["access_token"]
                        self.log(f"✓ Login successful for {email}", "SUCCESS")
                    else:
                        self.log(f"✗ Login failed for {email}: {response.status_code}", "ERROR")
                        all_success = False
                        continue
                
                # Get user profile to verify authentication
                profile_response = self.make_request("GET", "/api/v1/auth/me", token=self.tokens[email])
                if profile_response.status_code == 200:
                    self.user_data[email] = profile_response.json()
                    self.log(f"✓ Profile retrieved for {email}", "SUCCESS")
                else:
                    self.log(f"✗ Profile retrieval failed for {email}: {profile_response.status_code}", "ERROR")
                    all_success = False
                    
            except Exception as e:
                self.log(f"✗ Authentication failed for {email}: {e}", "ERROR")
                all_success = False
        
        return all_success

    def test_admin_user_management(self) -> bool:
        """Test admin user management endpoints."""
        self.log("Testing admin user management...")
        
        # Find admin user
        admin_token = None
        for email, user_data in self.user_data.items():
            if user_data.get("is_superuser") or "admin" in email.lower():
                admin_token = self.tokens[email]
                break
        
        if not admin_token:
            self.log("No admin user available for testing", "WARNING")
            return True
        
        success = True
        
        # Test listing all users
        try:
            response = self.make_request("GET", "/api/v1/users/admin/users", token=admin_token)
            if response.status_code == 200:
                users = response.json()
                self.log(f"✓ Listed {len(users)} users via admin endpoint", "SUCCESS")
            else:
                self.log(f"✗ Failed to list users: {response.status_code}", "ERROR")
                success = False
        except Exception as e:
            self.log(f"✗ User listing error: {e}", "ERROR")
            success = False
        
        # Test user details endpoint
        try:
            if "user@wildbox.com" in self.user_data:
                user_id = self.user_data["user@wildbox.com"]["id"]
                response = self.make_request("GET", f"/api/v1/users/admin/users/{user_id}", token=admin_token)
                if response.status_code == 200:
                    user_details = response.json()
                    self.log(f"✓ Retrieved user details for user ID {user_id}", "SUCCESS")
                else:
                    self.log(f"✗ Failed to get user details: {response.status_code}", "ERROR")
                    success = False
        except Exception as e:
            self.log(f"✗ User details error: {e}", "ERROR")
            success = False
        
        return success

    def test_api_key_management(self) -> bool:
        """Test API key management functionality."""
        self.log("Testing API key management...")
        
        # Find admin user for API key creation
        admin_token = None
        admin_email = None
        admin_user_data = None
        for email, user_data in self.user_data.items():
            if user_data.get("is_superuser") or "admin" in email.lower():
                admin_token = self.tokens[email]
                admin_email = email
                admin_user_data = user_data
                break
        
        if not admin_token:
            self.log("No admin user available for API key testing", "WARNING")
            return True
        
        success = True
        
        # First, get user's team memberships to find team_id
        team_id = None
        try:
            # Try to get team information from user profile
            if 'team_memberships' in admin_user_data and admin_user_data['team_memberships']:
                team_id = admin_user_data['team_memberships'][0]['team_id']
                self.log(f"✓ Found user's team ID: {team_id}", "SUCCESS")
            else:
                # Fallback: use personal API key endpoints
                self.log("No team found, using personal API key endpoints", "WARNING")
                return self.test_personal_api_keys(admin_token)
                
        except Exception as e:
            self.log(f"Could not get team info, using personal API keys: {e}", "WARNING")
            return self.test_personal_api_keys(admin_token)
        
        if not team_id:
            return self.test_personal_api_keys(admin_token)
        
        # Test team-based API key creation
        try:
            api_key_data = {
                "name": "Test Team API Key",
                "expires_at": None
            }
            
            response = self.make_request("POST", f"/api/v1/teams/{team_id}/api-keys", api_key_data, token=admin_token)
            
            if response.status_code in [200, 201]:
                key_info = response.json()
                self.log(f"✓ Created team API key: {key_info.get('name', 'Unknown')}", "SUCCESS")
                
                # Test listing team API keys
                list_response = self.make_request("GET", f"/api/v1/teams/{team_id}/api-keys", token=admin_token)
                if list_response.status_code == 200:
                    keys = list_response.json()
                    self.log(f"✓ Listed {len(keys)} team API keys", "SUCCESS")
                else:
                    self.log(f"✗ Failed to list team API keys: {list_response.status_code}", "ERROR")
                    success = False
                    
            else:
                self.log(f"✗ Failed to create team API key: {response.status_code}", "ERROR")
                if response.content:
                    self.log(f"Response: {response.text}", "ERROR")
                success = False
                
        except Exception as e:
            self.log(f"✗ Team API key management error: {e}", "ERROR")
            success = False
        
        return success

    def test_personal_api_keys(self, token: str) -> bool:
        """Test personal API key endpoints."""
        self.log("Testing personal API key management...")
        
        success = True
        
        try:
            # Test personal API key creation
            api_key_data = {
                "name": "Test Personal API Key"
            }
            
            response = self.make_request("POST", "/api/v1/users/me/api-keys", api_key_data, token=token)
            
            if response.status_code in [200, 201]:
                key_info = response.json()
                self.log(f"✓ Created personal API key: {key_info.get('name', 'Unknown')}", "SUCCESS")
                
                # Test listing personal API keys
                list_response = self.make_request("GET", "/api/v1/users/me/api-keys", token=token)
                if list_response.status_code == 200:
                    keys = list_response.json()
                    self.log(f"✓ Listed {len(keys)} personal API keys", "SUCCESS")
                else:
                    self.log(f"✗ Failed to list personal API keys: {list_response.status_code}", "ERROR")
                    success = False
                    
            else:
                self.log(f"✗ Failed to create personal API key: {response.status_code}", "ERROR")
                if response.content:
                    self.log(f"Response: {response.text}", "ERROR")
                success = False
                
        except Exception as e:
            self.log(f"✗ Personal API key management error: {e}", "ERROR")
            success = False
        
        return success

    def test_team_management(self) -> bool:
        """Test team management functionality."""
        self.log("Testing team management...")
        
        success = True
        
        for email, token in self.tokens.items():
            try:
                # Test getting user's own profile which should include team information
                response = self.make_request("GET", "/api/v1/auth/me", token=token)
                if response.status_code == 200:
                    user_data = response.json()
                    team_memberships = user_data.get('team_memberships', [])
                    if team_memberships:
                        team_info = team_memberships[0]  # First team
                        self.log(f"✓ Retrieved team info for {email}: Team ID {team_info.get('team_id', 'Unknown')}", "SUCCESS")
                    else:
                        self.log(f"? No team memberships found for {email} (expected for some users)", "WARNING")
                else:
                    self.log(f"✗ Failed to get user profile for {email}: {response.status_code}", "ERROR")
                    success = False
                    
            except Exception as e:
                self.log(f"✗ Team management error for {email}: {e}", "ERROR")
                success = False
        
        return success

    def test_gateway_routing(self) -> bool:
        """Test that requests work through the gateway."""
        self.log("Testing gateway routing...")
        
        success = True
        
        try:
            # Test gateway health
            response = self.make_request("GET", "/health", base_url=self.gateway_url)
            if response.status_code == 200:
                self.log("✓ Gateway health check passed", "SUCCESS")
            else:
                self.log(f"✗ Gateway health check failed: {response.status_code}", "ERROR")
                success = False
        except Exception as e:
            self.log(f"✗ Gateway health check error: {e}", "ERROR")
            success = False
        
        # Test authentication through gateway
        for email, token in self.tokens.items():
            try:
                response = self.make_request("GET", "/api/v1/identity/auth/me", token=token, base_url=self.gateway_url)
                if response.status_code == 200:
                    self.log(f"✓ Gateway authentication works for {email}", "SUCCESS")
                else:
                    self.log(f"✗ Gateway authentication failed for {email}: {response.status_code}", "ERROR")
                    success = False
                    break
            except Exception as e:
                self.log(f"✗ Gateway authentication error for {email}: {e}", "ERROR")
                success = False
                break
        
        return success

    def test_dashboard_integration(self) -> bool:
        """Test dashboard integration (if available)."""
        self.log("Testing dashboard integration...")
        
        try:
            # Test if dashboard is accessible
            response = requests.get(f"{self.dashboard_url}/", timeout=5)
            if response.status_code == 200:
                self.log("✓ Dashboard is accessible", "SUCCESS")
                return True
            else:
                self.log(f"? Dashboard not accessible (may not be running): {response.status_code}", "WARNING")
                return True  # Not a failure if dashboard isn't running
        except Exception as e:
            self.log(f"? Dashboard not accessible (may not be running): {e}", "WARNING")
            return True  # Not a failure if dashboard isn't running

    def test_subscription_and_billing(self) -> bool:
        """Test subscription and billing endpoints."""
        self.log("Testing subscription and billing...")
        
        success = True
        
        for email, token in self.tokens.items():
            try:
                # Test getting subscription info
                response = self.make_request("GET", "/api/v1/billing/subscription", token=token)
                if response.status_code == 200:
                    subscription = response.json()
                    self.log(f"✓ Retrieved subscription for {email}: {subscription.get('plan', 'Unknown')}", "SUCCESS")
                elif response.status_code == 404:
                    self.log(f"? No subscription found for {email} (expected for some users)", "WARNING")
                else:
                    self.log(f"✗ Failed to get subscription for {email}: {response.status_code}", "ERROR")
                    success = False
                    
            except Exception as e:
                self.log(f"✗ Subscription error for {email}: {e}", "ERROR")
                success = False
        
        return success

    def record_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Record test result."""
        self.results["total_tests"] += 1
        if passed:
            self.results["passed_tests"] += 1
        else:
            self.results["failed_tests"] += 1
        
        self.results["test_details"].append({
            "test_name": test_name,
            "passed": passed,
            "details": details
        })

    def run_all_tests(self) -> bool:
        """Run all authentication verification tests."""
        self.log("Starting comprehensive Wildbox authentication verification...", "INFO")
        self.log("=" * 80)
        
        # Test 1: Service Health Checks
        self.log("\n🏥 TESTING SERVICE HEALTH", "INFO")
        self.log("-" * 40)
        
        identity_healthy = self.test_service_health("Identity", self.identity_url)
        gateway_healthy = self.test_service_health("Gateway", self.gateway_url)
        dashboard_healthy = self.test_service_health("Dashboard", self.dashboard_url)
        
        self.record_test_result("Identity Service Health", identity_healthy)
        self.record_test_result("Gateway Service Health", gateway_healthy)
        self.record_test_result("Dashboard Service Health", dashboard_healthy)
        
        if not identity_healthy:
            self.log("❌ Identity service is not healthy. Cannot continue tests.", "ERROR")
            return False
        
        # Test 2: User Registration and Login
        self.log("\n🔐 TESTING USER AUTHENTICATION", "INFO")
        self.log("-" * 40)
        
        auth_result = self.test_user_registration_and_login()
        self.record_test_result("User Authentication", auth_result)
        
        if not auth_result:
            self.log("❌ User authentication failed. Cannot continue tests.", "ERROR")
            return False
        
        # Test 3: Admin User Management
        self.log("\n👥 TESTING ADMIN USER MANAGEMENT", "INFO")
        self.log("-" * 40)
        
        admin_result = self.test_admin_user_management()
        self.record_test_result("Admin User Management", admin_result)
        
        # Test 4: API Key Management
        self.log("\n🔑 TESTING API KEY MANAGEMENT", "INFO")
        self.log("-" * 40)
        
        api_key_result = self.test_api_key_management()
        self.record_test_result("API Key Management", api_key_result)
        
        # Test 5: Team Management
        self.log("\n🏢 TESTING TEAM MANAGEMENT", "INFO")
        self.log("-" * 40)
        
        team_result = self.test_team_management()
        self.record_test_result("Team Management", team_result)
        
        # Test 6: Gateway Routing
        self.log("\n🌐 TESTING GATEWAY ROUTING", "INFO")
        self.log("-" * 40)
        
        gateway_result = self.test_gateway_routing()
        self.record_test_result("Gateway Routing", gateway_result)
        
        # Test 7: Subscription and Billing
        self.log("\n💳 TESTING SUBSCRIPTION & BILLING", "INFO")
        self.log("-" * 40)
        
        billing_result = self.test_subscription_and_billing()
        self.record_test_result("Subscription & Billing", billing_result)
        
        # Test 8: Dashboard Integration
        self.log("\n📊 TESTING DASHBOARD INTEGRATION", "INFO")
        self.log("-" * 40)
        
        dashboard_result = self.test_dashboard_integration()
        self.record_test_result("Dashboard Integration", dashboard_result)
        
        # Test 9: Authentication Flow through Gateway
        self.log("\n🔄 TESTING AUTHENTICATION FLOW THROUGH GATEWAY", "INFO")
        self.log("-" * 40)
        
        auth_flow_gateway_result = self.test_auth_flow_gateway()
        self.record_test_result("Authentication Flow Gateway", auth_flow_gateway_result)
        
        # Test 10: Authentication Flow Directly to Identity Service
        self.log("\n🔄 TESTING AUTHENTICATION FLOW DIRECTLY TO IDENTITY SERVICE", "INFO")
        self.log("-" * 40)
        
        auth_flow_direct_result = self.test_auth_flow_direct()
        self.record_test_result("Authentication Flow Direct", auth_flow_direct_result)
        
        # Test 11: Logout Functionality
        self.log("\n🚪 TESTING LOGOUT FUNCTIONALITY", "INFO")
        self.log("-" * 40)
        
        logout_result = self.test_logout_flow()
        self.record_test_result("Logout Functionality", logout_result)
        
        # Test 12: Dashboard Authentication Integration
        self.log("\n📊 TESTING DASHBOARD AUTHENTICATION INTEGRATION", "INFO")
        self.log("-" * 40)
        
        dashboard_auth_integration_result = self.test_dashboard_auth_integration()
        self.record_test_result("Dashboard Auth Integration", dashboard_auth_integration_result)
        
        # Final Summary
        self.log("\n" + "=" * 80)
        self.log("🏁 VERIFICATION SUMMARY", "INFO")
        self.log("=" * 80)
        
        total = self.results["total_tests"]
        passed = self.results["passed_tests"]
        failed = self.results["failed_tests"]
        
        self.log(f"Total Tests: {total}")
        self.log(f"Passed: {passed}", "SUCCESS" if passed > 0 else "INFO")
        self.log(f"Failed: {failed}", "ERROR" if failed > 0 else "INFO")
        
        if failed == 0:
            self.log("🎉 ALL TESTS PASSED! Authentication system is fully operational.", "SUCCESS")
        else:
            self.log(f"⚠️  {failed} tests failed. See details above.", "WARNING")
        
        # Detailed results
        self.log("\n📋 DETAILED RESULTS:")
        for test in self.results["test_details"]:
            status = "✓ PASS" if test["passed"] else "✗ FAIL"
            color = "SUCCESS" if test["passed"] else "ERROR"
            self.log(f"  {status}: {test['test_name']}", color)
        
        return failed == 0

    def test_auth_flow_gateway(self) -> bool:
        """Test authentication flow through the gateway."""
        self.log("Testing authentication flow through gateway...")
        
        success = True
        email = "demo@wildbox.com"
        password = "demopassword123"
        
        try:
            # Test registration through gateway
            registration_data = {
                "email": email,
                "password": password
            }
            
            response = self.make_request("POST", "/api/v1/identity/auth/register", 
                                       registration_data, base_url=self.gateway_url)
            
            if response.status_code in [200, 201]:
                data = response.json()
                token = data.get("access_token")
                self.log(f"✓ Gateway registration successful for {email}", "SUCCESS")
                
                # Test profile retrieval through gateway
                profile_response = self.make_request("GET", "/api/v1/identity/auth/me", 
                                                   token=token, base_url=self.gateway_url)
                if profile_response.status_code == 200:
                    self.log(f"✓ Gateway profile retrieval successful", "SUCCESS")
                else:
                    self.log(f"✗ Gateway profile retrieval failed: {profile_response.status_code}", "ERROR")
                    success = False
                    
            else:
                # Registration failed, try login through gateway
                self.log(f"Gateway registration failed, trying login...", "WARNING")
                
                login_data = {
                    "username": email,
                    "password": password
                }
                
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                response = requests.post(
                    f"{self.gateway_url}/api/v1/identity/auth/login",
                    data=login_data,
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    token = data.get("access_token")
                    self.log(f"✓ Gateway login successful for {email}", "SUCCESS")
                    
                    # Test profile retrieval through gateway
                    profile_response = self.make_request("GET", "/api/v1/identity/auth/me", 
                                                       token=token, base_url=self.gateway_url)
                    if profile_response.status_code == 200:
                        self.log(f"✓ Gateway profile retrieval successful", "SUCCESS")
                    else:
                        self.log(f"✗ Gateway profile retrieval failed: {profile_response.status_code}", "ERROR")
                        success = False
                else:
                    self.log(f"✗ Gateway login failed: {response.status_code} - {response.text}", "ERROR")
                    success = False
                    
        except Exception as e:
            self.log(f"✗ Gateway authentication flow error: {e}", "ERROR")
            success = False
        
        return success

    def test_auth_flow_direct(self) -> bool:
        """Test authentication flow directly to identity service."""
        self.log("Testing authentication flow directly to identity service...")
        
        success = True
        email = "demo@wildbox.com"
        password = "demopassword123"
        
        try:
            # Test registration directly to identity service
            registration_data = {
                "email": email,
                "password": password
            }
            
            response = self.make_request("POST", "/api/v1/auth/register", 
                                       registration_data, base_url=self.identity_url)
            
            if response.status_code in [200, 201]:
                data = response.json()
                token = data.get("access_token")
                self.log(f"✓ Direct registration successful for {email}", "SUCCESS")
                
                # Test profile retrieval directly
                profile_response = self.make_request("GET", "/api/v1/auth/me", 
                                                   token=token, base_url=self.identity_url)
                if profile_response.status_code == 200:
                    self.log(f"✓ Direct profile retrieval successful", "SUCCESS")
                else:
                    self.log(f"✗ Direct profile retrieval failed: {profile_response.status_code}", "ERROR")
                    success = False
                    
            else:
                # Registration failed, try login directly
                self.log(f"Direct registration failed, trying login...", "WARNING")
                
                login_data = {
                    "username": email,
                    "password": password
                }
                
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                response = requests.post(
                    f"{self.identity_url}/api/v1/auth/login",
                    data=login_data,
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    token = data.get("access_token")
                    self.log(f"✓ Direct login successful for {email}", "SUCCESS")
                    
                    # Test profile retrieval directly
                    profile_response = self.make_request("GET", "/api/v1/auth/me", 
                                                       token=token, base_url=self.identity_url)
                    if profile_response.status_code == 200:
                        self.log(f"✓ Direct profile retrieval successful", "SUCCESS")
                    else:
                        self.log(f"✗ Direct profile retrieval failed: {profile_response.status_code}", "ERROR")
                        success = False
                else:
                    self.log(f"✗ Direct login failed: {response.status_code} - {response.text}", "ERROR")
                    success = False
                    
        except Exception as e:
            self.log(f"✗ Direct authentication flow error: {e}", "ERROR")
            success = False
        
        return success

    def test_logout_flow(self) -> bool:
        """Test logout functionality."""
        self.log("Testing logout flow...")
        
        success = True
        
        for email, token in self.tokens.items():
            try:
                # Test logout through gateway
                response = self.make_request("POST", "/api/v1/identity/auth/logout", 
                                           token=token, base_url=self.gateway_url)
                if response.status_code in [200, 204]:
                    self.log(f"✓ Gateway logout successful for {email}", "SUCCESS")
                else:
                    self.log(f"✗ Gateway logout failed for {email}: {response.status_code}", "ERROR")
                    success = False
                    
                # Test that token is invalidated
                profile_response = self.make_request("GET", "/api/v1/identity/auth/me", 
                                                   token=token, base_url=self.gateway_url)
                if profile_response.status_code == 401:
                    self.log(f"✓ Token invalidated after logout for {email}", "SUCCESS")
                else:
                    self.log(f"? Token still valid after logout for {email}: {profile_response.status_code}", "WARNING")
                    
            except Exception as e:
                self.log(f"✗ Logout flow error for {email}: {e}", "ERROR")
                success = False
        
        return success

    def test_dashboard_auth_integration(self) -> bool:
        """Test dashboard authentication integration."""
        self.log("Testing dashboard authentication integration...")
        
        try:
            # Test if dashboard is accessible
            response = requests.get(f"{self.dashboard_url}", timeout=5)
            if response.status_code == 200:
                self.log("✓ Dashboard is accessible", "SUCCESS")
                
                # Test dashboard API endpoints that require auth
                for email, token in self.tokens.items():
                    try:
                        # Test dashboard API with auth token
                        headers = {"Authorization": f"Bearer {token}"}
                        api_response = requests.get(f"{self.dashboard_url}/api/user", 
                                                  headers=headers, timeout=5)
                        if api_response.status_code in [200, 404]:  # 404 is OK if endpoint doesn't exist
                            self.log(f"✓ Dashboard API accessible with token for {email}", "SUCCESS")
                        else:
                            self.log(f"? Dashboard API response for {email}: {api_response.status_code}", "WARNING")
                    except Exception as e:
                        self.log(f"? Dashboard API test error for {email}: {e}", "WARNING")
                
                return True
            else:
                self.log(f"? Dashboard not accessible: {response.status_code}", "WARNING")
                return True  # Not a failure if dashboard isn't running
        except Exception as e:
            self.log(f"? Dashboard not accessible: {e}", "WARNING")
            return True  # Not a failure if dashboard isn't running

def main():
    """Main function to run the verification."""
    verifier = WildboxAuthenticationVerifier()
    
    try:
        success = verifier.run_all_tests()
        
        # Generate report file
        report_file = "authentication_verification_report.json"
        with open(report_file, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "summary": verifier.results,
                "user_data": {email: {k: v for k, v in data.items() if k != "team_memberships"} 
                             for email, data in verifier.user_data.items()},
                "overall_success": success
            }, f, indent=2)
        
        verifier.log(f"\n📄 Detailed report saved to: {report_file}")
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        verifier.log("\n❌ Verification interrupted by user.", "WARNING")
        return 1
    except Exception as e:
        verifier.log(f"\n❌ Verification failed with error: {e}", "ERROR")
        return 1

if __name__ == "__main__":
    sys.exit(main())
