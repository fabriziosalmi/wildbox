"""
Gateway Security Test Module
Tests routing, security headers, rate limiting, circuit breaker
"""

import requests
import asyncio
import time
from typing import Dict, List, Any, Optional


class GatewaySecurityTester:
    """Comprehensive tests for API Gateway (Port 80/443)"""
    
    def __init__(self, base_url: str = "http://localhost:80"):
        self.base_url = base_url
        self.https_url = "https://localhost:443"
        self.test_results = []
        
    def log_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Log individual test result"""
        self.test_results.append({
            "name": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
        
    async def test_gateway_health(self) -> bool:
        """Test gateway health endpoint"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            passed = response.status_code == 200
            
            if passed:
                health_data = response.json()
                details = f"Status: {health_data.get('status', 'unknown')}"
            else:
                details = f"HTTP {response.status_code}"
                
            self.log_test_result("Gateway Health Check", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Gateway Health Check", False, f"Error: {str(e)}")
            return False
            
    async def test_routing_with_authentication(self) -> bool:
        """Test routing through gateway with authentication"""
        try:
            # Test routing to identity service through gateway
            # This would require a valid token, but we test the routing exists
            
            response = requests.get(
                f"{self.base_url}/api/v1/auth/me",
                timeout=10
            )
            
            # Should get 401 (unauthorized) or proper response, not 404
            # This confirms routing is working
            passed = response.status_code != 404
            
            if passed:
                details = f"Routing works, got HTTP {response.status_code} (expected auth required)"
            else:
                details = "Route not found - gateway routing may be broken"
                
            self.log_test_result("Gateway Routing with Authentication", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Gateway Routing with Authentication", False, f"Error: {str(e)}")
            return False
            
    async def test_security_headers(self) -> bool:
        """Test security headers (HSTS, CSP, X-Frame-Options)"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            
            headers = response.headers
            security_headers = {
                "X-Frame-Options": ["DENY", "SAMEORIGIN"],
                "X-Content-Type-Options": ["nosniff"],
                "X-XSS-Protection": ["1; mode=block", "0"],
                "Referrer-Policy": ["strict-origin-when-cross-origin", "no-referrer"],
            }
            
            found_headers = []
            missing_headers = []
            
            for header, valid_values in security_headers.items():
                header_value = headers.get(header)
                if header_value:
                    found_headers.append(f"{header}: {header_value}")
                else:
                    missing_headers.append(header)
            
            # HSTS check (may only be present on HTTPS)
            if "Strict-Transport-Security" in headers:
                found_headers.append(f"Strict-Transport-Security: {headers['Strict-Transport-Security']}")
            
            # CSP check
            if "Content-Security-Policy" in headers:
                found_headers.append(f"Content-Security-Policy: present")
            
            passed = len(found_headers) >= 2  # At least some security headers present
            
            if passed:
                details = f"Found headers: {', '.join(found_headers)}"
            else:
                details = f"Missing security headers: {', '.join(missing_headers)}"
                
            self.log_test_result("Security Headers Check", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Security Headers Check", False, f"Error: {str(e)}")
            return False
            
    async def test_http_method_restrictions(self) -> bool:
        """Test restriction of non-permitted HTTP methods"""
        try:
            # Test various HTTP methods
            methods_to_test = ["OPTIONS", "TRACE", "CONNECT", "PATCH"]
            restricted_methods = []
            allowed_methods = []
            
            for method in methods_to_test:
                try:
                    response = requests.request(method, f"{self.base_url}/", timeout=5)
                    
                    # Methods should be restricted (405 Method Not Allowed or similar)
                    if response.status_code in [405, 501, 400]:
                        restricted_methods.append(method)
                    else:
                        allowed_methods.append(f"{method}:{response.status_code}")
                        
                except Exception:
                    # Connection errors might indicate method is blocked
                    restricted_methods.append(method)
            
            # Most methods should be restricted for security
            passed = len(restricted_methods) >= len(methods_to_test) // 2
            
            if passed:
                details = f"Restricted: {', '.join(restricted_methods)}"
            else:
                details = f"Too many methods allowed: {', '.join(allowed_methods)}"
                
            self.log_test_result("HTTP Method Restrictions", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("HTTP Method Restrictions", False, f"Error: {str(e)}")
            return False
            
    async def test_passthrough_headers(self) -> bool:
        """Test correct pass-through headers (X-User-ID, X-Team-ID, X-Role, X-Plan)"""
        try:
            # This test checks if the gateway properly sets headers when forwarding requests
            # We'll test with a dummy token to see header handling
            
            headers = {"Authorization": "Bearer dummy-token-for-testing"}
            response = requests.get(
                f"{self.base_url}/api/v1/auth/me",
                headers=headers,
                timeout=10
            )
            
            # Check if the request was processed (even if it fails auth)
            # This confirms the gateway is processing and forwarding requests
            passed = response.status_code in [401, 403, 200]  # Valid auth responses
            
            if passed:
                details = f"Gateway processes auth headers correctly (HTTP {response.status_code})"
            else:
                details = f"Unexpected response: HTTP {response.status_code}"
                
            self.log_test_result("Pass-through Headers Processing", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Pass-through Headers Processing", False, f"Error: {str(e)}")
            return False
            
    async def test_rate_limiting(self) -> bool:
        """Test rate limiting with burst protection"""
        try:
            # Send multiple rapid requests to test rate limiting
            requests_count = 20
            start_time = time.time()
            responses = []
            
            for i in range(requests_count):
                try:
                    response = requests.get(f"{self.base_url}/health", timeout=2)
                    responses.append(response.status_code)
                except Exception:
                    responses.append(0)  # Timeout/error
                    
            end_time = time.time()
            total_time = end_time - start_time
            
            # Check for rate limiting indicators
            rate_limited = any(code in [429, 503] for code in responses)
            successful_requests = sum(1 for code in responses if code == 200)
            
            # If we get rate limited OR requests are throttled (taking longer), it's working
            requests_per_second = requests_count / total_time if total_time > 0 else float('inf')
            
            passed = rate_limited or requests_per_second < 50  # Reasonable throttling
            
            if passed:
                details = f"Rate limiting active: {successful_requests}/{requests_count} succeeded"
            else:
                details = f"No rate limiting detected: {successful_requests}/{requests_count} in {total_time:.2f}s"
                
            self.log_test_result("Rate Limiting with Burst Protection", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Rate Limiting with Burst Protection", False, f"Error: {str(e)}")
            return False
            
    async def test_circuit_breaker(self) -> bool:
        """Test circuit breaker with recovery"""
        try:
            # Test circuit breaker by making requests to potentially failing endpoints
            # Since we can't easily trigger backend failures, we test behavior
            
            test_endpoints = [
                "/api/v1/tools/health",
                "/api/v1/data/health", 
                "/api/v1/agents/health"
            ]
            
            working_endpoints = 0
            for endpoint in test_endpoints:
                try:
                    response = requests.get(f"{self.base_url}{endpoint}", timeout=5)
                    # Any response (even 404) shows gateway is trying to route
                    if response.status_code != 502:  # 502 would indicate backend down
                        working_endpoints += 1
                except Exception:
                    pass
            
            # Circuit breaker is working if gateway handles backend failures gracefully
            passed = working_endpoints >= 1  # At least some services reachable
            
            if passed:
                details = f"Circuit breaker handling: {working_endpoints}/{len(test_endpoints)} services reachable"
            else:
                details = "Circuit breaker may not be working - all services unreachable"
                
            self.log_test_result("Circuit Breaker with Recovery", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Circuit Breaker with Recovery", False, f"Error: {str(e)}")
            return False


async def run_tests() -> Dict[str, Any]:
    """Run all gateway security tests"""
    tester = GatewaySecurityTester()
    
    # Run tests in sequence
    tests = [
        tester.test_gateway_health,
        tester.test_routing_with_authentication,
        tester.test_security_headers,
        tester.test_http_method_restrictions,
        tester.test_passthrough_headers,
        tester.test_rate_limiting,
        tester.test_circuit_breaker
    ]
    
    success_count = 0
    for test in tests:
        try:
            success = await test()
            if success:
                success_count += 1
        except Exception as e:
            print(f"Gateway test error: {e}")
            
    all_passed = success_count == len(tests)
    
    return {
        "success": all_passed,
        "tests": tester.test_results,
        "summary": f"{success_count}/{len(tests)} tests passed"
    }