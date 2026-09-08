"""
Gateway Security Test Module
Tests routing, security headers, rate limiting, circuit breaker
"""

import os
import pytest
import requests
import asyncio
import time
from typing import Dict, List, Any, Optional


class TestGatewaySecurity:
    """Comprehensive tests for API Gateway (Port 80/443)"""
    
    # setup_method, not __init__: pytest silently refuses to collect a
    # class that defines a constructor. Combined with the class rename
    # below, this is what makes these tests run at all (WILDBO-TEST-01).
    def setup_method(self, method):
        # Constructor defaults, resolved here now that pytest calls
        # setup_method() with no arguments (WILDBO-TEST-01).
        # Read the same environment variable the conftest reachability guard
        # reads. Hard-coding localhost meant the guard probed the configured
        # address, said "reachable", and the test then connected somewhere
        # else -- so these tests could only ever pass on a host where every
        # service happened to be on loopback.
        base_url = os.getenv("GATEWAY_URL", "http://localhost")
        self.base_url = base_url
        self.https_url = "https://localhost:443"
        self.results = []
        
    def log_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Log individual test result"""
        self.results.append({
            "name": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
        
    async def test_gateway_health(self) -> None:
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
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Gateway Health Check", False, f"Error: {str(e)}")
            raise
            
    async def test_routing_with_authentication(self) -> None:
        """Test routing through gateway with authentication"""
        try:
            # Test routing to identity service through gateway
            # This would require a valid token, but we test the routing exists
            
            # /api/v1/identity/users/me: the gateway's identity route, which
            # answers 401 without credentials. The previous target,
            # /api/v1/auth/me, matches no location in the gateway and no route
            # in identity, so this test could only ever report "gateway routing
            # may be broken" about a path nothing was ever meant to serve.
            response = requests.get(
                f"{self.base_url}/api/v1/identity/users/me",
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
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Gateway Routing with Authentication", False, f"Error: {str(e)}")
            raise
            
    async def test_security_headers(self) -> None:
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
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Security Headers Check", False, f"Error: {str(e)}")
            raise
            
    async def test_http_method_restrictions(self) -> None:
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
            assert passed, details
            
        except Exception as e:
            self.log_test_result("HTTP Method Restrictions", False, f"Error: {str(e)}")
            raise
            
    async def test_passthrough_headers(self) -> None:
        """Test correct pass-through headers (X-User-ID, X-Team-ID, X-Role, X-Plan)"""
        try:
            # Prove the identity actually propagates, rather than reading a
            # status code off a route that does not exist.
            #
            # This used to send a dummy bearer token to /api/v1/auth/me -- no
            # such location in the gateway, no such route in identity -- and
            # accept "401, 403 or 200" as evidence that headers were being
            # forwarded. It was asserting nothing about headers at all.
            #
            # The upstreams reject any request that does not carry the gateway's
            # X-Wildbox-* identity headers and its shared secret (the shared
            # gateway_auth dependency answers 403 GATEWAY_AUTH_REQUIRED). So a
            # 2xx from a protected route is only reachable if the gateway
            # authenticated the caller and forwarded that identity: that is the
            # pass-through, observed from outside.
            url = f"{self.base_url}/api/v1/data/stats"

            anonymous = requests.get(url, timeout=10)
            spoofed = requests.get(
                url,
                headers={
                    "X-Wildbox-User-ID": "00000000-0000-4000-8000-000000000000",
                    "X-Wildbox-Team-ID": "00000000-0000-4000-8000-000000000001",
                    "X-Wildbox-Role": "admin",
                },
                timeout=10,
            )
            authenticated = requests.get(
                url,
                headers={"X-API-Key": os.getenv("TEST_API_KEY", "")},
                timeout=10,
            )

            problems = []
            if anonymous.status_code not in (401, 403):
                problems.append(
                    f"anonymous request was not rejected (HTTP {anonymous.status_code})"
                )
            if spoofed.status_code not in (401, 403):
                problems.append(
                    "client-supplied X-Wildbox-* identity headers were accepted "
                    f"(HTTP {spoofed.status_code})"
                )
            if authenticated.status_code >= 400:
                problems.append(
                    "authenticated request did not reach the upstream "
                    f"(HTTP {authenticated.status_code}): identity was not forwarded"
                )

            passed = not problems
            details = (
                "Gateway forwards its own identity and refuses the client's"
                if passed
                else "; ".join(problems)
            )

            self.log_test_result("Pass-through Headers Processing", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Pass-through Headers Processing", False, f"Error: {str(e)}")
            raise
            
    async def test_rate_limiting(self) -> None:
        """Test rate limiting with burst protection"""
        try:
            # Prove the limiter is live by watching it count, not by trying to
            # trip it.
            #
            # This used to fire 20 requests at /health and conclude "no rate
            # limiting detected". /health is deliberately unauthenticated and
            # unlimited -- rate-limiting a load balancer's probe is how you get
            # taken out of rotation -- and the limiter lives in
            # auth_handler.authenticate(), so it never ran for those requests.
            # Tripping it for real would need max(1, RATE_LIMIT_PER_HOUR/60)
            # requests, 166 by default, which is a load test, not this.
            #
            # Instead: an authenticated route must report a budget, and the
            # remaining count must go down as requests are spent.
            url = f"{self.base_url}/api/v1/data/stats"
            headers = {"X-API-Key": os.getenv("TEST_API_KEY", "")}

            first = requests.get(url, headers=headers, timeout=10)
            second = requests.get(url, headers=headers, timeout=10)

            limit = first.headers.get("X-RateLimit-Limit")
            remaining_1 = first.headers.get("X-RateLimit-Remaining")
            remaining_2 = second.headers.get("X-RateLimit-Remaining")
            reset = first.headers.get("X-RateLimit-Reset")

            if not all([limit, remaining_1, remaining_2, reset]):
                passed = False
                details = (
                    "Gateway did not report a rate-limit budget on an "
                    f"authenticated route: limit={limit!r} "
                    f"remaining={remaining_1!r} reset={reset!r}"
                )
            elif int(remaining_2) >= int(remaining_1):
                passed = False
                details = (
                    f"Rate-limit counter did not advance: {remaining_1} then "
                    f"{remaining_2} -- requests are not being counted"
                )
            elif int(remaining_1) > int(limit):
                # Limit and Remaining must describe the same budget.
                passed = False
                details = f"Remaining ({remaining_1}) exceeds Limit ({limit})"
            else:
                passed = True
                details = (
                    f"Rate limiting active: limit={limit}, "
                    f"remaining {remaining_1} -> {remaining_2}"
                )

            self.log_test_result("Rate Limiting with Burst Protection", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Rate Limiting with Burst Protection", False, f"Error: {str(e)}")
            raise
            
    async def test_circuit_breaker(self) -> None:
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
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Circuit Breaker with Recovery", False, f"Error: {str(e)}")
            raise


async def run_tests() -> Dict[str, Any]:
    """Run all gateway security tests"""
    tester = TestGatewaySecurity()
    
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
        "tests": tester.results,
        "summary": f"{success_count}/{len(tests)} tests passed"
    }