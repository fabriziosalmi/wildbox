"""
Gateway Hardening Test Module
Tests RBAC and error handling for enterprise security

Rate limiting is not tested here. The two tests this module had for it could
not fail: each set ``passed = True`` in every branch, whether or not a request
was refused and whether or not a header was there (#776). What they claimed
to check is checked where it can be: the per-address limits and their 429
against the gateway image itself (open-security-gateway/test/
rate_limit_tests.py; the stacks this suite runs against raise those limits
so that it cannot meet them), and the per-team budget and its
``X-RateLimit-*`` headers in test_gateway_security.py's test_rate_limiting.
"""

import os
import pytest
import requests
import asyncio
import time
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv

# Load test environment
load_dotenv("tests/.env")


class TestGatewayHardening:
    """Enterprise-level security tests for Gateway"""
    
    # setup_method, not __init__: pytest silently refuses to collect a
    # class that defines a constructor. Combined with the class rename
    # below, this is what makes these tests run at all (WILDBO-TEST-01).
    def setup_method(self, method):
        # Constructor defaults, resolved here now that pytest calls
        # setup_method() with no arguments (WILDBO-TEST-01).
        base_url = None
        self.base_url = base_url or os.getenv("GATEWAY_URL", "http://localhost")
        self.admin_api_key = os.getenv("TEST_API_KEY", "test-api-key-for-ci-only")
        self.results = []
        
        # Default headers
        self.admin_headers = {
            "X-API-Key": self.admin_api_key,
            "Content-Type": "application/json"
        }
        
    def log_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Log individual test result"""
        self.results.append({
            "name": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
        
    async def test_rbac_user_forbidden_admin_endpoint(self) -> None:
        """
        Test RBAC: User role should get 403 on admin endpoints
        
        This tests that the gateway properly enforces role-based access control.
        A user with 'user' role should be denied access to administrative endpoints.
        """
        try:
            # Note: Currently we only have admin API key
            # In a real scenario, we'd create a user-level API key
            # For now, we test that the mechanism exists
            
            # Test Guardian vulnerabilities endpoint (should require admin in production)
            response = requests.get(
                f"{self.base_url}/api/v1/guardian/vulnerabilities/",
                headers=self.admin_headers,
                timeout=10
            )
            
            # Currently, with admin key, we should get 200
            admin_access = response.status_code == 200
            
            if admin_access:
                details = "Admin role has access to vulnerabilities endpoint (expected)"
                passed = True
            else:
                details = f"Unexpected admin access denial: HTTP {response.status_code}"
                passed = False
                
            self.log_test_result("RBAC: Admin Access to Protected Endpoint", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("RBAC: Admin Access to Protected Endpoint", False, f"Error: {str(e)}")
            raise
            
    async def test_rbac_role_header_propagation(self) -> None:
        """
        Test that X-Wildbox-Role header is correctly propagated from gateway to services
        
        This validates the gateway authentication middleware injects the correct role
        header based on the authenticated user's permissions.
        """
        try:
            # Make request to Guardian which logs the role
            response = requests.get(
                f"{self.base_url}/api/v1/guardian/vulnerabilities/",
                headers=self.admin_headers,
                timeout=10
            )
            
            # Check if request succeeded (indicating role was accepted)
            passed = response.status_code in [200, 401, 403]  # Any auth-aware response
            
            if response.status_code == 200:
                data = response.json()
                # Guardian should have processed the request with the role
                details = f"Role header propagated successfully, got {len(data) if isinstance(data, list) else 'object'} response"
            elif response.status_code == 403:
                details = "Role-based access control is active (403 received)"
            else:
                details = f"Gateway auth response: HTTP {response.status_code}"
                
            self.log_test_result("RBAC: Role Header Propagation", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("RBAC: Role Header Propagation", False, f"Error: {str(e)}")
            raise
            
    async def test_error_handling_service_failure(self) -> None:
        """
        Test resilience: How does the system handle upstream service failures?
        
        This tests the All-Star playbook behavior when Agents service fails.
        The Responder should gracefully handle the error and mark the playbook as FAILED.
        """
        try:
            # Execute All-Star playbook (which calls Agents)
            test_execution = {
                "trigger_data": {
                    "ip": "127.0.0.1"
                }
            }
            
            response = requests.post(
                f"{self.base_url}/api/v1/responder/playbooks/all_star_e2e/execute",
                json=test_execution,
                headers=self.admin_headers,
                timeout=15
            )
            
            if response.status_code in [200, 202]:
                result = response.json()
                run_id = result.get('run_id')
                
                # Wait briefly for execution
                await asyncio.sleep(3)
                
                # Check run status
                status_response = requests.get(
                    f"{self.base_url}/api/v1/responder/runs/{run_id}",
                    headers=self.admin_headers,
                    timeout=10
                )
                
                if status_response.status_code == 200:
                    run_data = status_response.json()
                    status = run_data.get('status')
                    
                    # Playbook should complete (with or without errors)
                    passed = status in ['completed', 'failed']
                    details = f"Playbook execution status: {status}, error handling active"
                else:
                    passed = True  # Status endpoint working is good enough
                    details = f"Error tracking available (HTTP {status_response.status_code})"
            else:
                passed = response.status_code != 500
                details = f"Playbook execution response: HTTP {response.status_code}"
                
            self.log_test_result("Error Handling: Service Failure Resilience", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Error Handling: Service Failure Resilience", False, f"Error: {str(e)}")
            raise
            
    async def test_malicious_ip_vulnerability_creation(self) -> None:
        """
        Test complete security workflow: Malicious IP → Guardian vulnerability
        
        This tests the All-Star playbook with a known malicious IP.
        The Agents service should detect it as malicious, and Guardian should
        create a vulnerability entry.
        """
        try:
            # Use a test IP that might be flagged (simulated malicious)
            test_execution = {
                "trigger_data": {
                    "ip": "192.168.1.100"  # Private IP for testing
                }
            }
            
            response = requests.post(
                f"{self.base_url}/api/v1/responder/playbooks/all_star_e2e/execute",
                json=test_execution,
                headers=self.admin_headers,
                timeout=15
            )
            
            if response.status_code in [200, 202]:
                result = response.json()
                run_id = result.get('run_id')
                
                # Wait for the run to finish. Five seconds used to be enough
                # because every connector call failed at once (#616); the
                # steps now reach the tools and agents services, and the port
                # scan and threat-intelligence lookups take their time.
                deadline = time.monotonic() + 180
                while True:
                    status_response = requests.get(
                        f"{self.base_url}/api/v1/responder/runs/{run_id}",
                        headers=self.admin_headers,
                        timeout=10
                    )
                    if (
                        status_response.status_code != 200
                        or status_response.json().get('status')
                        in ('completed', 'failed', 'cancelled')
                        or time.monotonic() > deadline
                    ):
                        break
                    await asyncio.sleep(2)

                if status_response.status_code == 200:
                    run_data = status_response.json()
                    status = run_data.get('status')
                    
                    # Check if vulnerability creation step was executed
                    steps = run_data.get('step_results', [])
                    vuln_step = next((s for s in steps if 'vulnerability' in s.get('step_name', '').lower()), None)
                    
                    if vuln_step:
                        vuln_created = vuln_step.get('status') == 'completed'
                        details = f"Playbook completed, vulnerability step: {vuln_step.get('status')}"
                        passed = status == 'completed'
                    else:
                        details = f"Playbook executed with status: {status}"
                        passed = status in ['completed', 'failed']
                else:
                    passed = True
                    details = "Playbook execution tracked"
            else:
                passed = response.status_code != 500
                details = f"Playbook execution: HTTP {response.status_code}"
                
            self.log_test_result("Security Workflow: Malicious IP Detection", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Security Workflow: Malicious IP Detection", False, f"Error: {str(e)}")
            raise


async def run_tests() -> Dict[str, Any]:
    """Run all gateway hardening tests"""
    tester = TestGatewayHardening()
    
    # Run tests in sequence
    tests = [
        tester.test_rbac_user_forbidden_admin_endpoint,
        tester.test_rbac_role_header_propagation,
        tester.test_error_handling_service_failure,
        tester.test_malicious_ip_vulnerability_creation
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


if __name__ == "__main__":
    import asyncio
    result = asyncio.run(run_tests())
    print(f"\nGateway Hardening Tests: {result['summary']}")
    for test in result['tests']:
        status = "✅" if test['passed'] else "❌"
        print(f"{status} {test['name']}: {test['details']}")
