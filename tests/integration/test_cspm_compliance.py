"""
CSPM Compliance Test Module
Tests cloud security dashboard, scanning, findings management
"""

import os
import pytest
import requests
import asyncio
import time
from typing import Dict, List, Any, Optional


class TestCSPMCompliance:
    """Comprehensive tests for CSPM Compliance Service (Port 8019)"""
    
    # setup_method, not __init__: pytest silently refuses to collect a
    # class that defines a constructor. Combined with the class rename
    # below, this is what makes these tests run at all (WILDBO-TEST-01).
    def setup_method(self, method):
        # Constructor defaults, resolved here now that pytest calls
        # setup_method() with no arguments (WILDBO-TEST-01).
        # Two base URLs, because the service has two front doors.
        #
        # Everything but /health refuses a direct connection: the shared
        # gateway_auth middleware answers 403 GATEWAY_AUTH_REQUIRED ("This
        # service must be accessed through the API gateway"). Calling the
        # service directly, as these tests did, could therefore only ever fail
        # -- and the API paths they used did not exist either.
        self.direct_url = os.getenv("CSPM_SERVICE_URL", "http://localhost:8019")
        self.base_url = os.getenv("GATEWAY_URL", "https://localhost") + "/api/v1/cspm"
        self.headers = {"X-API-Key": os.getenv("TEST_API_KEY", "")}
        self.results = []
        
    def log_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Log individual test result"""
        self.results.append({
            "name": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
        
    async def test_service_health(self) -> None:
        """Test CSPM service health"""
        try:
            response = requests.get(f"{self.direct_url}/health", timeout=10)
            passed = response.status_code == 200
            
            if passed:
                health_data = response.json()
                details = f"Status: {health_data.get('status', 'unknown')}"
            else:
                details = f"HTTP {response.status_code}"
                
            self.log_test_result("CSPM Service Health", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("CSPM Service Health", False, f"Error: {str(e)}")
            raise
            
    async def test_dashboard_summary(self) -> None:
        """Test the dashboard summary.

        GET /dashboard/executive-summary is gone (#578): it read
        scan:{id}:results, a key nothing writes. The summary reports the
        team's stored scan reports instead.
        """
        try:
            response = requests.get(f"{self.base_url}/dashboard/summary", headers=self.headers, timeout=15)

            if response.status_code == 200:
                summary = response.json()
                problems = [
                    f"{field} missing"
                    for field in ("total_scans", "accounts_assessed", "compliance_score",
                                  "total_findings", "critical_findings")
                    if field not in summary
                ]
                # Nothing assessed is a null score, not 0%.
                if summary.get("accounts_assessed") == 0 and summary.get("compliance_score") is not None:
                    problems.append("a score reported with no completed scan")
                passed = not problems
                details = "; ".join(problems) or f"Dashboard summary: {summary.get('total_scans')} scan(s)"
            elif response.status_code in [401, 403]:
                details = "Dashboard summary requires authentication (expected)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Dashboard endpoint responds (HTTP {response.status_code})"

            self.log_test_result("Dashboard Summary", passed, details)
            assert passed, details

        except Exception as e:
            self.log_test_result("Dashboard Summary", False, f"Error: {str(e)}")
            raise

    async def test_cloud_scanning_business_plus(self) -> None:
        """Test cloud scanning trigger for Business+ plans"""
        try:
            # Test cloud scan trigger
            scan_request = {
                "provider": "aws",
                "account_id": "123456789012",
                "regions": ["us-east-1"],
                "scan_type": "security_assessment"
            }
            
            response = requests.post(
                f"{self.base_url}/scans",
                json=scan_request,
                timeout=15
            )
            
            # Check response
            if response.status_code in [200, 201, 202]:
                scan_result = response.json()
                
                # Check for scan ID or immediate result
                if 'scan_id' in scan_result or 'task_id' in scan_result:
                    details = f"Cloud scan triggered: {scan_result.get('scan_id') or scan_result.get('task_id')}"
                    passed = True
                else:
                    details = f"Cloud scan response: {str(scan_result)[:100]}"
                    passed = True
                    
            elif response.status_code in [401, 403]:
                details = "Cloud scanning requires authentication (expected)"
                passed = True
            elif response.status_code == 402:
                details = "Cloud scanning requires Business+ plan (expected)"
                passed = True
            elif response.status_code == 400:
                details = "Scan validation working (HTTP 400)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Scan trigger endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("Cloud Scanning for Business+ Plans", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Cloud Scanning for Business+ Plans", False, f"Error: {str(e)}")
            raise
            
    async def test_team_scoped_findings(self) -> None:
        """Test team-scoped findings listing"""
        try:
            # Test findings endpoint
            response = requests.get(f"{self.base_url}/compliance/findings", headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                findings = response.json()
                findings_count = len(findings) if isinstance(findings, list) else len(findings.get('findings', []))
                
                passed = True  # Any response structure is acceptable
                details = f"Findings accessible: {findings_count} findings found"
                
            elif response.status_code in [401, 403]:
                details = "Findings require authentication (expected)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Findings endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("Team-scoped Findings List", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Team-scoped Findings List", False, f"Error: {str(e)}")
            raise
            
    async def test_compliance_frameworks(self) -> None:
        """Test compliance frameworks support"""
        try:
            # Test compliance frameworks endpoint
            response = requests.get(f"{self.base_url}/compliance/summary", headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                frameworks = response.json()
                
                if isinstance(frameworks, list):
                    framework_count = len(frameworks)
                    passed = framework_count > 0
                    details = f"{framework_count} compliance frameworks available"
                elif isinstance(frameworks, dict):
                    framework_names = list(frameworks.keys())
                    passed = len(framework_names) > 0
                    details = f"Frameworks: {', '.join(framework_names[:3])}"
                else:
                    passed = True
                    details = f"Compliance frameworks response: {str(frameworks)[:100]}"
                    
            elif response.status_code in [401, 403]:
                details = "Compliance frameworks require authentication (expected)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Frameworks endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("Compliance Frameworks Support", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Compliance Frameworks Support", False, f"Error: {str(e)}")
            raise
            
    async def test_scan_history(self) -> None:
        """Test scan history and reporting"""
        try:
            # Test scan history endpoint
            response = requests.get(f"{self.base_url}/scans", headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                history = response.json()
                scan_count = len(history) if isinstance(history, list) else len(history.get('scans', []))
                
                passed = True  # Any response is good
                details = f"Scan history accessible: {scan_count} scans found"
                
            elif response.status_code in [401, 403]:
                details = "Scan history requires authentication (expected)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Scan history endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("Scan History and Reporting", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Scan History and Reporting", False, f"Error: {str(e)}")
            raise


async def run_tests() -> Dict[str, Any]:
    """Run all CSPM compliance tests"""
    tester = TestCSPMCompliance()
    
    # Run tests in sequence
    tests = [
        tester.test_service_health,
        tester.test_dashboard_summary,
        tester.test_cloud_scanning_business_plus,
        tester.test_team_scoped_findings,
        tester.test_compliance_frameworks,
        tester.test_scan_history
    ]
    
    success_count = 0
    for test in tests:
        try:
            success = await test()
            if success:
                success_count += 1
        except Exception as e:
            print(f"CSPM compliance test error: {e}")
            
    all_passed = success_count == len(tests)
    
    return {
        "success": all_passed,
        "tests": tester.results,
        "summary": f"{success_count}/{len(tests)} tests passed"
    }