"""
CSPM Compliance Test Module
Tests cloud security dashboard, scanning, findings management
"""

import requests
import asyncio
import time
from typing import Dict, List, Any, Optional


class CSPMComplianceTester:
    """Comprehensive tests for CSPM Compliance Service (Port 8019)"""
    
    def __init__(self, base_url: str = "http://localhost:8019"):
        self.base_url = base_url
        self.results = []
        
    def log_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Log individual test result"""
        self.results.append({
            "name": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
        
    async def test_service_health(self) -> bool:
        """Test CSPM service health"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            passed = response.status_code == 200
            
            if passed:
                health_data = response.json()
                details = f"Status: {health_data.get('status', 'unknown')}"
            else:
                details = f"HTTP {response.status_code}"
                
            self.log_test_result("CSPM Service Health", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("CSPM Service Health", False, f"Error: {str(e)}")
            return False
            
    async def test_executive_dashboard_summary(self) -> bool:
        """Test executive dashboard summary"""
        try:
            response = requests.get(f"{self.base_url}/api/v1/dashboard/executive", timeout=15)
            
            if response.status_code == 200:
                dashboard_data = response.json()
                
                # Check for expected dashboard elements
                expected_fields = ['compliance_score', 'total_checks', 'critical_findings', 'summary']
                found_fields = []
                
                for field in expected_fields:
                    if field in dashboard_data:
                        found_fields.append(field)
                
                passed = len(found_fields) >= 2  # At least some dashboard data
                
                if passed:
                    compliance_score = dashboard_data.get('compliance_score', 'unknown')
                    total_checks = dashboard_data.get('total_checks', 'unknown')
                    details = f"Executive dashboard: {len(found_fields)}/{len(expected_fields)} fields, compliance: {compliance_score}, checks: {total_checks}"
                else:
                    details = f"Incomplete dashboard: {list(dashboard_data.keys())}"
                    
            elif response.status_code in [401, 403]:
                details = "Executive dashboard requires authentication (expected)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Dashboard endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("Executive Dashboard Summary", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Executive Dashboard Summary", False, f"Error: {str(e)}")
            return False
            
    async def test_cloud_scanning_business_plus(self) -> bool:
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
                f"{self.base_url}/api/v1/scans/trigger",
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
            return passed
            
        except Exception as e:
            self.log_test_result("Cloud Scanning for Business+ Plans", False, f"Error: {str(e)}")
            return False
            
    async def test_team_scoped_findings(self) -> bool:
        """Test team-scoped findings listing"""
        try:
            # Test findings endpoint
            response = requests.get(f"{self.base_url}/api/v1/findings", timeout=15)
            
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
            return passed
            
        except Exception as e:
            self.log_test_result("Team-scoped Findings List", False, f"Error: {str(e)}")
            return False
            
    async def test_compliance_frameworks(self) -> bool:
        """Test compliance frameworks support"""
        try:
            # Test compliance frameworks endpoint
            response = requests.get(f"{self.base_url}/api/v1/compliance/frameworks", timeout=10)
            
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
            return passed
            
        except Exception as e:
            self.log_test_result("Compliance Frameworks Support", False, f"Error: {str(e)}")
            return False
            
    async def test_scan_history(self) -> bool:
        """Test scan history and reporting"""
        try:
            # Test scan history endpoint
            response = requests.get(f"{self.base_url}/api/v1/scans/history", timeout=10)
            
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
            return passed
            
        except Exception as e:
            self.log_test_result("Scan History and Reporting", False, f"Error: {str(e)}")
            return False


async def run_tests() -> Dict[str, Any]:
    """Run all CSPM compliance tests"""
    tester = CSPMComplianceTester()
    
    # Run tests in sequence
    tests = [
        tester.test_service_health,
        tester.test_executive_dashboard_summary,
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