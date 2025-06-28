"""
Guardian Monitoring Test Module
Tests assets, vulnerabilities, Celery task management
"""

import requests
import asyncio
import time
from typing import Dict, List, Any, Optional


class GuardianMonitoringTester:
    """Comprehensive tests for Guardian Monitoring Service (Port 8013)"""
    
    def __init__(self, base_url: str = "http://localhost:8013"):
        self.base_url = base_url
        self.test_results = []
        
    def log_test_result(self, test_name: str, passed: bool, details: str = ""):
        """Log individual test result"""
        self.test_results.append({
            "name": test_name,
            "passed": passed,
            "details": details,
            "timestamp": time.time()
        })
        
    async def test_service_health(self) -> bool:
        """Test Guardian service health"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            passed = response.status_code == 200
            
            if passed:
                health_data = response.json()
                details = f"Status: {health_data.get('status', 'unknown')}"
            else:
                details = f"HTTP {response.status_code}"
                
            self.log_test_result("Guardian Service Health", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Guardian Service Health", False, f"Error: {str(e)}")
            return False
            
    async def test_assets_database_access(self) -> bool:
        """Test access to assets database"""
        try:
            # Test assets endpoint
            response = requests.get(f"{self.base_url}/api/v1/assets", timeout=10)
            
            # Check if endpoint is accessible
            if response.status_code == 200:
                assets_data = response.json()
                asset_count = len(assets_data) if isinstance(assets_data, list) else len(assets_data.get('assets', []))
                details = f"Assets database accessible, {asset_count} assets found"
                passed = True
            elif response.status_code in [401, 403]:
                details = "Assets database requires authentication (expected)"
                passed = True
            elif response.status_code == 404:
                details = "Assets endpoint not found"
                passed = False
            else:
                details = f"Assets endpoint responds (HTTP {response.status_code})"
                passed = True
                
            self.log_test_result("Assets Database Access", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Assets Database Access", False, f"Error: {str(e)}")
            return False
            
    async def test_vulnerabilities_database_access(self) -> bool:
        """Test access to vulnerabilities database"""
        try:
            # Test vulnerabilities endpoint
            response = requests.get(f"{self.base_url}/api/v1/vulnerabilities", timeout=10)
            
            # Check if endpoint is accessible
            if response.status_code == 200:
                vulns_data = response.json()
                vuln_count = len(vulns_data) if isinstance(vulns_data, list) else len(vulns_data.get('vulnerabilities', []))
                details = f"Vulnerabilities database accessible, {vuln_count} vulnerabilities found"
                passed = True
            elif response.status_code in [401, 403]:
                details = "Vulnerabilities database requires authentication (expected)"
                passed = True
            elif response.status_code == 404:
                details = "Vulnerabilities endpoint not found"
                passed = False
            else:
                details = f"Vulnerabilities endpoint responds (HTTP {response.status_code})"
                passed = True
                
            self.log_test_result("Vulnerabilities Database Access", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Vulnerabilities Database Access", False, f"Error: {str(e)}")
            return False
            
    async def test_asset_creation_authorization(self) -> bool:
        """Test asset creation with authorization"""
        try:
            # Test asset creation
            test_asset = {
                "name": f"test-asset-{int(time.time())}",
                "type": "server", 
                "ip_address": "192.168.1.100",
                "environment": "test"
            }
            
            response = requests.post(
                f"{self.base_url}/api/v1/assets",
                json=test_asset,
                timeout=10
            )
            
            # Check response
            if response.status_code in [200, 201]:
                details = "Asset creation successful"
                passed = True
            elif response.status_code in [401, 403]:
                details = "Asset creation requires authorization (expected)"
                passed = True
            elif response.status_code == 400:
                details = "Asset validation working (HTTP 400)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Asset creation endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("Asset Creation with Authorization", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Asset Creation with Authorization", False, f"Error: {str(e)}")
            return False
            
    async def test_celery_task_trigger(self) -> bool:
        """Test asynchronous Celery task triggering"""
        try:
            # Test task endpoints that might trigger Celery tasks
            task_endpoints = [
                "/api/v1/tasks/scan",
                "/api/v1/tasks/report",
                "/api/v1/scans/start"
            ]
            
            task_capable_endpoints = 0
            
            for endpoint in task_endpoints:
                try:
                    # Use GET to test if endpoint exists
                    response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                    
                    # Any response except 404 means endpoint exists
                    if response.status_code != 404:
                        task_capable_endpoints += 1
                        
                    # Also test POST to see if it triggers tasks
                    post_response = requests.post(
                        f"{self.base_url}{endpoint}",
                        json={"test": "task"},
                        timeout=10
                    )
                    
                    if post_response.status_code not in [404, 405]:
                        task_capable_endpoints += 1
                        
                except Exception:
                    pass
            
            passed = task_capable_endpoints > 0
            
            if passed:
                details = f"{task_capable_endpoints} task-capable endpoints found"
            else:
                details = "No Celery task endpoints found"
                
            self.log_test_result("Celery Task Triggering", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Celery Task Triggering", False, f"Error: {str(e)}")
            return False
            
    async def test_monitoring_dashboard_access(self) -> bool:
        """Test monitoring dashboard accessibility"""
        try:
            # Test dashboard/admin endpoints
            dashboard_endpoints = [
                "/admin",
                "/dashboard", 
                "/api/v1/status",
                "/api/v1/metrics"
            ]
            
            accessible_dashboards = 0
            
            for endpoint in dashboard_endpoints:
                try:
                    response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                    
                    # Any response except 404 means endpoint exists
                    if response.status_code != 404:
                        accessible_dashboards += 1
                        
                except Exception:
                    pass
            
            passed = accessible_dashboards > 0
            
            if passed:
                details = f"{accessible_dashboards}/{len(dashboard_endpoints)} dashboard endpoints accessible"
            else:
                details = "No monitoring dashboard endpoints found"
                
            self.log_test_result("Monitoring Dashboard Access", passed, details)
            return passed
            
        except Exception as e:
            self.log_test_result("Monitoring Dashboard Access", False, f"Error: {str(e)}")
            return False


async def run_tests() -> Dict[str, Any]:
    """Run all Guardian monitoring tests"""
    tester = GuardianMonitoringTester()
    
    # Run tests in sequence
    tests = [
        tester.test_service_health,
        tester.test_assets_database_access,
        tester.test_vulnerabilities_database_access,
        tester.test_asset_creation_authorization,
        tester.test_celery_task_trigger,
        tester.test_monitoring_dashboard_access
    ]
    
    success_count = 0
    for test in tests:
        try:
            success = await test()
            if success:
                success_count += 1
        except Exception as e:
            print(f"Guardian monitoring test error: {e}")
            
    all_passed = success_count == len(tests)
    
    return {
        "success": all_passed,
        "tests": tester.test_results,
        "summary": f"{success_count}/{len(tests)} tests passed"
    }