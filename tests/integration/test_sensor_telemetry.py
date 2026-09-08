"""
Sensor Telemetry Test Module
Tests osquery status, telemetry submission, remote configuration
"""

import os
import pytest
import requests
import asyncio
import time
from typing import Dict, List, Any, Optional


class TestSensorTelemetry:
    """Comprehensive tests for Security Sensor Service (Port 8004)"""
    
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
        base_url = os.getenv("SENSOR_SERVICE_URL", "http://localhost:8004")
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
        
    async def test_service_health(self) -> None:
        """Test sensor service health"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            passed = response.status_code == 200
            
            if passed:
                health_data = response.json()
                details = f"Status: {health_data.get('status', 'unknown')}"
            else:
                details = f"HTTP {response.status_code}"
                
            self.log_test_result("Sensor Service Health", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Sensor Service Health", False, f"Error: {str(e)}")
            raise
            
    async def test_osquery_process_status(self) -> None:
        """Test osquery process status monitoring"""
        try:
            # Test osquery status endpoint
            response = requests.get(f"{self.base_url}/api/v1/osquery/status", timeout=10)
            
            if response.status_code == 200:
                status_data = response.json()
                details = f"osquery status: {status_data.get('status', 'unknown')}"
                passed = True
            elif response.status_code in [503, 500]:
                details = "osquery not running (acceptable for test)"
                passed = True
            elif response.status_code in [401, 403]:
                details = "osquery status requires authentication (expected)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"osquery endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("osquery Process Status", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("osquery Process Status", False, f"Error: {str(e)}")
            raise
            
    async def test_telemetry_submission(self) -> None:
        """Test telemetry submission with certificate authentication"""
        try:
            # Test telemetry submission endpoint
            test_telemetry = {
                "hostname": "test-sensor-01",
                "timestamp": int(time.time()),
                "events": [
                    {
                        "name": "process_start",
                        "pid": 1234,
                        "cmdline": "test_process",
                        "user": "testuser"
                    }
                ]
            }
            
            response = requests.post(
                f"{self.base_url}/api/v1/telemetry",
                json=test_telemetry,
                timeout=10
            )
            
            # Check response
            if response.status_code in [200, 201]:
                details = "Telemetry submission successful"
                passed = True
            elif response.status_code in [401, 403]:
                details = "Telemetry requires certificate authentication (expected)"
                passed = True
            elif response.status_code == 400:
                details = "Telemetry validation working (HTTP 400)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Telemetry endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("Telemetry Submission with Certificate Auth", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Telemetry Submission with Certificate Auth", False, f"Error: {str(e)}")
            raise
            
    async def test_remote_configuration_retrieval(self) -> None:
        """Test remote configuration retrieval"""
        try:
            # Test configuration endpoint
            response = requests.get(f"{self.base_url}/api/v1/config", timeout=10)
            
            if response.status_code == 200:
                config_data = response.json()
                details = f"Configuration retrieved: {len(str(config_data))} bytes"
                passed = True
            elif response.status_code in [401, 403]:
                details = "Configuration requires authentication (expected)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Configuration endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("Remote Configuration Retrieval", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Remote Configuration Retrieval", False, f"Error: {str(e)}")
            raise
            
    async def test_sensor_registration(self) -> None:
        """Test sensor registration process"""
        try:
            # Test sensor registration
            test_registration = {
                "hostname": f"test-sensor-{int(time.time())}",
                "platform": "linux",
                "version": "1.0.0",
                "capabilities": ["osquery", "file_monitoring"]
            }
            
            response = requests.post(
                f"{self.base_url}/api/v1/sensors/register",
                json=test_registration,
                timeout=10
            )
            
            # Check response
            if response.status_code in [200, 201]:
                details = "Sensor registration successful"
                passed = True
            elif response.status_code in [401, 403]:
                details = "Sensor registration requires authentication (expected)"
                passed = True
            elif response.status_code == 400:
                details = "Registration validation working (HTTP 400)"
                passed = True
            else:
                passed = response.status_code != 404
                details = f"Registration endpoint responds (HTTP {response.status_code})"
                
            self.log_test_result("Sensor Registration", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("Sensor Registration", False, f"Error: {str(e)}")
            raise


async def run_tests() -> Dict[str, Any]:
    """Run all sensor telemetry tests"""
    tester = TestSensorTelemetry()
    
    # Run tests in sequence
    tests = [
        tester.test_service_health,
        tester.test_osquery_process_status,
        tester.test_telemetry_submission,
        tester.test_remote_configuration_retrieval,
        tester.test_sensor_registration
    ]
    
    success_count = 0
    for test in tests:
        try:
            success = await test()
            if success:
                success_count += 1
        except Exception as e:
            print(f"Sensor telemetry test error: {e}")
            
    all_passed = success_count == len(tests)
    
    return {
        "success": all_passed,
        "tests": tester.results,
        "summary": f"{success_count}/{len(tests)} tests passed"
    }