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
        # The sensor's local API authenticates with its own key (SENSOR_API_KEY),
        # not the platform one: it is an agent on a host, not a gateway client.
        self.sensor_headers = {"X-API-Key": os.getenv("SENSOR_API_KEY", "")}
        # Collected telemetry is read back from the data service, through the
        # gateway: the data service answers 403 GATEWAY_AUTH_REQUIRED to a
        # direct connection.
        self.data_url = os.getenv("GATEWAY_URL", "https://localhost") + "/api/v1/data"
        self.headers = {"X-API-Key": os.getenv("TEST_API_KEY", "")}
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
            # /api/v1/components is where the sensor reports its collectors,
            # osquery among them. /api/v1/osquery/status has never existed: the
            # sensor's routes are /health, /status, /api/v1/{status,stats,
            # components,config,queries,query,test-connection,dashboard/metrics}.
            response = requests.get(
                f"{self.base_url}/api/v1/components",
                headers=self.sensor_headers,
                timeout=10,
            )
            
            if response.status_code == 200:
                components = response.json()
                osquery = (components or {}).get("osquery_manager")
                if not isinstance(osquery, dict):
                    passed = False
                    details = f"no osquery_manager component reported: {list(components)}"
                elif not isinstance(osquery.get("running"), bool):
                    passed = False
                    details = f"osquery_manager does not report a running state: {osquery}"
                else:
                    passed = True
                    details = (
                        f"osquery_manager running={osquery['running']}, "
                        f"{osquery.get('total_queries', 0)} queries in "
                        f"{len(osquery.get('query_packs') or [])} pack(s)"
                    )
            elif response.status_code == 503:
                # Fails closed when SENSOR_API_KEY is unset. That is correct
                # behaviour, and a deployment that has not set it is a
                # configuration problem, not a test failure.
                passed = False
                details = (
                    "sensor local API is disabled: SENSOR_API_KEY is not "
                    "configured, so every route but /health answers 503"
                )
            elif response.status_code in [401, 403]:
                passed = False
                details = "sensor rejected SENSOR_API_KEY"
            self.log_test_result("osquery Process Status", passed, details)
            assert passed, details
            
        except Exception as e:
            self.log_test_result("osquery Process Status", False, f"Error: {str(e)}")
            raise
            
    async def test_telemetry_pipeline(self) -> None:
        """The sensor collects events and the data service serves them back.

        There is no telemetry *submission* API to call: the sensor pushes to
        the data lake on its own schedule, and the data service publishes
        /api/v1/telemetry/events and /api/v1/telemetry/stats as GET only. This
        test used to POST to {sensor}/api/v1/telemetry, a route that exists in
        neither service, and accept "400, 401 or 403" as success -- so a 404
        from a non-existent endpoint was the only outcome it could not report.
        """
        try:
            problems = []

            stats = requests.get(
                f"{self.base_url}/api/v1/stats",
                headers=self.sensor_headers,
                timeout=10,
            )
            if stats.status_code != 200:
                problems.append(f"sensor /api/v1/stats -> HTTP {stats.status_code}")
            else:
                counters = stats.json()
                if isinstance(counters, dict) and "stats" in counters:
                    counters = counters["stats"]
                for field in ("events_collected", "events_processed"):
                    if not isinstance((counters or {}).get(field), int):
                        problems.append(f"sensor does not report {field}")

            # The read side, on the data service.
            for path in ("/telemetry/events", "/telemetry/stats"):
                resp = requests.get(f"{self.data_url}{path}", headers=self.headers, timeout=10)
                if resp.status_code == 404:
                    problems.append(f"data service does not serve /api/v1{path}")

            passed = not problems
            details = (
                "Telemetry pipeline reachable end to end"
                if passed
                else "; ".join(problems)
            )

            self.log_test_result("Telemetry Pipeline", passed, details)
            assert passed, details

        except Exception as e:
            self.log_test_result("Telemetry Pipeline", False, f"Error: {str(e)}")
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
            
    async def test_sensor_inventory(self) -> None:
        """The data service publishes the sensors it knows about.

        There is no registration API. This used to POST to
        {sensor}/api/v1/sensors/register -- no such route on the sensor, and
        the data service's /api/v1/sensors is GET only -- and then accepted
        400/401/403 as evidence that "registration validation" worked. A sensor
        appears in the inventory by reporting to the data lake, so what is
        verifiable here is that the inventory is served and well formed.
        """
        try:
            response = requests.get(
                f"{self.data_url}/sensors", headers=self.headers, timeout=10
            )

            if response.status_code != 200:
                passed = False
                details = f"data service /api/v1/sensors -> HTTP {response.status_code}"
            else:
                sensors = response.json()
                if isinstance(sensors, dict):
                    sensors = sensors.get("sensors", [])
                if not isinstance(sensors, list):
                    passed = False
                    details = f"unexpected payload: {type(sensors).__name__}"
                else:
                    unnamed = [
                        entry
                        for entry in sensors
                        if not isinstance(entry, dict)
                        or not (entry.get("sensor_id") or entry.get("hostname"))
                    ]
                    passed = not unnamed
                    details = (
                        f"{len(sensors)} sensor(s) in the inventory, all identified"
                        if passed
                        else f"{len(unnamed)} sensor entr(ies) without an identifier"
                    )

            self.log_test_result("Sensor Inventory", passed, details)
            assert passed, details

        except Exception as e:
            self.log_test_result("Sensor Inventory", False, f"Error: {str(e)}")
            raise
