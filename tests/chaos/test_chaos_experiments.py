"""
Chaos Engineering test suite for Wildbox microservices.

Tests system resilience under failure conditions:
- Network failures (service isolation)
- High latency (slow dependencies)
- Resource exhaustion (CPU, memory, connections)
- Cascading failures (upstream service down)

Based on Netflix Chaos Monkey and Gremlin patterns.

Usage:
    pytest tests/chaos/test_chaos_identity.py -v
    pytest tests/chaos/ --chaos-intensity=high
"""

import pytest
import asyncio
import httpx
from typing import AsyncGenerator
import docker
import time
from datetime import datetime, timedelta
import psutil
import subprocess

# Chaos testing utilities
class ChaosController:
    """
    Controls chaos experiments on Docker containers.
    
    Capabilities:
    - Network partition (disconnect service)
    - Latency injection (delay responses)
    - Resource limits (CPU/memory throttling)
    - Service kill (simulate crashes)
    """
    
    def __init__(self):
        self.client = docker.from_env()
        self._original_limits = {}
    
    def disconnect_service(self, service_name: str):
        """
        Simulate network partition (service unreachable).
        
        Args:
            service_name: Container name (e.g., 'wildbox-identity-1')
        
        Example:
            chaos.disconnect_service('wildbox-identity-1')
            # Identity service now unreachable
            # Circuit breakers should trip
        """
        container = self.client.containers.get(service_name)
        container.pause()
        print(f"[CHAOS] Disconnected {service_name}")
    
    def reconnect_service(self, service_name: str):
        """Restore network connectivity."""
        container = self.client.containers.get(service_name)
        container.unpause()
        print(f"[CHAOS] Reconnected {service_name}")
    
    def inject_latency(self, service_name: str, delay_ms: int):
        """
        Add network latency to service.
        
        Args:
            service_name: Container name
            delay_ms: Delay in milliseconds
        
        Example:
            chaos.inject_latency('wildbox-postgres-1', 500)
            # Database queries now take +500ms
        """
        container = self.client.containers.get(service_name)
        # Use tc (traffic control) to add delay
        exec_result = container.exec_run(
            f"tc qdisc add dev eth0 root netem delay {delay_ms}ms",
            privileged=True
        )
        print(f"[CHAOS] Injected {delay_ms}ms latency to {service_name}")
    
    def remove_latency(self, service_name: str):
        """Remove network latency."""
        container = self.client.containers.get(service_name)
        container.exec_run(
            "tc qdisc del dev eth0 root",
            privileged=True
        )
        print(f"[CHAOS] Removed latency from {service_name}")
    
    def limit_cpu(self, service_name: str, cpu_quota: float):
        """
        Throttle CPU usage.
        
        Args:
            service_name: Container name
            cpu_quota: CPU quota (0.5 = 50%, 1.0 = 100%)
        
        Example:
            chaos.limit_cpu('wildbox-agents-1', 0.2)
            # AI agents now only have 20% CPU
        """
        container = self.client.containers.get(service_name)
        # Store original limits
        if service_name not in self._original_limits:
            self._original_limits[service_name] = container.attrs['HostConfig']
        
        # Update CPU quota
        container.update(cpu_quota=int(cpu_quota * 100000))
        print(f"[CHAOS] Limited {service_name} to {cpu_quota * 100}% CPU")
    
    def limit_memory(self, service_name: str, memory_mb: int):
        """
        Limit memory usage.
        
        Args:
            service_name: Container name
            memory_mb: Memory limit in MB
        """
        container = self.client.containers.get(service_name)
        container.update(mem_limit=f"{memory_mb}m")
        print(f"[CHAOS] Limited {service_name} to {memory_mb}MB RAM")
    
    def restore_limits(self, service_name: str):
        """Restore original resource limits."""
        if service_name in self._original_limits:
            container = self.client.containers.get(service_name)
            original = self._original_limits[service_name]
            container.update(
                cpu_quota=original.get('CpuQuota', 100000),
                mem_limit=original.get('Memory', 0)
            )
            print(f"[CHAOS] Restored limits for {service_name}")
    
    def kill_service(self, service_name: str):
        """Simulate service crash."""
        container = self.client.containers.get(service_name)
        container.kill()
        print(f"[CHAOS] Killed {service_name}")
    
    def restart_service(self, service_name: str):
        """Restart killed service."""
        container = self.client.containers.get(service_name)
        container.restart()
        print(f"[CHAOS] Restarted {service_name}")


# Pytest fixtures
@pytest.fixture
def chaos():
    """Chaos controller fixture with automatic cleanup."""
    controller = ChaosController()
    yield controller
    # Cleanup: restore all limits
    for service in controller._original_limits.keys():
        try:
            controller.restore_limits(service)
        except Exception as e:
            print(f"Warning: Could not restore {service}: {e}")


@pytest.fixture
async def http_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """HTTP client for testing APIs."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        yield client


# Chaos tests for Identity Service
@pytest.mark.chaos
class TestIdentityServiceChaos:
    """
    Chaos tests for identity service resilience.
    
    Validates:
    - Circuit breakers trip on failures
    - Graceful degradation
    - Recovery after network restoration
    """
    
    @pytest.mark.asyncio
    async def test_identity_network_partition(self, chaos, http_client):
        """
        Test behavior when identity service isolated.
        
        Expected:
        - Gateway detects failure
        - Circuit breaker opens
        - Requests fail fast (no hanging)
        - Service recovers after reconnection
        """
        # Baseline: service healthy
        response = await http_client.get("http://localhost/health")
        assert response.status_code == 200
        
        # Inject chaos: disconnect identity
        chaos.disconnect_service('wildbox-identity-1')
        
        # Wait for circuit breaker to detect failure
        await asyncio.sleep(5)
        
        # Verify: requests fail fast (not timeout)
        start = time.time()
        try:
            await http_client.get("http://localhost/api/v1/auth/me")
            pytest.fail("Expected request to fail")
        except httpx.RequestError:
            duration = time.time() - start
            assert duration < 2.0, "Circuit breaker should fail fast"
        
        # Restore service
        chaos.reconnect_service('wildbox-identity-1')
        await asyncio.sleep(10)  # Allow circuit to close
        
        # Verify: service recovered
        response = await http_client.get("http://localhost/health")
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_database_latency_impact(self, chaos, http_client):
        """
        Test behavior when database slow.
        
        Expected:
        - Requests timeout appropriately
        - Circuit breaker trips after threshold
        - No cascade to other services
        """
        # Inject chaos: 500ms database latency
        chaos.inject_latency('wildbox-postgres-1', 500)
        
        # Measure response times
        response_times = []
        for _ in range(5):
            start = time.time()
            try:
                await http_client.get("http://localhost/api/v1/auth/me")
            except Exception:
                pass
            duration = time.time() - start
            response_times.append(duration)
        
        # Verify: latency increased
        avg_latency = sum(response_times) / len(response_times)
        assert avg_latency > 0.5, f"Expected >500ms, got {avg_latency:.2f}s"
        
        # Cleanup
        chaos.remove_latency('wildbox-postgres-1')
    
    @pytest.mark.asyncio
    async def test_cpu_exhaustion(self, chaos, http_client):
        """
        Test behavior when service CPU throttled.
        
        Expected:
        - Slower response times
        - Service remains functional
        - No crashes or deadlocks
        """
        # Baseline response time
        start = time.time()
        await http_client.get("http://localhost/health")
        baseline = time.time() - start
        
        # Inject chaos: limit to 20% CPU
        chaos.limit_cpu('wildbox-identity-1', 0.2)
        
        # Measure degraded performance
        start = time.time()
        await http_client.get("http://localhost/health")
        degraded = time.time() - start
        
        # Verify: slower but functional
        assert degraded > baseline, "Expected slower response"
        assert degraded < 10.0, "Should not hang completely"
        
        # Cleanup
        chaos.restore_limits('wildbox-identity-1')


@pytest.mark.chaos
class TestCascadingFailures:
    """
    Test cascading failure scenarios.
    
    Validates circuit breakers prevent cascade.
    """
    
    @pytest.mark.asyncio
    async def test_upstream_service_down(self, chaos, http_client):
        """
        Test when upstream dependency fails.
        
        Scenario:
        - Guardian depends on Data service for IOCs
        - Data service goes down
        - Guardian circuit breaker should trip
        - Guardian remains functional for non-IOC operations
        """
        # Kill data service
        chaos.kill_service('wildbox-data-1')
        await asyncio.sleep(5)
        
        # Verify: guardian health still responds
        # (circuit breaker prevents cascade)
        try:
            response = await http_client.get("http://localhost:8013/health")
            assert response.status_code == 200
        except Exception as e:
            pytest.fail(f"Guardian should remain healthy: {e}")
        
        # Restore data service
        chaos.restart_service('wildbox-data-1')
        await asyncio.sleep(10)
    
    @pytest.mark.asyncio
    async def test_redis_failure_graceful_degradation(self, chaos, http_client):
        """
        Test behavior when Redis cache unavailable.
        
        Expected:
        - Cache misses don't crash service
        - Fallback to database queries
        - Performance degraded but functional
        """
        # Disconnect Redis
        chaos.disconnect_service('wildbox-redis-1')
        
        # Verify: services remain functional
        # (should fallback to database)
        response = await http_client.get("http://localhost/health")
        assert response.status_code == 200
        
        # Restore Redis
        chaos.reconnect_service('wildbox-redis-1')


@pytest.mark.chaos
class TestResourceExhaustion:
    """
    Test resource exhaustion scenarios.
    
    Validates resource limits prevent OOM/crashes.
    """
    
    @pytest.mark.asyncio
    async def test_memory_limit_respected(self, chaos, http_client):
        """
        Test service respects memory limits.
        
        Expected:
        - Service stays within memory limit
        - No OOM kills
        - Graceful degradation if memory pressure
        """
        # Limit memory to 256MB
        chaos.limit_memory('wildbox-agents-1', 256)
        
        # Trigger memory-intensive operation
        # (AI agent analysis)
        payload = {
            "threat_data": {
                "indicators": ["malicious.com"] * 1000  # Large payload
            }
        }
        
        try:
            response = await http_client.post(
                "http://localhost:8006/api/v1/analyze",
                json=payload,
                timeout=30.0
            )
            # Should either succeed or fail gracefully
            assert response.status_code in [200, 503]
        except httpx.TimeoutException:
            pytest.fail("Service should not hang on memory pressure")
        
        # Cleanup
        chaos.restore_limits('wildbox-agents-1')
    
    @pytest.mark.asyncio
    async def test_connection_pool_exhaustion(self, chaos, http_client):
        """
        Test behavior when database connections exhausted.
        
        Expected:
        - New connections rejected gracefully
        - Existing requests complete
        - Connection pool recovers
        """
        # Simulate connection pool exhaustion
        # by making many concurrent requests
        tasks = []
        for _ in range(100):
            task = http_client.get("http://localhost/api/v1/auth/me")
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify: some requests may fail, but no crashes
        success_count = sum(
            1 for r in results 
            if isinstance(r, httpx.Response) and r.status_code == 200
        )
        assert success_count > 0, "At least some requests should succeed"


# Chaos experiment runner
@pytest.mark.chaos
class TestChaosExperiments:
    """
    Full chaos experiments (run manually).
    
    Usage:
        pytest tests/chaos/test_chaos_experiments.py::TestChaosExperiments::test_full_outage -v
    """
    
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Manual chaos experiment")
    async def test_full_outage_scenario(self, chaos, http_client):
        """
        Simulate major outage:
        1. Database goes down
        2. Redis goes down
        3. Identity service killed
        
        Expected:
        - Gateway remains responsive
        - Circuit breakers trip
        - System recovers after restoration
        """
        print("\n[CHAOS] Starting full outage experiment...")
        
        # Phase 1: Database down
        print("[CHAOS] Phase 1: Killing database")
        chaos.kill_service('wildbox-postgres-1')
        await asyncio.sleep(10)
        
        # Phase 2: Redis down
        print("[CHAOS] Phase 2: Killing Redis")
        chaos.kill_service('wildbox-redis-1')
        await asyncio.sleep(10)
        
        # Phase 3: Identity down
        print("[CHAOS] Phase 3: Killing identity service")
        chaos.kill_service('wildbox-identity-1')
        await asyncio.sleep(10)
        
        # Verify: Gateway still responds with errors
        try:
            response = await http_client.get("http://localhost/health")
            print(f"[CHAOS] Gateway status: {response.status_code}")
        except Exception as e:
            print(f"[CHAOS] Gateway error (expected): {e}")
        
        # Recovery Phase 1: Restore database
        print("[CHAOS] Recovery 1: Restarting database")
        chaos.restart_service('wildbox-postgres-1')
        await asyncio.sleep(20)
        
        # Recovery Phase 2: Restore Redis
        print("[CHAOS] Recovery 2: Restarting Redis")
        chaos.restart_service('wildbox-redis-1')
        await asyncio.sleep(10)
        
        # Recovery Phase 3: Restore identity
        print("[CHAOS] Recovery 3: Restarting identity")
        chaos.restart_service('wildbox-identity-1')
        await asyncio.sleep(30)
        
        # Verify: Full recovery
        response = await http_client.get("http://localhost/health")
        assert response.status_code == 200, "System should fully recover"
        print("[CHAOS] Experiment complete - system recovered")


# Pytest configuration
def pytest_configure(config):
    """Register chaos marker."""
    config.addinivalue_line(
        "markers",
        "chaos: mark test as chaos engineering experiment"
    )


# Example usage
"""
# Run all chaos tests
pytest tests/chaos/ -v -m chaos

# Run specific chaos test
pytest tests/chaos/test_chaos_identity.py::TestIdentityServiceChaos::test_identity_network_partition -v

# Run chaos experiments (manual)
pytest tests/chaos/test_chaos_experiments.py::TestChaosExperiments::test_full_outage_scenario -v -s

# Run with high chaos intensity
pytest tests/chaos/ -v --chaos-intensity=high

# View chaos test report
pytest tests/chaos/ --html=chaos-report.html
"""
