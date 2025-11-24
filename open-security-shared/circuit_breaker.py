"""
Circuit Breaker pattern implementation for resilient external service calls.

Prevents cascade failures by temporarily halting requests to failing services.
Implements three states: CLOSED (normal), OPEN (failing), HALF_OPEN (testing recovery).

Based on Martin Fowler's Circuit Breaker pattern and Hystrix design.

Usage:
    from shared.circuit_breaker import CircuitBreaker, circuit_breaker
    
    breaker = CircuitBreaker(
        failure_threshold=5,
        timeout=60,
        recovery_timeout=30
    )
    
    @circuit_breaker(breaker)
    async def call_external_api():
        ...
"""

import asyncio
import time
from enum import Enum
from typing import Callable, Optional, Any
from functools import wraps
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"       # Normal operation, requests pass through
    OPEN = "open"           # Failing, requests immediately rejected
    HALF_OPEN = "half_open" # Testing recovery, limited requests allowed


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5          # Failures before opening circuit
    success_threshold: int = 2          # Successes to close from half-open
    timeout: int = 60                   # Seconds before allowing retry
    recovery_timeout: int = 30          # Half-open window duration
    expected_exception: type = Exception # Exception type to count as failure


@dataclass
class CircuitBreakerStats:
    """Statistics tracked by circuit breaker."""
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    state_changed_at: float = field(default_factory=time.time)
    total_calls: int = 0
    rejected_calls: int = 0


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is OPEN."""
    pass


class CircuitBreaker:
    """
    Circuit breaker for external service calls.
    
    State transitions:
    - CLOSED → OPEN: After `failure_threshold` consecutive failures
    - OPEN → HALF_OPEN: After `timeout` seconds
    - HALF_OPEN → CLOSED: After `success_threshold` consecutive successes
    - HALF_OPEN → OPEN: On any failure
    
    Example:
        breaker = CircuitBreaker(failure_threshold=5, timeout=60)
        
        @circuit_breaker(breaker)
        async def fetch_threat_intel():
            async with httpx.AsyncClient() as client:
                response = await client.get("https://threatfeed.example.com")
                return response.json()
    """
    
    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        success_threshold: int = 2,
        timeout: int = 60,
        recovery_timeout: int = 30,
        expected_exception: type = Exception
    ):
        self.name = name
        self.config = CircuitBreakerConfig(
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout,
            recovery_timeout=recovery_timeout,
            expected_exception=expected_exception
        )
        self.stats = CircuitBreakerStats()
        self.state = CircuitState.CLOSED
        self._lock = asyncio.Lock()
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Raises:
            CircuitBreakerError: If circuit is OPEN
            Exception: Original exception if call fails
        """
        self.stats.total_calls += 1
        
        async with self._lock:
            # Check if circuit should transition from OPEN to HALF_OPEN
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    logger.info(f"Circuit breaker '{self.name}': OPEN → HALF_OPEN (attempting recovery)")
                    self.state = CircuitState.HALF_OPEN
                    self.stats.state_changed_at = time.time()
                else:
                    self.stats.rejected_calls += 1
                    time_until_retry = int(
                        self.config.timeout - (time.time() - self.stats.state_changed_at)
                    )
                    logger.warning(
                        f"Circuit breaker '{self.name}' is OPEN. "
                        f"Retry in {time_until_retry}s. "
                        f"Rejected calls: {self.stats.rejected_calls}"
                    )
                    raise CircuitBreakerError(
                        f"Circuit breaker '{self.name}' is OPEN. "
                        f"Service unavailable. Retry in {time_until_retry} seconds."
                    )
        
        # Execute function
        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        
        except self.config.expected_exception as e:
            await self._on_failure()
            raise e
    
    async def _on_success(self):
        """Handle successful call."""
        async with self._lock:
            self.stats.success_count += 1
            self.stats.last_success_time = time.time()
            
            if self.state == CircuitState.HALF_OPEN:
                if self.stats.success_count >= self.config.success_threshold:
                    logger.info(
                        f"Circuit breaker '{self.name}': HALF_OPEN → CLOSED "
                        f"({self.stats.success_count} consecutive successes)"
                    )
                    self.state = CircuitState.CLOSED
                    self.stats.failure_count = 0
                    self.stats.success_count = 0
                    self.stats.state_changed_at = time.time()
    
    async def _on_failure(self):
        """Handle failed call."""
        async with self._lock:
            self.stats.failure_count += 1
            self.stats.success_count = 0  # Reset success counter
            self.stats.last_failure_time = time.time()
            
            if self.state == CircuitState.HALF_OPEN:
                # Immediate transition back to OPEN on any failure
                logger.warning(
                    f"Circuit breaker '{self.name}': HALF_OPEN → OPEN "
                    f"(recovery failed)"
                )
                self.state = CircuitState.OPEN
                self.stats.state_changed_at = time.time()
            
            elif self.state == CircuitState.CLOSED:
                if self.stats.failure_count >= self.config.failure_threshold:
                    logger.error(
                        f"Circuit breaker '{self.name}': CLOSED → OPEN "
                        f"({self.stats.failure_count} failures, "
                        f"threshold: {self.config.failure_threshold})"
                    )
                    self.state = CircuitState.OPEN
                    self.stats.state_changed_at = time.time()
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit should transition from OPEN to HALF_OPEN."""
        if self.state != CircuitState.OPEN:
            return False
        
        time_since_open = time.time() - self.stats.state_changed_at
        return time_since_open >= self.config.timeout
    
    def get_state(self) -> dict:
        """Get current circuit breaker state for monitoring."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.stats.failure_count,
            "success_count": self.stats.success_count,
            "total_calls": self.stats.total_calls,
            "rejected_calls": self.stats.rejected_calls,
            "last_failure_time": self.stats.last_failure_time,
            "last_success_time": self.stats.last_success_time,
            "state_duration_seconds": time.time() - self.stats.state_changed_at,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "timeout": self.config.timeout
            }
        }
    
    async def reset(self):
        """Manually reset circuit breaker (for testing/admin)."""
        async with self._lock:
            logger.info(f"Circuit breaker '{self.name}': Manual reset to CLOSED")
            self.state = CircuitState.CLOSED
            self.stats = CircuitBreakerStats()


def circuit_breaker(breaker: CircuitBreaker):
    """
    Decorator to protect async function with circuit breaker.
    
    Usage:
        openai_breaker = CircuitBreaker(
            name="openai",
            failure_threshold=3,
            timeout=120
        )
        
        @circuit_breaker(openai_breaker)
        async def call_openai_api(prompt: str):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)
        
        # Attach breaker for monitoring
        wrapper.__circuit_breaker__ = breaker
        
        return wrapper
    return decorator


# Global circuit breakers for common external services
OPENAI_BREAKER = CircuitBreaker(
    name="openai",
    failure_threshold=3,
    timeout=120,  # 2 minutes
    recovery_timeout=60
)

THREAT_FEED_BREAKER = CircuitBreaker(
    name="threat_feeds",
    failure_threshold=5,
    timeout=300,  # 5 minutes
    recovery_timeout=120
)

AWS_API_BREAKER = CircuitBreaker(
    name="aws_api",
    failure_threshold=10,
    timeout=180,  # 3 minutes
    recovery_timeout=60
)

AZURE_API_BREAKER = CircuitBreaker(
    name="azure_api",
    failure_threshold=10,
    timeout=180,
    recovery_timeout=60
)

GCP_API_BREAKER = CircuitBreaker(
    name="gcp_api",
    failure_threshold=10,
    timeout=180,
    recovery_timeout=60
)


# Example usage
"""
from shared.circuit_breaker import circuit_breaker, OPENAI_BREAKER
import httpx

@circuit_breaker(OPENAI_BREAKER)
async def analyze_with_ai(threat_data: dict):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": str(threat_data)}]
            },
            timeout=30.0
        )
        response.raise_for_status()
        return response.json()

# If OpenAI API fails 3 times, circuit opens
# Requests rejected for 120 seconds
# After timeout, attempts recovery with limited requests
# If 2 consecutive successes, circuit closes and normal operation resumes
"""
