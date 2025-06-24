"""
Rate limiting utilities for API requests and data collection
"""

import asyncio
import time
from typing import Dict, Optional
from dataclasses import dataclass, field

@dataclass
class RateLimitState:
    """State tracking for rate limiting"""
    requests: int = 0
    window_start: float = field(default_factory=time.time)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

class RateLimiter:
    """Async rate limiter with sliding window"""
    
    def __init__(self, max_requests: int, time_window: int):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Maximum number of requests allowed
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.state = RateLimitState()
    
    async def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        Acquire permission to make a request
        
        Args:
            timeout: Maximum time to wait for permission
            
        Returns:
            True if permission granted, False if timeout
        """
        start_time = time.time()
        
        while True:
            async with self.state.lock:
                current_time = time.time()
                
                # Reset window if time window has passed
                if current_time - self.state.window_start >= self.time_window:
                    self.state.requests = 0
                    self.state.window_start = current_time
                
                # Check if we can make a request
                if self.state.requests < self.max_requests:
                    self.state.requests += 1
                    return True
                
                # Check timeout
                if timeout and (current_time - start_time) >= timeout:
                    return False
            
            # Wait a bit before checking again
            await asyncio.sleep(0.1)
    
    def get_status(self) -> Dict[str, float]:
        """Get current rate limit status"""
        current_time = time.time()
        window_elapsed = current_time - self.state.window_start
        
        return {
            "requests_made": self.state.requests,
            "max_requests": self.max_requests,
            "window_elapsed": window_elapsed,
            "window_duration": self.time_window,
            "requests_remaining": max(0, self.max_requests - self.state.requests),
            "time_until_reset": max(0, self.time_window - window_elapsed)
        }

class GlobalRateLimiter:
    """Global rate limiter managing multiple named limiters"""
    
    def __init__(self):
        self._limiters: Dict[str, RateLimiter] = {}
    
    def get_limiter(self, name: str, max_requests: int, time_window: int) -> RateLimiter:
        """Get or create a named rate limiter"""
        if name not in self._limiters:
            self._limiters[name] = RateLimiter(max_requests, time_window)
        return self._limiters[name]
    
    async def acquire(self, name: str, max_requests: int, time_window: int, 
                     timeout: Optional[float] = None) -> bool:
        """Acquire permission from a named rate limiter"""
        limiter = self.get_limiter(name, max_requests, time_window)
        return await limiter.acquire(timeout)
    
    def get_all_status(self) -> Dict[str, Dict[str, float]]:
        """Get status of all rate limiters"""
        return {name: limiter.get_status() for name, limiter in self._limiters.items()}

# Global instance
global_rate_limiter = GlobalRateLimiter()
