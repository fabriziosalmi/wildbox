#!/usr/bin/env python3
"""
Rate Limiting End-to-End Test
Sprint 1: Test gateway rate limiting (100 req/min with 20 burst)
"""

import asyncio
import sys
import time
from typing import List
import httpx

# Test configuration
GATEWAY_URL = "http://localhost"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

class RateLimitTester:
    def __init__(self):
        self.base_url = GATEWAY_URL
        self.test_results = []
        
    def log(self, message: str, color: str = Colors.BLUE):
        """Print colored log message"""
        print(f"{color}{message}{Colors.END}")
        
    def success(self, test_name: str):
        """Record successful test"""
        self.log(f"✓ {test_name}", Colors.GREEN)
        self.test_results.append((test_name, True))
        
    def failure(self, test_name: str, error: str):
        """Record failed test"""
        self.log(f"✗ {test_name}: {error}", Colors.RED)
        self.test_results.append((test_name, False))
    
    async def test_01_health_check_exempt(self) -> bool:
        """Test that health checks are exempt from rate limiting"""
        test_name = "Health check exempt from rate limiting"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Make 50 rapid health check requests
                tasks = []
                for _ in range(50):
                    tasks.append(client.get(f"{self.base_url}/health"))
                
                responses = await asyncio.gather(*tasks)
                
                # All should succeed (200)
                success_count = sum(1 for r in responses if r.status_code == 200)
                rate_limited = sum(1 for r in responses if r.status_code == 429)
                
                if rate_limited > 0:
                    self.failure(test_name, f"{rate_limited} health checks were rate limited")
                    return False
                
                if success_count != 50:
                    self.failure(test_name, f"Only {success_count}/50 succeeded")
                    return False
                
                self.success(test_name)
                self.log(f"  Sent 50 rapid health checks, all succeeded", Colors.YELLOW)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_02_burst_allowance(self) -> bool:
        """Test burst allowance (20 immediate requests allowed)"""
        test_name = "Burst allowance (20 requests)"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Make 20 rapid requests (within burst limit)
                tasks = []
                for _ in range(20):
                    tasks.append(client.get(f"{self.base_url}/auth/jwt/login"))
                
                start_time = time.time()
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                duration = time.time() - start_time
                
                # Count status codes (exclude exceptions)
                status_codes = [r.status_code for r in responses if hasattr(r, 'status_code')]
                rate_limited = sum(1 for code in status_codes if code == 429)
                
                # Within burst limit, none should be rate limited
                if rate_limited > 0:
                    self.failure(test_name, f"{rate_limited}/20 requests were rate limited (burst should allow 20)")
                    return False
                
                self.success(test_name)
                self.log(f"  Sent 20 rapid requests in {duration:.2f}s, none rate limited", Colors.YELLOW)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_03_rate_limit_triggered(self) -> bool:
        """Test that rate limit is triggered after exceeding burst"""
        test_name = "Rate limit triggered (25+ requests)"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Make 25 rapid requests (exceeds burst of 20)
                tasks = []
                for _ in range(25):
                    tasks.append(client.get(f"{self.base_url}/auth/jwt/login"))
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Count status codes
                status_codes = [r.status_code for r in responses if hasattr(r, 'status_code')]
                rate_limited = sum(1 for code in status_codes if code == 429)
                
                # At least some should be rate limited
                if rate_limited == 0:
                    self.failure(test_name, "No requests were rate limited (expected some after burst)")
                    return False
                
                self.success(test_name)
                self.log(f"  Sent 25 rapid requests, {rate_limited} rate limited (as expected)", Colors.YELLOW)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_04_rate_limit_response_format(self) -> bool:
        """Test that 429 response has correct format and headers"""
        test_name = "Rate limit response format (429)"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Trigger rate limit with many rapid requests
                for _ in range(30):
                    response = await client.get(f"{self.base_url}/auth/jwt/login")
                    
                    if response.status_code == 429:
                        # Check headers
                        if "X-RateLimit-Limit" not in response.headers:
                            self.failure(test_name, "Missing X-RateLimit-Limit header")
                            return False
                        
                        if "Retry-After" not in response.headers:
                            self.failure(test_name, "Missing Retry-After header")
                            return False
                        
                        # Check JSON response format
                        try:
                            data = response.json()
                            if "error" not in data:
                                self.failure(test_name, "Missing 'error' field in response")
                                return False
                            
                            error = data["error"]
                            required_fields = ["code", "message", "type"]
                            for field in required_fields:
                                if field not in error:
                                    self.failure(test_name, f"Missing '{field}' in error object")
                                    return False
                            
                            if error["code"] != 429:
                                self.failure(test_name, f"Wrong error code: {error['code']}")
                                return False
                            
                        except Exception as e:
                            self.failure(test_name, f"Invalid JSON response: {e}")
                            return False
                        
                        self.success(test_name)
                        self.log(f"  Rate limit: {response.headers.get('X-RateLimit-Limit')}", Colors.YELLOW)
                        self.log(f"  Retry after: {response.headers.get('Retry-After')}s", Colors.YELLOW)
                        return True
                
                self.failure(test_name, "Could not trigger rate limit")
                return False
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def test_05_rate_limit_recovery(self) -> bool:
        """Test that rate limit recovers after waiting"""
        test_name = "Rate limit recovery (after 60s)"
        try:
            self.log(f"  Waiting 65 seconds for rate limit window to reset...", Colors.YELLOW)
            await asyncio.sleep(65)  # Wait for rate limit window to reset
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Try 5 requests after waiting
                success_count = 0
                for _ in range(5):
                    response = await client.get(f"{self.base_url}/health")
                    if response.status_code == 200:
                        success_count += 1
                    await asyncio.sleep(0.5)
                
                if success_count < 3:  # At least 3 should succeed
                    self.failure(test_name, f"Only {success_count}/5 requests succeeded after reset")
                    return False
                
                self.success(test_name)
                self.log(f"  {success_count}/5 requests succeeded after window reset", Colors.YELLOW)
                return True
                
        except Exception as e:
            self.failure(test_name, str(e))
            return False
    
    async def run_all_tests(self):
        """Run all tests in sequence"""
        self.log("\n" + "="*60, Colors.BLUE)
        self.log("Rate Limiting End-to-End Test", Colors.BLUE)
        self.log(f"Testing against: {self.base_url}", Colors.BLUE)
        self.log("Configuration: 100 req/min with 20 burst", Colors.BLUE)
        self.log("="*60 + "\n", Colors.BLUE)
        
        tests = [
            self.test_01_health_check_exempt,
            self.test_02_burst_allowance,
            self.test_03_rate_limit_triggered,
            self.test_04_rate_limit_response_format,
            # Skip recovery test in CI (takes too long)
            # self.test_05_rate_limit_recovery,
        ]
        
        for test in tests:
            result = await test()
            if not result:
                self.log(f"\nTest failed: {test.__name__}", Colors.RED)
                # Continue with other tests even if one fails
            await asyncio.sleep(1)  # Pause between tests
        
        # Print summary
        self.log("\n" + "="*60, Colors.BLUE)
        self.log("Test Summary", Colors.BLUE)
        self.log("="*60, Colors.BLUE)
        
        passed = sum(1 for _, result in self.test_results if result)
        total = len(self.test_results)
        
        self.log(f"Passed: {passed}/{total}", Colors.GREEN if passed == total else Colors.YELLOW)
        
        if passed == total:
            self.log("\n✓ All tests passed!", Colors.GREEN)
            return 0
        else:
            self.log(f"\n✗ {total - passed} test(s) failed", Colors.RED)
            return 1


async def main():
    """Main entry point"""
    tester = RateLimitTester()
    exit_code = await tester.run_all_tests()
    sys.exit(exit_code)


if __name__ == "__main__":
    asyncio.run(main())
