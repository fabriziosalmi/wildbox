#!/usr/bin/env python3
"""Quick test for Gateway rate limiting"""
import requests
import time

print("Testing Gateway rate limiting...")
print("Sending 20 rapid requests to http://localhost:80/health")

start = time.time()
responses = []

for i in range(20):
    try:
        r = requests.get("http://localhost:80/health", timeout=2)
        responses.append(r.status_code)
    except Exception as e:
        responses.append(0)

end = time.time()
duration = end - start

print(f"\nResults:")
print(f"  Total time: {duration:.2f}s")
print(f"  Requests/sec: {20/duration:.1f}")
print(f"\nStatus codes:")
for code in sorted(set(responses)):
    count = responses.count(code)
    print(f"  {code}: {count}")

rate_limited = any(code in [429, 503] for code in responses)
print(f"\nRate limiting detected: {rate_limited}")
print(f"Test would {'PASS' if rate_limited or (20/duration < 50) else 'FAIL'}")
