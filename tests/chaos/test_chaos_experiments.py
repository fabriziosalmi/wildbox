"""
Chaos experiments: inject one fault into the running stack, measure what the
system does, undo the fault, measure that it recovers.

Each experiment asserts a behaviour the code actually implements, with the
numbers taken from the code:

- the gateway caches an authorisation decision for AUTH_CACHE_TTL (300 s) and
  calls identity with a 5 s timeout; after 10 failed calls its circuit breaker
  refuses new tokens with a 503 for 60 s
  (open-security-gateway/nginx/lua/auth_handler.lua);
- every service runs with `restart: unless-stopped` (docker-compose.yml);
- identity's token blacklist fails open when Redis is unreachable
  (open-security-identity/app/token_blacklist.py).

Run against a stack started the way the integration job starts it; see
.github/workflows/chaos-and-load.yml.
"""

import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from .stack import (
    DATA_URL,
    IDENTITY_URL,
    fresh_token,
    gateway_get,
    login,
    wait_until,
)

pytestmark = pytest.mark.chaos

# auth_handler.lua
IDENTITY_TIMEOUT_S = 5
BREAKER_THRESHOLD = 10
BREAKER_OPEN_S = 60


def timed(fn, *args, **kwargs):
    start = time.monotonic()
    result = fn(*args, **kwargs)
    return result, time.monotonic() - start


def test_cached_authorisation_survives_an_identity_outage(stack):
    """A token the gateway has already authorised keeps working while identity
    is unreachable, for as long as the decision is cached."""
    token = fresh_token()
    assert gateway_get(token).status_code == 200  # warms the cache

    stack.pause("identity")
    try:
        response, elapsed = timed(gateway_get, token)
        assert (
            response.status_code == 200
        ), f"cached token refused during identity outage: {response.status_code}"
        assert (
            elapsed < 2
        ), f"cached path took {elapsed:.1f}s; it should not call identity"
    finally:
        stack.unpause("identity")


def test_new_tokens_fail_closed_then_fast_while_identity_is_down(stack):
    """With identity unreachable, a token the gateway has not seen is refused
    with 503 -- never let through, never left hanging -- and once the breaker
    opens the refusal is immediate. When identity returns, new tokens work
    again within the breaker's open window."""
    attempts = BREAKER_THRESHOLD + 3
    tokens = [fresh_token() for _ in range(attempts)]

    stack.pause("identity")
    results = []
    try:
        for token in tokens:
            response, elapsed = timed(
                gateway_get, token, timeout=IDENTITY_TIMEOUT_S * 4
            )
            results.append((response.status_code, round(elapsed, 2)))
    finally:
        stack.unpause("identity")

    print(f"\n[chaos] identity paused, new tokens: {results}")
    statuses = [s for s, _ in results]
    assert all(
        s == 503 for s in statuses
    ), f"expected 503 for every new token, got {statuses}"
    assert all(
        t < IDENTITY_TIMEOUT_S + 2 for _, t in results
    ), f"a request outlived the {IDENTITY_TIMEOUT_S}s identity timeout: {results}"
    after_breaker = [t for _, t in results[BREAKER_THRESHOLD:]]
    assert all(
        t < 1 for t in after_breaker
    ), f"breaker should answer immediately after {BREAKER_THRESHOLD} failures: {results}"

    recovered = wait_until(
        lambda: gateway_get(fresh_token(), timeout=10).status_code == 200,
        BREAKER_OPEN_S + 30,
        2,
    )
    print(f"[chaos] new tokens accepted again {recovered}s after identity returned")
    assert recovered is not None, "new tokens still refused after the breaker window"


def test_identity_reports_and_survives_a_database_outage(stack):
    """With PostgreSQL down, identity says so in its health report and refuses
    logins quickly; when PostgreSQL returns, identity recovers on its own,
    without being restarted."""
    restarts_before = stack.restart_count("identity")
    stack.stop("postgres")
    try:
        unhealthy = wait_until(
            lambda: requests.get(f"{IDENTITY_URL}/health", timeout=10)
            .json()
            .get("status")
            != "healthy",
            30,
        )
        assert (
            unhealthy is not None
        ), "identity /health still reports healthy with the database down"

        response, elapsed = timed(login, timeout=30)
        print(
            f"\n[chaos] login with database down: {response.status_code} in {elapsed:.1f}s"
        )
        assert response.status_code != 200, "login succeeded with the database down"
        assert (
            response.status_code >= 500
        ), f"database outage reported as {response.status_code}"
        assert elapsed < 15, f"login took {elapsed:.1f}s to fail"
    finally:
        stack.start("postgres")

    recovered = wait_until(lambda: login(timeout=10).status_code == 200, 120, 2)
    print(f"[chaos] login works again {recovered}s after the database returned")
    assert recovered is not None, "identity did not recover after the database returned"
    assert (
        stack.restart_count("identity") == restarts_before
    ), "identity had to be restarted to recover from a database outage"


def test_redis_outage_does_not_block_authentication(stack):
    """Redis backs identity's token blacklist and login-attempt counter, both of
    which fail open. Logging in and calling the API must keep working."""
    stack.stop("wildbox-redis")
    try:
        response, elapsed = timed(login, timeout=30)
        print(
            f"\n[chaos] login with redis down: {response.status_code} in {elapsed:.1f}s"
        )
        assert (
            response.status_code == 200
        ), f"login failed with redis down: {response.status_code}"
        assert elapsed < 10, f"login took {elapsed:.1f}s with redis down"

        token = response.json()["access_token"]
        api, api_elapsed = timed(gateway_get, token)
        assert api.status_code == 200, f"API refused with redis down: {api.status_code}"
        assert api_elapsed < 10
    finally:
        stack.start("wildbox-redis")


@pytest.mark.parametrize("service", ["identity", "data"])
def test_a_crashed_service_is_restarted_and_serves_again(stack, service):
    """When a service's main process dies, `restart: unless-stopped` brings the
    container back, it becomes healthy, and the gateway routes to it again."""
    before = stack.crash(service)

    restarted = wait_until(lambda: stack.restart_count(service) > before, 60, 1)
    assert (
        restarted is not None
    ), f"{service} was not restarted after its process exited"

    healthy = wait_until(lambda: stack.healthy(service), 180, 2)
    assert healthy is not None, f"{service} restarted but never became healthy"

    # nginx marks an upstream failed for fail_timeout=30s after max_fails=3.
    served = wait_until(
        lambda: gateway_get(fresh_token(), timeout=10).status_code == 200, 90, 2
    )
    print(
        f"\n[chaos] {service}: restarted in {restarted:.0f}s, healthy +{healthy:.0f}s, "
        f"served through the gateway +{served}s"
    )
    assert (
        served is not None
    ), f"gateway did not route to {service} again after its restart"


def test_concurrent_burst_through_the_gateway(stack):
    """200 authenticated requests from 50 threads: every one gets an answer,
    no answer is a server error, and the backend is still healthy afterwards.
    429 is an acceptable answer -- the per-IP limit_req zones exist for this."""
    token = fresh_token()
    assert gateway_get(token).status_code == 200

    def one(_):
        try:
            response, elapsed = timed(gateway_get, token, timeout=30)
            return response.status_code, elapsed
        except requests.RequestException as exc:
            return type(exc).__name__, None

    with ThreadPoolExecutor(max_workers=50) as pool:
        results = list(pool.map(one, range(200)))

    statuses = {}
    for status, _ in results:
        statuses[status] = statuses.get(status, 0) + 1
    latencies = sorted(t for _, t in results if t is not None)
    p95 = latencies[int(len(latencies) * 0.95) - 1] if latencies else None
    print(
        f"\n[chaos] burst statuses {statuses}, median {statistics.median(latencies):.2f}s, "
        f"p95 {p95:.2f}s"
    )

    assert set(statuses) <= {200, 429}, f"unexpected answers under load: {statuses}"
    assert statuses.get(200, 0) > 0, "no request succeeded"
    assert requests.get(f"{DATA_URL}/health", timeout=10).status_code == 200
