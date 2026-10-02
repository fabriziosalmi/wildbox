"""
Fixtures for the chaos experiments. The helpers they use live in stack.py.
"""

import os

import pytest

from .stack import Stack, fresh_token, gateway_get, wait_until

CORE_SERVICES = ("postgres", "wildbox-redis", "identity", "data", "gateway")


@pytest.fixture(scope="session")
def stack() -> Stack:
    for var in ("INITIAL_ADMIN_EMAIL", "INITIAL_ADMIN_PASSWORD"):
        if not os.getenv(var):
            pytest.fail(f"{var} is not set; export it from the stack's .env")
    return Stack()


@pytest.fixture(autouse=True)
def stack_is_healthy(stack: Stack):
    """Start every experiment from a healthy stack, and leave it healthy."""

    def all_up() -> bool:
        return all(stack.healthy(s) for s in CORE_SERVICES)

    def gateway_serves() -> bool:
        return gateway_get(fresh_token(), timeout=10).status_code == 200

    for service in CORE_SERVICES:
        stack.unpause(service)
        stack.start(service)
    assert (
        wait_until(all_up, 180, 2) is not None
    ), "stack not healthy before the experiment"
    # The identity circuit breaker in the gateway stays open for 60 s after the
    # last failure; an experiment that tripped it would otherwise hand the next
    # one a gateway that refuses every new token.
    assert (
        wait_until(gateway_serves, 120, 3) is not None
    ), "gateway not serving before the experiment"
    yield
    for service in CORE_SERVICES:
        stack.unpause(service)
        stack.start(service)
