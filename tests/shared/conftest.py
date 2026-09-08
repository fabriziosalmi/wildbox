"""
Unit tests for open_security_shared. No services required.

The repository-root conftest declares an autouse `ensure_services_ready` fixture
that waits for the docker-compose stack and fails the test if it is absent. That
is right for the integration suite and wrong here: these are pure-function tests
of the gateway auth dependency and the error contract, and their whole value is
that they run without a stack (WILDBO-TEST-03). Overriding the fixture with a
no-op keeps that true.
"""

import pytest


@pytest.fixture(autouse=True)
def ensure_services_ready():
    """No-op override: these tests need no running services."""
    return None
