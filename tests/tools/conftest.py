"""
Unit tests for individual tools. No services required.

Like tests/shared, these are pure-function tests: they exercise a tool module
directly rather than through a running service. The repository-root conftest
declares an autouse `ensure_services_ready` fixture that waits for the
docker-compose stack and fails the test if it is absent, which is right for the
integration suite and wrong here -- it made these tests unrunnable without the
whole stack up.
"""

import pytest


@pytest.fixture(autouse=True)
def ensure_services_ready():
    """No-op override: these tests need no running services."""
    return None
