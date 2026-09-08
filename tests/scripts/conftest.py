"""Tests for the repository's own scripts. No services required.

The repository-root conftest declares an autouse `ensure_services_ready`
fixture that waits for the docker-compose stack and fails the test if it is
absent. That is right for the integration suite and wrong here: these tests
read scripts/generate_secrets.py and draw values from it, and their whole value
is that they run anywhere, including on a laptop with nothing started.
Overriding the fixture with a no-op keeps that true -- the same trick
tests/shared/conftest.py uses, for the same reason.
"""

import pytest


@pytest.fixture(autouse=True)
def ensure_services_ready():
    """No-op override: these tests need no running services."""
    return None
