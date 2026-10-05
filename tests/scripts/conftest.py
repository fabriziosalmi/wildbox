"""
Unit tests for the scripts/ helpers. No services required.

The repository-root conftest declares an autouse `ensure_services_ready` fixture
that waits for the docker-compose stack and fails the test if it is absent. That
is right for the integration suite and wrong here: these exercise a script over
fixture files on disk, and their whole value is that they run without a stack.
Overriding the fixture with a no-op keeps that true, the same way tests/shared
already does.

Some of these tests do start containers of their own: a throwaway PostgreSQL
or Redis under the test's own Compose project name, never the stack. They ask
for the `docker` fixture below, which skips them on a machine without Docker.
In CI that would be a hole: a runner that lost Docker, or a test that grew a
skip of its own, would leave the backup, restore and rotation scripts
untested behind a green job (#723). So with WILDBOX_REQUIRE_DOCKER_TESTS=1,
which .github/workflows/test.yml sets for this directory, a skipped test is a
failed test, whatever skipped it.
"""

import os
import shutil
import subprocess

import pytest

REQUIRE_DOCKER_TESTS = "WILDBOX_REQUIRE_DOCKER_TESTS"


@pytest.fixture(autouse=True)
def ensure_services_ready():
    """No-op override: these tests need no running services."""
    return None


def docker_available():
    """True when the docker CLI, the Compose plugin and a daemon all answer."""
    if not shutil.which("docker"):
        return False
    for probe in (["docker", "compose", "version"], ["docker", "info"]):
        try:
            answered = subprocess.run(probe, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return False
        if answered.returncode != 0:
            return False
    return True


@pytest.fixture(scope="session")
def docker():
    """For a test that starts containers: skip it where Docker is missing.

    Where every test must run, the skip is turned into a failure by the hook
    below, and this says why before that.
    """
    if not docker_available():
        if os.environ.get(REQUIRE_DOCKER_TESTS) == "1":
            pytest.fail("docker is required for these tests and is not available")
        pytest.skip("docker is not available")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """With WILDBOX_REQUIRE_DOCKER_TESTS=1, no test here may be skipped."""
    outcome = yield
    report = outcome.get_result()
    if (
        report.skipped
        and os.environ.get(REQUIRE_DOCKER_TESTS) == "1"
        and not hasattr(report, "wasxfail")
    ):
        reason = report.longrepr
        if isinstance(reason, tuple):
            reason = reason[-1]
        report.outcome = "failed"
        report.longrepr = (
            f"{item.nodeid} was skipped, and {REQUIRE_DOCKER_TESTS}=1 means "
            f"every test in tests/scripts must run. {reason}"
        )
