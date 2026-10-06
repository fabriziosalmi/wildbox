"""A PostgreSQL server in a throwaway container, for the errors only it writes.

What PostgreSQL says about a row it refuses (``DETAIL: Key (email)=(...)
already exists``) is written by the server and passed on by the driver: a
hand-made exception would test the test. The tests that need the real text
start a server here.

Needs Docker. Where there is none the tests are skipped; CI sets
WILDBOX_REQUIRE_DOCKER_TESTS=1 so that they run there.
"""

import os
import secrets
import shutil
import subprocess
import time
import uuid

import pytest

POSTGRES_IMAGE = "postgres:15"  # the version docker-compose.yml runs
READY_SECONDS = 120


def _docker_available():
    if not shutil.which("docker"):
        return False
    return (
        subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode
        == 0
    )


def _docker(*arguments, **options):
    return subprocess.run(
        ["docker", *arguments], capture_output=True, text=True, timeout=300, **options
    )


class Server:
    """One container; ``url`` is ``postgresql://`` for the database ``test``."""

    def __init__(self):
        self.container = f"wbtest778-pg-{uuid.uuid4().hex[:8]}"
        # Given to docker through the environment, not on its command line.
        password = secrets.token_hex(16)
        started = _docker(
            *["run", "-d", "--rm", "--name", self.container],
            *["-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_DB=test"],
            *["-p", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql/data"],
            POSTGRES_IMAGE,
            env={**os.environ, "POSTGRES_PASSWORD": password},
        )
        if started.returncode != 0:
            pytest.fail(f"PostgreSQL did not start: {started.stderr.strip()}")
        try:
            address = _docker("port", self.container, "5432/tcp").stdout.split()[0]
            self.url = f"postgresql://postgres:{password}@{address}/test"
            self._wait()
        except BaseException:
            self.stop()
            raise

    def _wait(self):
        # The image starts the server twice: once to initialise the database,
        # on a socket only, then for good. Asking over TCP waits for that one.
        deadline = time.monotonic() + READY_SECONDS
        query = ["exec", self.container, "psql", "-h", "127.0.0.1", "-U", "postgres"]
        while _docker(*query, "-d", "test", "-c", "SELECT 1").returncode != 0:
            if time.monotonic() > deadline:
                pytest.fail(f"PostgreSQL was not ready within {READY_SECONDS} s")
            time.sleep(0.5)

    def stop(self):
        _docker("rm", "-f", self.container)


def start_or_skip():
    """A started ``Server``; skips, or fails where Docker is required."""
    if not _docker_available():
        if os.environ.get("WILDBOX_REQUIRE_DOCKER_TESTS") == "1":
            pytest.fail("docker is required for these tests and is not available")
        pytest.skip("docker is not available")
    return Server()
