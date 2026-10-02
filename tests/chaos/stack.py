"""
Helpers for the chaos experiments: the running stack and the calls they make.

The previous suite addressed containers by a name scheme the compose file does
not use ("wildbox-identity-1"), talked to the gateway on port 80 where
everything but a static /health is a 301 to HTTPS, and ran async fixtures on a
loop pytest-asyncio had already closed (#428). It never measured the system.

Everything here is synchronous and resolves what it touches from the running
stack:

- containers by their compose service label, so a `container_name:` added or
  removed in docker-compose.yml does not break an experiment;
- the gateway over HTTPS, trusting the development CA the same way the
  integration suite does (REQUESTS_CA_BUNDLE);
- the admin account the stack provisions (INITIAL_ADMIN_EMAIL/PASSWORD).

Every fault an experiment injects is undone in a finally block, and every
experiment starts by waiting until the stack is healthy again, so one failed
experiment cannot leave the next one measuring the wreckage.
"""

import os
import time
from typing import Callable, Optional

import docker
import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
DATA_URL = os.getenv("DATA_SERVICE_URL", "http://localhost:8002")

# An authenticated route that is cheap and touches one backend: the gateway
# runs auth_handler.authenticate() on it, then proxies to data's /health.
PROTECTED_PATH = "/api/v1/data/health"


def wait_until(
    check: Callable[[], bool], timeout: float, interval: float = 1.0
) -> Optional[float]:
    """Poll `check` until it returns True. Return the seconds it took, or None."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            if check():
                return time.monotonic() - start
        except requests.RequestException:
            pass
        time.sleep(interval)
    return None


class Stack:
    """The running compose stack, addressed by service name."""

    def __init__(self) -> None:
        self.docker = docker.from_env()

    def container(self, service: str):
        found = self.docker.containers.list(
            all=True, filters={"label": f"com.docker.compose.service={service}"}
        )
        if len(found) != 1:
            names = [c.name for c in found]
            pytest.fail(
                f"expected one container for compose service {service!r}, found {names}"
            )
        return found[0]

    def pause(self, service: str) -> None:
        self.container(service).pause()

    def unpause(self, service: str) -> None:
        c = self.container(service)
        c.reload()
        if c.status == "paused":
            c.unpause()

    def stop(self, service: str) -> None:
        self.container(service).stop(timeout=10)

    def start(self, service: str) -> None:
        c = self.container(service)
        c.reload()
        if c.status != "running":
            c.start()

    def crash(self, service: str) -> int:
        """End the service's main process from inside the container.

        Not `docker kill`/`docker stop`: the daemon records both as a manual
        stop (moby daemon/kill.go sets HasBeenManuallyStopped), and a manually
        stopped container is exactly what `restart: unless-stopped` leaves
        alone -- the experiment would prove nothing about crash recovery. A
        process that exits on its own is what the policy is for. Returns the
        container's restart count before the crash.
        """
        c = self.container(service)
        c.reload()
        before = c.attrs["RestartCount"]
        c.exec_run(["sh", "-c", "kill -TERM 1"], detach=True)
        return before

    def restart_count(self, service: str) -> int:
        c = self.container(service)
        c.reload()
        return c.attrs["RestartCount"]

    def healthy(self, service: str) -> bool:
        c = self.container(service)
        c.reload()
        state = c.attrs["State"]
        if state.get("Status") != "running":
            return False
        health = state.get("Health")
        return health is None or health.get("Status") == "healthy"


def login(timeout: float = 10.0) -> requests.Response:
    return requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={
            "username": os.environ["INITIAL_ADMIN_EMAIL"],
            "password": os.environ["INITIAL_ADMIN_PASSWORD"],
        },
        timeout=timeout,
    )


def fresh_token() -> str:
    """A token the gateway has never seen.

    identity puts a unique jti in every token, and the gateway caches
    authorisation decisions per token, so each call here is a guaranteed
    cache miss -- the request has to reach identity.
    """
    response = login()
    assert (
        response.status_code == 200
    ), f"login failed: {response.status_code} {response.text[:200]}"
    return response.json()["access_token"]


def gateway_get(token: str, timeout: float = 15.0) -> requests.Response:
    return requests.get(
        f"{GATEWAY_URL}{PROTECTED_PATH}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
