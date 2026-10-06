"""What the tests of a dependency that does not answer share (#778).

A server that accepts and never answers, a way to time a call without
hanging the suite on it, and the seconds each probe gives ``/health``.
"""

import re
import socket
import threading
import time
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
HEALTH_LIBRARY = REPO_ROOT / "scripts" / "lib" / "health_endpoints.sh"
WAIT_SCRIPT = REPO_ROOT / "scripts" / "wait-for-services.sh"
needs_checkout = pytest.mark.skipif(
    not COMPOSE_FILE.exists(), reason="needs the repository checkout"
)

# How long anything may take in these tests, in seconds: a few attempts of a
# client whose limits the test shortened, far from the "for ever" of a client
# without one.
SOON = 5.0


class Silent:
    """A server that accepts every connection and never answers.

    What a paused container, or a host that stopped, looks like to a client:
    the connection opens, and nothing comes back.
    """

    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.port = self.listener.getsockname()[1]
        self.url = f"redis://127.0.0.1:{self.port}/0"
        self.accepted = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            self.accepted.append(connection)

    def close(self):
        self.listener.close()
        for connection in self.accepted:
            connection.close()


class NoAnswer(Exception):
    """The call was still waiting when the test stopped waiting for it."""


def timed(call):
    """(what ``call`` raised or returned, the seconds it took).

    In a thread the test does not wait on for ever: a client that has lost
    its limit fails the test, it does not hang the suite.
    """
    result = {}

    def run():
        started = time.monotonic()
        try:
            result["outcome"] = call()
        except Exception as error:  # noqa: BLE001 - the tests look at the class
            result["outcome"] = error
        result["seconds"] = time.monotonic() - started

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(2 * SOON)
    if thread.is_alive():
        return NoAnswer(), 2 * SOON
    return result["outcome"], result["seconds"]


def probe_waits():
    """Seconds a probe gives /health, read from the files that say so:
    (`make health`, the Compose health check, scripts/wait-for-services.sh).

    The last one uses the probe of the first, with a wait of its own when
    it sets one: it set 3 seconds, under the deadline of /health (#788).
    """
    waits = re.search(r"\$\{HEALTH_TIMEOUT:-(\d+)\}", HEALTH_LIBRARY.read_text())
    healthcheck = yaml.safe_load(COMPOSE_FILE.read_text())["services"]["cspm"][
        "healthcheck"
    ]
    script = WAIT_SCRIPT.read_text()
    assert "wb_http_status" in script, "the script no longer uses the shared probe"
    own = re.search(r"HEALTH_TIMEOUT=(\d+)", script)
    return (
        float(waits.group(1)),
        float(healthcheck["timeout"].rstrip("s")),
        float((own or waits).group(1)),
    )
