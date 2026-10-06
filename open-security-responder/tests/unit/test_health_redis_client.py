"""/health asks Redis with one client, which has timeouts and is closed (#788).

The route made a new Redis client, with a connection pool of its own, every
time it was asked: a connection to Redis opened and dropped at every probe,
for as long as the service ran. The client had no timeout, and the PING was
sent from the event loop: a Redis that accepts the connection and never
answers held the probe and everything else the process serves.

Redis is played here by a socket server: one that answers as Redis does, and
counts the connections it is given, and one that accepts and never answers.
The client is the real one. The answer of the route is as it was.
"""

import asyncio
import os
import socket
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "s" * 40)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.main as main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# Seconds, for the limits the tests shorten and for what must not take long.
SHORT = 0.3
SOON = 5.0


class Server:
    """A TCP server that counts its connections. ``answers``: it replies as
    Redis does (PONG to a PING, OK to anything else); otherwise it accepts
    and never says a word."""

    def __init__(self, answers):
        self.answers = answers
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.url = f"redis://127.0.0.1:{self.listener.getsockname()[1]}/0"
        self.connections = []
        self.closed_by_client = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            self.connections.append(connection)
            if self.answers:
                threading.Thread(
                    target=self._serve, args=(connection,), daemon=True
                ).start()

    def _serve(self, connection):
        buffered = b""
        while True:
            try:
                received = connection.recv(4096)
            except OSError:
                return
            if not received:
                self.closed_by_client += 1
                return
            buffered += received
            # One reply for each command: a command is an array, "*<n>".
            while True:
                command, buffered = _command(buffered)
                if command is None:
                    break
                reply = b"+PONG\r\n" if command[0].upper() == b"PING" else b"+OK\r\n"
                connection.sendall(reply)

    def close(self):
        self.listener.close()
        for connection in self.connections:
            connection.close()


def _command(buffered):
    """(the first complete command of ``buffered``, the rest), or (None,
    ``buffered``) when it holds none yet."""
    if not buffered.startswith(b"*") or b"\r\n" not in buffered:
        return None, buffered
    header, rest = buffered.split(b"\r\n", 1)
    words = []
    for _ in range(int(header[1:])):
        if b"\r\n" not in rest:
            return None, buffered
        length, rest = rest.split(b"\r\n", 1)
        size = int(length[1:])
        if len(rest) < size + 2:
            return None, buffered
        words.append(rest[:size])
        # The word, and the line end after it.
        taken = size + 2
        rest = rest[taken:]
    return words, rest


@pytest.fixture
def redis_server(request, monkeypatch):
    server = Server(answers=getattr(request, "param", True))
    monkeypatch.setattr(main.settings, "redis_url", server.url)
    monkeypatch.setattr(main, "_health_redis", None)
    yield server
    main._close_health_redis()
    server.close()


def _probe(client):
    response = client.get("/health")
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"status", "timestamp"}
    return body["status"]


def test_every_probe_asks_redis_over_the_same_connection(redis_server):
    client = TestClient(main.app)

    statuses = [_probe(client) for _ in range(5)]

    assert statuses == ["healthy"] * 5
    # main: five clients, five pools, five connections.
    assert len(redis_server.connections) == 1
    assert redis_server.closed_by_client == 0


def test_the_client_is_made_once_with_both_timeouts(redis_server):
    client = TestClient(main.app)
    _probe(client)
    first = main._health_redis
    _probe(client)

    assert main._health_redis is first
    settings = first.connection_pool.connection_kwargs
    # main: neither key was there.
    assert settings["socket_connect_timeout"] == main.HEALTH_REDIS_TIMEOUT_SECONDS
    assert settings["socket_timeout"] == main.HEALTH_REDIS_TIMEOUT_SECONDS
    assert 0 < main.HEALTH_REDIS_TIMEOUT_SECONDS < 5


def test_the_client_is_closed_when_the_service_stops(redis_server):
    client = TestClient(main.app)
    _probe(client)
    assert redis_server.closed_by_client == 0
    # Held here, so that it is the close that ends its connection and not
    # the collection of a client nobody refers to any more.
    held = main._health_redis

    main._close_health_redis()

    deadline = time.monotonic() + SOON
    while redis_server.closed_by_client == 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert redis_server.closed_by_client == 1
    assert main._health_redis is None and held is not None
    # Closing what is closed, or was never made, is not an error.
    main._close_health_redis()


def test_the_shutdown_of_the_application_closes_it(redis_server, monkeypatch):
    closed = []
    monkeypatch.setattr(main, "_close_health_redis", lambda: closed.append(True))
    # What the start does besides: not under test, and not without Redis.
    monkeypatch.setattr(main.playbook_parser, "load_playbooks", lambda: {})
    monkeypatch.setattr(main.workflow_engine, "reap_abandoned_runs", lambda: 0)

    with TestClient(main.app) as client:
        _probe(client)
        assert closed == []

    assert closed == [True]


@pytest.mark.parametrize("redis_server", [False], indirect=True)
def test_a_redis_that_never_answers_is_unhealthy_within_the_limit(
    redis_server, monkeypatch
):
    monkeypatch.setattr(main, "HEALTH_REDIS_TIMEOUT_SECONDS", SHORT)
    outcome = {}

    def probe():
        started = time.monotonic()
        outcome["status"] = _probe(TestClient(main.app))
        outcome["seconds"] = time.monotonic() - started

    thread = threading.Thread(target=probe, daemon=True)
    thread.start()
    thread.join(2 * SOON)

    # main: no answer, for as long as the server kept the connection.
    assert not thread.is_alive(), "the probe is still waiting for Redis"
    assert outcome["status"] == "unhealthy"
    assert SHORT <= outcome["seconds"] < SOON


def test_a_redis_that_is_down_is_unhealthy_as_before(monkeypatch):
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        url = f"redis://127.0.0.1:{unused.getsockname()[1]}/0"
    monkeypatch.setattr(main.settings, "redis_url", url)
    monkeypatch.setattr(main, "_health_redis", None)

    try:
        assert _probe(TestClient(main.app)) == "unhealthy"
    finally:
        main._close_health_redis()


@pytest.mark.parametrize("redis_server", [False], indirect=True)
def test_another_request_is_served_while_the_probe_waits_for_redis(
    redis_server, monkeypatch
):
    """The PING is sent from a thread: the event loop is free meanwhile."""
    monkeypatch.setattr(main, "HEALTH_REDIS_TIMEOUT_SECONDS", 1.0)

    async def scenario():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://r") as c:
            probe = asyncio.create_task(c.get("/health"))
            while not redis_server.connections:
                await asyncio.sleep(0.005)
            asked = time.monotonic()
            other = await asyncio.wait_for(c.get("/"), SOON)
            other_took = time.monotonic() - asked
            waiting = not probe.done()
            return other, other_took, waiting, await probe

    other, other_took, waiting, health = asyncio.run(scenario())

    # main: the route held the loop until Redis answered, which is never.
    assert other.status_code == 200
    assert waiting and other_took < 0.5
    assert health.json()["status"] == "unhealthy"
