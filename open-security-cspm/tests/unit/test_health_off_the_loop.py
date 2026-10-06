"""GET /health does not hold the event loop, and answers inside a deadline (#778).

The route asked Redis for a PING and then the workers for a reply, with two
synchronous clients, inside the event loop. The workers are given a second
to reply on every probe, and a Redis that is slow takes as long as it takes:
for that time the process served nothing else, liveness probe included.

Both checks run in a thread now, and the route waits for them until a
deadline shorter than what any probe waits for the answer.

The application is called on the test's own event loop (httpx's ASGI
transport), so a check that blocks the loop blocks the test's other request
with it, as it would in the server.
"""

import asyncio
import logging
import threading
import time
from types import SimpleNamespace

import httpx
import pytest
from app import connections, main
from stalls import needs_checkout, probe_waits

# Longer than any test should take; a check that is never released ends here.
SAFETY = 3.0


class Gate:
    """A check that says it started and then waits to be let through."""

    def __init__(self, answer):
        self.answer = answer
        self.entered = threading.Event()
        self.release = threading.Event()

    def __call__(self):
        self.entered.set()
        self.release.wait(SAFETY)
        return self.answer


async def _entered(gate):
    """Wait, without blocking the loop, for the check to have started."""
    deadline = time.monotonic() + SAFETY
    while not gate.entered.is_set() and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    assert gate.entered.is_set()


def _client():
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app), base_url="http://cspm"
    )


def _workers(world, monkeypatch, active):
    monkeypatch.setattr(
        world.celery.control, "inspect", lambda: SimpleNamespace(active=active)
    )


def _run(scenario):
    return asyncio.run(scenario())


# --- The loop is free while a check waits ------------------------------------------


@pytest.mark.parametrize("waiting_on", ["redis", "the workers"])
def test_another_request_is_served_while_the_probe_waits(
    world, monkeypatch, waiting_on
):
    gate = Gate(True if waiting_on == "redis" else {"celery@worker-1": []})
    if waiting_on == "redis":
        monkeypatch.setattr(main, "redis_client", SimpleNamespace(ping=gate))
    else:
        _workers(world, monkeypatch, gate)

    async def scenario():
        async with _client() as client:
            probe = asyncio.create_task(client.get("/health"))
            await _entered(gate)

            # The probe is inside its check, and the process still answers.
            live = await asyncio.wait_for(client.get("/health/live"), SAFETY)
            served_while_waiting = not probe.done()

            gate.release.set()
            return live, served_while_waiting, await probe

    live, served_while_waiting, health = _run(scenario)

    assert live.status_code == 200
    assert live.json() == {"status": "alive"}
    assert served_while_waiting
    assert health.status_code == 200
    assert health.json()["status"] == "healthy"


def test_two_probes_at_once_do_not_wait_for_each_other(world, monkeypatch):
    """Compose, the gateway's check and a monitor can ask at the same time."""
    started = []
    both = threading.Barrier(2, timeout=SAFETY)

    def ping():
        started.append(time.monotonic())
        both.wait()  # passes only when the two checks are in at once
        return True

    monkeypatch.setattr(main, "redis_client", SimpleNamespace(ping=ping))

    async def scenario():
        async with _client() as client:
            return await asyncio.gather(client.get("/health"), client.get("/health"))

    first, second = _run(scenario)

    assert (first.status_code, second.status_code) == (200, 200)
    assert len(started) == 2


# --- The deadline --------------------------------------------------------------------


@pytest.fixture
def short_deadline(monkeypatch):
    monkeypatch.setattr(main, "HEALTH_DEADLINE_SECONDS", 0.3)
    return 0.3


def _timed_health(release=None):
    async def scenario():
        async with _client() as client:
            started = time.monotonic()
            response = await client.get("/health")
            seconds = time.monotonic() - started
            if release is not None:
                release.set()
            return response, seconds

    return _run(scenario)


def test_a_redis_check_still_waiting_at_the_deadline_is_unhealthy(
    world, monkeypatch, short_deadline, caplog
):
    gate = Gate(True)
    monkeypatch.setattr(main, "redis_client", SimpleNamespace(ping=gate))

    with caplog.at_level(logging.ERROR):
        response, seconds = _timed_health(gate.release)

    assert response.status_code == 503
    assert response.json()["status"] == "unhealthy"
    assert response.json()["checks"] == {
        "redis": "unhealthy",
        "celery": "unknown",
        "api": "healthy",
    }
    assert short_deadline <= seconds < SAFETY / 2
    # The workers are not asked about a Redis that did not answer.
    assert world.celery.control.inspections == 0
    assert "Redis did not answer within 0.3 seconds" in caplog.text


def test_a_worker_check_still_waiting_at_the_deadline_is_degraded(
    world, monkeypatch, short_deadline, caplog
):
    gate = Gate({"celery@worker-1": []})
    _workers(world, monkeypatch, gate)

    with caplog.at_level(logging.ERROR):
        response, seconds = _timed_health(gate.release)

    # Redis answered: the API reads and queues, and says so with 200 (#766).
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"] == {
        "redis": "healthy",
        "celery": "unhealthy",
        "api": "healthy",
    }
    assert short_deadline <= seconds < SAFETY / 2
    assert "the task queue did not answer within 0.3 seconds" in caplog.text


def test_the_deadline_is_for_the_route_not_for_each_check(world, monkeypatch):
    """A Redis that answers late leaves the workers what is left."""
    monkeypatch.setattr(main, "HEALTH_DEADLINE_SECONDS", 1.0)

    def slow_ping():
        time.sleep(0.7)
        return True

    gate = Gate({"celery@worker-1": []})
    monkeypatch.setattr(main, "redis_client", SimpleNamespace(ping=slow_ping))
    _workers(world, monkeypatch, gate)

    response, seconds = _timed_health(gate.release)

    assert response.json()["checks"]["redis"] == "healthy"
    assert response.json()["status"] == "degraded"
    # 1.0 for the two, not 0.7 and then 1.0 more.
    assert 1.0 <= seconds < 1.5


def test_checks_that_answer_are_not_made_to_wait_for_the_deadline(world):
    response, seconds = _timed_health()

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert seconds < main.HEALTH_DEADLINE_SECONDS / 2


@needs_checkout
def test_the_deadline_is_inside_what_every_probe_waits():
    """`make health` gives the answer 5 seconds, the Compose health check
    10. The deadline leaves a second of
    them, and is longer than one Redis reply may take, so that a Redis that
    does not answer is reported by its own check, with its cause logged."""
    shortest = min(probe_waits())

    assert main.HEALTH_DEADLINE_SECONDS <= shortest - 1
    assert connections.REDIS_READ_TIMEOUT_SECONDS < main.HEALTH_DEADLINE_SECONDS
    assert connections.REDIS_CONNECT_TIMEOUT_SECONDS < main.HEALTH_DEADLINE_SECONDS
