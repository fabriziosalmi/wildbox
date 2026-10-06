"""A route that waits for Redis does not hold the event loop (#788).

Every route was ``async def`` and called the synchronous Redis and Celery
clients in its body, so in the event loop: while one request waited for
Redis, the process served nothing else, ``/health/live`` included. #778 gave
the clients limits, which turned "for ever" into three seconds per request;
the requests still went through one at a time.

FastAPI runs a route that is a plain ``def`` in a thread of its pool. The
routes whose bodies are synchronous are plain functions now, and a request
that waits holds a thread and nothing else.

The application is called on the test's own event loop (httpx's ASGI
transport), as in test_health_off_the_loop.py: a route that blocks the loop
blocks the test's other request with it, as it would in the server. Redis is
the server of test_redis_that_never_answers.py, which accepts and never
answers; the clients are the real ones.
"""

import asyncio
import inspect
import time

import anyio.to_thread
import httpx
import pytest
from app import connections, main
from celery import Celery
from route_probes import (
    HEADERS,
    REQUESTS,
    SAME_ID_EVERYWHERE,
    SECRET,
    route_keys,
    route_named,
)
from stalls import SOON, Silent

# Seconds the clients wait for the server that never answers, here: long
# enough to tell "served meanwhile" from "served afterwards" at a glance.
LIMIT = 1.0

# The routes that stay coroutines, and why each may.
STAY_COROUTINES = {
    # Asks nothing of anybody. It answers from the event loop, so also when
    # every thread of the pool is waiting for Redis: that is what a liveness
    # probe is for.
    ("GET", "/health/live"),
    # Runs its two checks in threads itself and waits for them until its own
    # deadline (#778): a plain function could not give the answer up in time.
    ("GET", "/health"),
    # Read what the process holds in memory: the providers and the checks it
    # loaded. Nothing to wait for, and no thread of the pool to wait for
    # either.
    ("GET", "/api/v1/providers"),
    ("GET", "/api/v1/checks"),
}
# The shared package's route, a plain function that reads the process's own
# counters: it asks nothing of Redis either.
METRICS = ("GET", "/metrics")
ROUTES = route_keys()
WAIT_FOR_REDIS = [
    key for key in ROUTES if key not in STAY_COROUTINES and key != METRICS
]


@pytest.fixture
def silent():
    server = Silent()
    yield server
    server.close()


@pytest.fixture
def api_on_silent_redis(request, monkeypatch, silent):
    """The application with its three clients on the server that never
    answers, each given LIMIT seconds (or the seconds a test asks for)."""
    limit = getattr(request, "param", LIMIT)
    monkeypatch.setattr(connections, "REDIS_CONNECT_TIMEOUT_SECONDS", limit)
    monkeypatch.setattr(connections, "REDIS_READ_TIMEOUT_SECONDS", limit)
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(main, "redis_client", connections.redis_client(silent.url))
    app = Celery("cspm-test", broker=silent.url, backend=silent.url)
    app.conf.update(task_serializer="json", accept_content=["json"])

    @app.task(name="run_cspm_scan")
    def run_cspm_scan(scan_config):
        return scan_config

    connections.bound_task_queue_waits(app)
    monkeypatch.setattr(main, "celery_app", app)
    monkeypatch.setattr(main, "run_cspm_scan_task", app.tasks["run_cspm_scan"])
    return silent


def _client():
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app), base_url="http://cspm"
    )


def _send(client, method, path):
    arguments = dict(REQUESTS[(method, path)](SAME_ID_EVERYWHERE))
    url = path.format(**arguments.pop("path", {}))
    return client.request(method, url, headers=HEADERS, **arguments)


async def _until(condition):
    deadline = time.monotonic() + SOON
    while not condition() and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert condition()


def test_the_routes_that_wait_for_redis_are_the_ones_this_file_walks():
    """Every route but four is a plain function. A route added as a
    coroutine fails here until it is in STAY_COROUTINES, with its reason."""
    coroutines = {
        key for key in ROUTES if inspect.iscoroutinefunction(route_named(*key).endpoint)
    }

    assert coroutines == STAY_COROUTINES
    assert len(WAIT_FOR_REDIS) == 9


@pytest.mark.parametrize(
    "method, path", WAIT_FOR_REDIS, ids=[" ".join(key) for key in WAIT_FOR_REDIS]
)
def test_another_request_is_served_while_a_route_waits_for_redis(
    api_on_silent_redis, method, path
):
    silent = api_on_silent_redis

    async def scenario():
        async with _client() as client:
            waiting = asyncio.create_task(_send(client, method, path))
            # The route has asked Redis, which will not answer.
            await _until(lambda: silent.accepted)

            asked = time.monotonic()
            live = await asyncio.wait_for(client.get("/health/live"), SOON)
            live_took = time.monotonic() - asked
            served_while_waiting = not waiting.done()

            answer = await asyncio.wait_for(waiting, 2 * SOON)
            return live, live_took, served_while_waiting, answer

    live, live_took, served_while_waiting, answer = asyncio.run(scenario())

    assert live.status_code == 200 and live.json() == {"status": "alive"}
    # main: False. The loop was in the Redis client until its limit ended,
    # and the test's own request for /health/live could not even be sent
    # before that.
    assert served_while_waiting
    assert live_took < LIMIT / 2
    # And the route itself still ends as it did (#778).
    assert answer.status_code == 503, answer.text
    assert answer.json()["error"]["message"] == main.DEPENDENCY_UNAVAILABLE_MESSAGE


def test_requests_that_wait_for_redis_wait_side_by_side(api_on_silent_redis):
    """Ten requests took ten limits, one after the other. They take one."""
    silent = api_on_silent_redis
    route = ("GET", "/api/v1/dashboard/summary")

    async def scenario():
        async with _client() as client:
            started = time.monotonic()
            answers = await asyncio.gather(*(_send(client, *route) for _ in range(10)))
            return answers, time.monotonic() - started

    answers, seconds = asyncio.run(scenario())

    assert [answer.status_code for answer in answers] == [503] * 10
    assert len(silent.accepted) == 10
    # main: 10 * LIMIT.
    assert LIMIT <= seconds < 3 * LIMIT


# Seconds the clients wait in the test below: long enough for a slow machine
# to start every thread of the pool before the first of them gives up.
POOL_LIMIT = 3.0


@pytest.mark.parametrize("api_on_silent_redis", [POOL_LIMIT], indirect=True)
def test_liveness_answers_when_every_thread_of_the_pool_waits_for_redis(
    api_on_silent_redis,
):
    """Why the liveness route stays a coroutine: as a plain function it
    would wait for a thread, behind the requests that hold them all."""
    silent = api_on_silent_redis
    route = ("GET", "/api/v1/compliance/summary")

    async def scenario():
        threads = int(anyio.to_thread.current_default_thread_limiter().total_tokens)
        async with _client() as client:
            waiting = [
                asyncio.create_task(_send(client, *route)) for _ in range(threads + 5)
            ]
            # Every thread of the pool is in the Redis client.
            await _until(lambda: len(silent.accepted) >= threads)

            asked = time.monotonic()
            live = await asyncio.wait_for(client.get("/health/live"), SOON)
            live_took = time.monotonic() - asked
            none_done = not any(task.done() for task in waiting)

            answers = await asyncio.wait_for(asyncio.gather(*waiting), 4 * SOON)
            return live, live_took, none_done, answers

    live, live_took, none_done, answers = asyncio.run(scenario())

    assert live.status_code == 200
    assert none_done and live_took < POOL_LIMIT / 2
    assert {answer.status_code for answer in answers} == {503}
