"""With Redis or the broker unreachable, a route answers 503, not 500 (#766).

``POST /api/v1/scans`` had a 503 for it, and the other routes a clause that
named ``ConnectionError`` and ``TimeoutError``. None could fire: the Redis
client raises ``redis.exceptions.ConnectionError`` and ``TimeoutError``,
which derive from ``RedisError``, and Celery raises kombu's
``OperationalError``. Not one of them is the builtin the clauses named, so
with Redis down every route answered 500 in the error body.

The application answers them now, in one handler, for every route: these
tests take the routes from the application, as test_route_answers.py does,
so a route added later is held to the same answer.
"""

import logging
from types import SimpleNamespace

import pytest
import redis
from app import main, scan_store
from celery.exceptions import OperationalError
from fastapi.testclient import TestClient
from route_probes import (
    HEADERS,
    SAME_ID_EVERYWHERE,
    SECRET,
    Celery,
    QueuedTasks,
    route_keys,
    route_named,
    scan_request,
    send,
)

MESSAGE = "Scan store or task queue temporarily unavailable"
MARKER = "cache-7.internal:6379 said no"

ROUTES = route_keys()

# The routes that read nothing from Redis, and answer as usual without it.
ANSWER_WITHOUT_REDIS = {
    ("GET", "/metrics"),
    ("GET", "/health/live"),
    ("GET", "/api/v1/providers"),
    ("GET", "/api/v1/checks"),
}
# Its own body, with 503: test_health_status.py.
HEALTH = ("GET", "/health")


def assert_unavailable(response):
    """503 in the canonical error body, and nothing else in it."""
    assert response.status_code == 503, response.text
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert set(error) == {"code", "message", "type", "request_id"}
    assert (error["code"], error["message"], error["type"]) == (
        503,
        MESSAGE,
        "HTTPException",
    )
    assert error["request_id"]


@pytest.fixture
def redis_down(monkeypatch, tmp_path):
    """The API on the real Redis client, pointed at a socket nothing serves."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    socket_path = str(tmp_path / "no-redis.sock")
    monkeypatch.setattr(
        main,
        "redis_client",
        redis.Redis(unix_socket_path=socket_path, decode_responses=True),
    )
    # No broker is reached either way: Redis fails first in every route.
    monkeypatch.setattr(main, "celery_app", Celery())
    monkeypatch.setattr(main, "run_cspm_scan_task", QueuedTasks())
    return SimpleNamespace(
        client=TestClient(main.app, raise_server_exceptions=False),
        socket_path=socket_path,
    )


@pytest.mark.parametrize("method, path", ROUTES, ids=[" ".join(key) for key in ROUTES])
def test_every_route_that_needs_redis_answers_503_without_it(
    redis_down, caplog, method, path
):
    with caplog.at_level(logging.ERROR):
        response = send(redis_down.client, method, path, SAME_ID_EVERYWHERE)

    if (method, path) in ANSWER_WITHOUT_REDIS:
        assert response.status_code == (route_named(method, path).status_code or 200)
        return
    if (method, path) == HEALTH:
        assert response.status_code == 503
        assert response.json()["status"] == "unhealthy"
        return
    assert_unavailable(response)
    # The address of Redis is the operator's: in the log, not in the answer.
    assert redis_down.socket_path not in response.text
    assert redis_down.socket_path in caplog.text


def test_a_refused_caller_is_still_refused_before_redis_is_asked(redis_down):
    """503 says nothing to a caller the gateway did not send."""
    response = redis_down.client.get(
        "/api/v1/dashboard/summary", headers={**HEADERS, "X-Gateway-Secret": "forged"}
    )

    assert response.status_code == 403, response.text


class Raising:
    """A Redis client whose every command raises ``error``."""

    def __init__(self, error):
        self.error = error

    def __getattr__(self, name):
        def command(*args, **kwargs):
            raise self.error

        return command


@pytest.mark.parametrize(
    "error",
    [
        redis.exceptions.ConnectionError(MARKER),
        redis.exceptions.TimeoutError(MARKER),
        # Subclasses of redis.exceptions.ConnectionError: a wrong password,
        # a server still loading its data.
        redis.exceptions.AuthenticationError(MARKER),
        redis.exceptions.BusyLoadingError(MARKER),
        OperationalError(MARKER),
        ConnectionError(MARKER),
        ConnectionRefusedError(MARKER),
        TimeoutError(MARKER),
    ],
    ids=lambda error: f"{type(error).__module__}.{type(error).__name__}",
)
@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", "/api/v1/scans/{scan_id}"),
        ("GET", "/api/v1/scans/{scan_id}/report"),
        ("GET", "/api/v1/scans/{scan_id}/compliance"),
        ("DELETE", "/api/v1/scans/{scan_id}"),
        ("POST", "/api/v1/scans"),
        ("POST", "/api/v1/batch/scans"),
        ("GET", "/api/v1/dashboard/summary"),
        ("GET", "/api/v1/compliance/summary"),
        ("GET", "/api/v1/compliance/findings"),
    ],
)
def test_each_way_of_being_unreachable_is_a_503(
    world, monkeypatch, caplog, method, path, error
):
    monkeypatch.setattr(main, "redis_client", Raising(error))

    with caplog.at_level(logging.ERROR):
        response = send(world.client, method, path, world.scans)

    assert_unavailable(response)
    assert MARKER not in response.text
    assert MARKER in caplog.text


def test_the_handler_covers_every_class_it_names():
    handlers = main.app.exception_handlers

    assert set(main.DEPENDENCY_UNAVAILABLE) == {
        redis.exceptions.ConnectionError,
        redis.exceptions.TimeoutError,
        OperationalError,
        ConnectionError,
        TimeoutError,
    }
    for error_class in main.DEPENDENCY_UNAVAILABLE:
        assert handlers[error_class] is main.dependency_unavailable_handler
    # What the routes used to name is not what Redis and Celery raise.
    for error_class in main.DEPENDENCY_UNAVAILABLE[:3]:
        assert not issubclass(error_class, (ConnectionError, TimeoutError))


@pytest.mark.parametrize(
    "error",
    [redis.exceptions.ResponseError(MARKER), RuntimeError(MARKER)],
    ids=lambda error: type(error).__name__,
)
def test_an_error_that_is_not_unavailability_is_not_called_temporary(
    world, monkeypatch, error
):
    monkeypatch.setattr(main, "redis_client", Raising(error))

    response = world.client.get("/api/v1/dashboard/summary", headers=HEADERS)

    assert response.status_code == 500, response.text
    assert response.json()["error"]["type"] == "InternalServerError"
    assert MARKER not in response.text


# --- The broker down, the store up ----------------------------------------------


def test_a_scan_the_broker_cannot_take_is_a_503(world, monkeypatch):
    def refuse(args, task_id):
        raise OperationalError(MARKER)

    monkeypatch.setattr(world.queue, "apply_async", refuse)

    response = world.client.post(
        "/api/v1/scans", json=scan_request("777777777777"), headers=HEADERS
    )

    assert_unavailable(response)
    assert MARKER not in response.text


def test_a_cancellation_the_broker_cannot_take_is_a_503_and_cancels_nothing(
    world, monkeypatch
):
    def refuse(task_id, terminate=False):
        raise OperationalError(MARKER)

    monkeypatch.setattr(world.celery.control, "revoke", refuse)
    before = world.redis.get(scan_store.metadata_key(world.scans.running))

    response = world.client.delete(
        f"/api/v1/scans/{world.scans.running}", headers=HEADERS
    )

    assert_unavailable(response)
    # Not recorded as cancelled while its task was never revoked.
    assert world.redis.get(scan_store.metadata_key(world.scans.running)) == before
    assert (
        scan_store.load_metadata(world.redis, world.scans.running)["status"]
        == "started"
    )


def test_a_status_the_result_backend_cannot_give_is_a_503_not_a_404(world, monkeypatch):
    """This route answered a connection error with "Scan not found"."""

    class Unreachable:
        info = None

        @property
        def status(self):
            raise redis.exceptions.ConnectionError(MARKER)

    monkeypatch.setattr(world.celery, "AsyncResult", lambda task_id: Unreachable())

    response = world.client.get(f"/api/v1/scans/{world.scans.queued}", headers=HEADERS)

    assert_unavailable(response)

    # A scan with a final status is read from the store alone.
    final = world.client.get(f"/api/v1/scans/{world.scans.completed}", headers=HEADERS)
    assert final.status_code == 200, final.text
    assert final.json()["status"] == "completed"
