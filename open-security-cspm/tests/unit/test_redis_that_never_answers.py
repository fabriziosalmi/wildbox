"""A Redis that accepts the connection and never answers ends in a 503 (#778).

The clients had no timeout. A server that is down refuses the connection
and the answer is a 503 at once (#766); one that accepts and then says
nothing, which is what a paused container or a stopped host looks like,
held ``/health`` and every route for as long as the caller waited.

The server here is a socket that accepts and never reads or writes. The
clients are the real ones, made the way the service makes them, with the
limits shortened so that the tests take a second: the first tests check that
the limits the service ships with are the ones they shorten.
"""

import socket
import subprocess
import sys
import threading

import pytest
import redis
from app import connections, main
from celery import Celery
from fastapi.testclient import TestClient
from route_probes import SAME_ID_EVERYWHERE, SECRET, route_keys, send
from stalls import SERVICE_ROOT, SOON, Silent, needs_checkout, probe_waits
from stalls import timed as _timed

# The limits of the tests, in seconds.
SHORT = 0.3


@pytest.fixture
def silent():
    server = Silent()
    yield server
    server.close()


@pytest.fixture
def short_limits(monkeypatch):
    monkeypatch.setattr(connections, "REDIS_CONNECT_TIMEOUT_SECONDS", SHORT)
    monkeypatch.setattr(connections, "REDIS_READ_TIMEOUT_SECONDS", SHORT)


# --- The limits the service ships with -------------------------------------------


def test_the_scan_store_client_has_both_limits_by_default():
    kwargs = main.redis_client.connection_pool.connection_kwargs

    assert kwargs["socket_connect_timeout"] == connections.REDIS_CONNECT_TIMEOUT_SECONDS
    assert kwargs["socket_timeout"] == connections.REDIS_READ_TIMEOUT_SECONDS
    assert kwargs["decode_responses"] is True
    assert 0 < connections.REDIS_CONNECT_TIMEOUT_SECONDS
    assert 0 < connections.REDIS_READ_TIMEOUT_SECONDS


def test_the_url_still_decides_when_it_names_a_limit():
    """An operator who set a limit in REDIS_URL keeps it."""
    client = connections.redis_client(
        "redis://cache.internal:6379/3?socket_timeout=7&socket_connect_timeout=9"
    )
    kwargs = client.connection_pool.connection_kwargs

    assert kwargs["socket_timeout"] == 7.0
    assert kwargs["socket_connect_timeout"] == 9.0

    only_one = connections.redis_client("redis://cache.internal/3?socket_timeout=7")
    kwargs = only_one.connection_pool.connection_kwargs
    assert kwargs["socket_timeout"] == 7.0
    assert kwargs["socket_connect_timeout"] == connections.REDIS_CONNECT_TIMEOUT_SECONDS


def test_the_api_process_bounds_its_celery_client_and_keeps_the_worker_settings():
    conf = main.celery_app.conf

    options = conf.broker_transport_options
    assert (
        options["socket_connect_timeout"] == connections.REDIS_CONNECT_TIMEOUT_SECONDS
    )
    assert options["socket_timeout"] == connections.REDIS_READ_TIMEOUT_SECONDS
    # What app.worker set is still there (#601).
    assert options["visibility_timeout"] == main.settings.scan_timeout_seconds + 600
    assert (
        conf.redis_socket_connect_timeout == connections.REDIS_CONNECT_TIMEOUT_SECONDS
    )
    assert conf.redis_socket_timeout == connections.REDIS_READ_TIMEOUT_SECONDS


def test_the_result_backend_url_still_decides_when_it_names_a_limit():
    app = _celery_on(
        "memory://",
        "redis://cache.internal:6379/3?socket_timeout=7&socket_connect_timeout=9",
    )

    assert app.backend.connparams["socket_timeout"] == 7.0
    assert app.backend.connparams["socket_connect_timeout"] == 9.0


def test_the_worker_process_keeps_celerys_own_waits():
    """The worker waits on its broker connection for as long as no task
    comes: the limits are the API's, set where only the API runs."""
    script = (
        "import json; from app import worker; conf = worker.celery_app.conf; "
        "print(json.dumps([sorted(conf.broker_transport_options), "
        "conf.redis_socket_connect_timeout, "
        "dict(conf.result_backend_transport_options or {})]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=SERVICE_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
    assert (
        result.stdout.strip().splitlines()[-1] == '[["visibility_timeout"], null, {}]'
    )


@needs_checkout
def test_a_redis_that_never_answers_is_told_inside_what_every_probe_waits():
    """/health asks Redis first and stops there when it does not answer:
    one connection, or one reply, with a second to spare."""
    assert probe_waits() == (5.0, 10.0)
    shortest = min(probe_waits())

    assert connections.REDIS_READ_TIMEOUT_SECONDS <= shortest - 1
    assert connections.REDIS_CONNECT_TIMEOUT_SECONDS <= shortest - 1


# --- The scan store ------------------------------------------------------------


def test_a_client_without_a_limit_waits_for_as_long_as_it_is_let(silent):
    """What main did: this is the server the other tests bound."""
    unbounded = redis.from_url(silent.url, decode_responses=True)
    done = threading.Event()

    def ping():
        try:
            unbounded.ping()
        except redis.exceptions.RedisError:
            pass
        done.set()

    threading.Thread(target=ping, daemon=True).start()

    assert not done.wait(4 * SHORT)
    silent.close()
    assert done.wait(SOON)


def test_the_scan_store_client_gives_up_after_its_read_timeout(silent, short_limits):
    client = connections.redis_client(silent.url)

    outcome, seconds = _timed(client.ping)

    assert isinstance(outcome, redis.exceptions.TimeoutError), outcome
    assert isinstance(outcome, main.DEPENDENCY_UNAVAILABLE)
    assert SHORT <= seconds < SOON


@pytest.fixture
def api_on_silent_redis(monkeypatch, silent, short_limits):
    """The API with its three clients on the server that never answers."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(main, "redis_client", connections.redis_client(silent.url))
    app = _celery_on(silent.url, silent.url)
    monkeypatch.setattr(main, "celery_app", app)
    monkeypatch.setattr(main, "run_cspm_scan_task", app.tasks["run_cspm_scan"])
    return TestClient(main.app, raise_server_exceptions=False)


ANSWER_WITHOUT_REDIS = {
    ("GET", "/metrics"),
    ("GET", "/health/live"),
    ("GET", "/api/v1/providers"),
    ("GET", "/api/v1/checks"),
}
ROUTES = route_keys()


@pytest.mark.parametrize("method, path", ROUTES, ids=[" ".join(key) for key in ROUTES])
def test_every_route_answers_a_redis_that_never_does(api_on_silent_redis, method, path):
    response, seconds = _timed(
        lambda: send(api_on_silent_redis, method, path, SAME_ID_EVERYWHERE)
    )

    assert not isinstance(response, Exception), repr(response)
    assert seconds < SOON
    if (method, path) in ANSWER_WITHOUT_REDIS:
        assert response.status_code < 300
    elif (method, path) == ("GET", "/health"):
        assert response.status_code == 503
        assert response.json()["status"] == "unhealthy"
        assert response.json()["checks"]["redis"] == "unhealthy"
    else:
        assert response.status_code == 503, response.text
        assert (
            response.json()["error"]["message"] == main.DEPENDENCY_UNAVAILABLE_MESSAGE
        )


# --- The task queue: the broker and the result backend ----------------------------


def _celery_on(broker, backend):
    """A Celery client made as app.worker makes it, bounded as the API bounds it."""
    app = Celery("cspm-test", broker=broker, backend=backend)
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        broker_transport_options={"visibility_timeout": 4200},
    )

    @app.task(name="run_cspm_scan")
    def run_cspm_scan(scan_config):
        return scan_config

    connections.bound_task_queue_waits(app)
    return app


SCAN = "2f0f2c1e-9d9c-4d55-8a57-0d1f4b1f6f01"
# What the API asks of the broker: queue a scan, cancel one, ask the workers.
BROKER_OPERATIONS = {
    "queue a scan": lambda app: app.tasks["run_cspm_scan"].apply_async(
        args=[{}], task_id=SCAN
    ),
    "cancel a scan": lambda app: app.control.revoke(SCAN, terminate=True),
    "ask the workers": lambda app: app.control.inspect().active(),
}
# A result backend that needs no server, for the tests of the broker alone.
NO_BACKEND_SERVER = "cache+memory://"


def closed_port_url():
    """The URL of a port nothing listens on: the connection is refused."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return f"redis://127.0.0.1:{probe.getsockname()[1]}/0"


@pytest.mark.parametrize("operation", list(BROKER_OPERATIONS))
def test_a_broker_that_never_answers_is_given_up_after_one_attempt(
    silent, short_limits, operation
):
    app = _celery_on(silent.url, NO_BACKEND_SERVER)

    outcome, seconds = _timed(lambda: BROKER_OPERATIONS[operation](app))

    # One of the classes the application answers 503 for (#766).
    assert isinstance(outcome, main.DEPENDENCY_UNAVAILABLE), repr(outcome)
    assert SHORT <= seconds < SOON
    # Celery's own settings open it again, twice or three times, with pauses
    # of two and four seconds in between.
    assert len(silent.accepted) == 1


@pytest.mark.parametrize("operation", ["cancel a scan", "ask the workers"])
def test_a_broker_that_refuses_is_not_asked_again_after_a_pause(
    short_limits, operation
):
    """Not the stall, and already a 503 (#766), but after kombu's pause: two
    seconds before it opened the connection again, to cancel a scan and to
    tell /health that no worker answers."""
    app = _celery_on(closed_port_url(), NO_BACKEND_SERVER)

    outcome, seconds = _timed(lambda: BROKER_OPERATIONS[operation](app))

    assert isinstance(outcome, main.DEPENDENCY_UNAVAILABLE), repr(outcome)
    assert seconds < 1.5


def test_a_backend_that_never_answers_does_not_hold_a_scan_being_queued(
    silent, short_limits, tmp_path
):
    """The broker takes the task (a directory, here); the result backend,
    which Celery subscribes to for every task it sends, never answers.
    Celery's own policy reconnects twenty times, a second apart."""
    queue = tmp_path / "queue"
    queue.mkdir()
    app = _celery_on("filesystem://", silent.url)
    app.conf.broker_transport_options = {
        **app.conf.broker_transport_options,
        "data_folder_in": str(queue),
        "data_folder_out": str(queue),
    }

    outcome, seconds = _timed(lambda: BROKER_OPERATIONS["queue a scan"](app))

    assert isinstance(outcome, main.DEPENDENCY_UNAVAILABLE), repr(outcome)
    assert seconds < SOON
    # The subscription, and one reconnection.
    assert len(silent.accepted) == 2


def test_a_backend_that_never_answers_does_not_hold_the_state_of_a_scan(
    silent, short_limits
):
    app = _celery_on("memory://", silent.url)

    outcome, seconds = _timed(lambda: app.AsyncResult(SCAN).status)

    assert isinstance(outcome, main.DEPENDENCY_UNAVAILABLE), repr(outcome)
    assert SHORT <= seconds < SOON
    assert len(silent.accepted) == 1
