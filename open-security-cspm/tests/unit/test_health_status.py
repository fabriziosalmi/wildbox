"""GET /health says with its status what it says in its body (#766).

The probes read the status code and nothing else: ``curl -f`` in the Compose
health check, ``make health`` and ``scripts/wait-for-services.sh`` (2xx or
unhealthy). The route answered 200 with ``"status": "unhealthy"``, so they
read a failed check as healthy; and with Redis down it answered 500 in the
error body, because what the Redis client raises is not the builtin
``ConnectionError`` the route caught.

- ``healthy``, 200: Redis answers and a worker does.
- ``degraded``, 200: Redis answers and no worker does. Scans wait; the API
  reads and queues. The worker has its own health check, and a cspm started
  before its worker must not read unhealthy.
- ``unhealthy``, 503: Redis cannot be reached, or the check itself failed.
"""

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
import redis
import yaml
from app import main, schemas
from celery.exceptions import OperationalError

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
needs_compose = pytest.mark.skipif(
    not COMPOSE_FILE.exists(), reason="needs the repository checkout"
)
MARKER = "cache-7.internal:6379 said no"


def _health(world):
    response = world.client.get("/health")
    # Whatever the status, the body is this route's, never the error body.
    body = schemas.HealthCheckResponse.model_validate(response.json())
    assert set(response.json()) == set(schemas.HealthCheckResponse.model_fields)
    return response, body


def test_redis_and_a_worker_answering_is_healthy(world):
    response, body = _health(world)

    assert response.status_code == 200
    assert body.status == "healthy"
    assert body.checks == {"redis": "healthy", "celery": "healthy", "api": "healthy"}
    assert body.uptime_seconds >= 0


@pytest.mark.parametrize("answer", [None, {}], ids=["no reply", "no worker"])
def test_no_worker_is_degraded_and_still_200(world, answer):
    """A cspm whose worker is not up yet, or is restarting, is not unhealthy:
    Compose would mark the API container for something its own restart
    cannot fix."""
    world.celery.control.workers = answer

    response, body = _health(world)

    assert response.status_code == 200
    assert body.status == "degraded"
    assert body.checks == {"redis": "healthy", "celery": "unhealthy", "api": "healthy"}


def test_a_broker_that_cannot_be_reached_is_degraded_without_its_address(
    world, monkeypatch, caplog
):
    def inspect():
        def active():
            raise OperationalError(MARKER)

        return SimpleNamespace(active=active)

    monkeypatch.setattr(world.celery.control, "inspect", inspect)

    with caplog.at_level(logging.ERROR):
        response, body = _health(world)

    assert response.status_code == 200
    assert body.status == "degraded"
    assert body.checks["celery"] == "unhealthy"
    assert MARKER not in response.text and "OperationalError" not in response.text
    assert MARKER in caplog.text


def test_redis_down_is_unhealthy_and_503(world, monkeypatch, tmp_path, caplog):
    """The real client, on a socket nothing listens on: what it raises is
    redis.exceptions.ConnectionError, which is not the builtin."""
    socket_path = str(tmp_path / "no-redis.sock")
    down = redis.Redis(unix_socket_path=socket_path, decode_responses=True)
    with pytest.raises(redis.exceptions.ConnectionError) as raised:
        down.ping()
    assert not isinstance(raised.value, ConnectionError)
    monkeypatch.setattr(main, "redis_client", down)

    with caplog.at_level(logging.ERROR):
        response, body = _health(world)

    assert response.status_code == 503
    assert body.status == "unhealthy"
    assert body.checks == {"redis": "unhealthy", "celery": "unknown", "api": "healthy"}
    # The workers are asked through the broker, in the stack the same Redis:
    # asking would hold the probe while the broker client retries.
    assert world.celery.control.inspections == 0
    # Where Redis is, is the operator's: in the log, not in the body.
    assert socket_path not in response.text
    assert socket_path in caplog.text


class Ping:
    def __init__(self, outcome):
        self.outcome = outcome

    def ping(self):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.mark.parametrize(
    "outcome",
    [
        redis.exceptions.ConnectionError(MARKER),
        redis.exceptions.TimeoutError(MARKER),
        redis.exceptions.AuthenticationError(MARKER),
        redis.exceptions.BusyLoadingError(MARKER),
        ConnectionError(MARKER),
        TimeoutError(MARKER),
        False,
    ],
    ids=lambda outcome: type(outcome).__module__ + "." + type(outcome).__name__,
)
def test_a_redis_that_does_not_answer_is_unhealthy(world, monkeypatch, outcome):
    monkeypatch.setattr(main, "redis_client", Ping(outcome))

    response, body = _health(world)

    assert response.status_code == 503
    assert body.status == "unhealthy"
    assert body.checks["redis"] == "unhealthy"
    assert MARKER not in response.text


@pytest.mark.parametrize(
    "error",
    [
        # Not connection errors, and not among the five builtins the route
        # used to catch either: these two answered 500 in the error body.
        redis.exceptions.ResponseError(MARKER),
        RuntimeError(MARKER),
        ValueError(MARKER),
    ],
    ids=lambda error: type(error).__name__,
)
def test_a_check_that_fails_for_any_other_reason_is_unhealthy_too(
    world, monkeypatch, caplog, error
):
    monkeypatch.setattr(main, "redis_client", Ping(error))

    with caplog.at_level(logging.ERROR):
        response, body = _health(world)

    assert response.status_code == 503
    assert body.status == "unhealthy"
    assert body.checks == {"api": "unhealthy", "error": "Health check failed"}
    assert MARKER not in response.text
    assert type(error).__name__ not in response.text
    assert MARKER in caplog.text
    assert any(record.exc_info for record in caplog.records)


def test_a_failing_worker_check_does_not_make_the_route_fail(world, monkeypatch):
    def inspect():
        raise RuntimeError(MARKER)

    monkeypatch.setattr(world.celery.control, "inspect", inspect)

    response, body = _health(world)

    assert response.status_code == 503
    assert body.checks == {"api": "unhealthy", "error": "Health check failed"}


def test_liveness_does_not_depend_on_redis(world, monkeypatch):
    monkeypatch.setattr(main, "redis_client", Ping(redis.exceptions.ConnectionError()))

    response = world.client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_the_schema_documents_the_503_with_the_same_body():
    responses = main.app.openapi()["paths"]["/health"]["get"]["responses"]

    assert set(responses) == {"200", "503"}
    assert (
        responses["503"]["content"]["application/json"]["schema"]
        == responses["200"]["content"]["application/json"]["schema"]
    )


# --- What reads the status -------------------------------------------------------


def _compose():
    return yaml.safe_load(COMPOSE_FILE.read_text())["services"]


@needs_compose
def test_the_compose_health_check_reads_the_status_code():
    """``curl -f`` fails on a 503: the container reads unhealthy when the
    route says so, and only then."""
    test = _compose()["cspm"]["healthcheck"]["test"]

    assert test == ["CMD", "curl", "-f", "http://localhost:8019/health"]


@needs_compose
def test_no_service_waits_for_cspm_to_be_healthy():
    """An honest 503 while Redis is away must not keep the rest of the stack
    from starting: the gateway needs cspm's name to resolve, not its health."""
    waiting = []
    for name, service in _compose().items():
        depends_on = service.get("depends_on") or {}
        if isinstance(depends_on, dict):
            condition = (depends_on.get("cspm") or {}).get("condition")
            if condition == "service_healthy":
                waiting.append(name)

    assert waiting == []


@needs_compose
def test_cspm_does_not_wait_for_its_worker():
    """``degraded`` stays 200 for this: the API starts without a worker."""
    depends_on = _compose()["cspm"].get("depends_on") or {}

    assert "cspm-worker" not in depends_on
