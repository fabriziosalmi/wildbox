"""The hourly operation limit is one count per caller, in Redis (#721).

``AuthorizationManager.check_rate_limit`` counted in a dict of the process
that asked. The API process and every child of the Celery prefork worker
counted on their own, and a restart forgot every run, so "one destructive
test per caller per hour" was one per process per restart.

These tests run against a Redis server (the ``redis_url`` fixture), from
several connections and from several processes, because that is the claim:
a second process, started after the first took the allowance, is refused.
"""

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
import redis

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.security import rate_limit  # noqa: E402
from app.security.authorization import (  # noqa: E402
    DEFAULT_HOURLY_LIMIT,
    HOURLY_LIMITS,
    OperationType,
    authorization_manager,
)
from app.security.rate_limit import (  # noqa: E402
    OperationRateLimiter,
    RateLimitUnavailable,
)

SERVICE_ROOT = Path(__file__).resolve().parents[2]
TOOL = "sql_injection_scanner"
PUBLIC_IP = "93.184.215.14"
TARGET = f"http://{PUBLIC_IP}/page?id=1"


def caller() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def prefix(redis_client):
    """A key prefix of this test's own, emptied afterwards."""
    name = f"wildbox:tools:test-operation-limit:{uuid.uuid4().hex}"
    yield name
    keys = list(redis_client.scan_iter(match=f"{name}:*"))
    if keys:
        redis_client.delete(*keys)


def connect(redis_url):
    """A client with a connection pool of its own, as another process has."""
    return redis.Redis.from_url(redis_url, decode_responses=True)


@pytest.fixture
def limiter(redis_url, prefix):
    client = connect(redis_url)
    yield OperationRateLimiter(client, key_prefix=prefix)
    client.close()


@pytest.fixture
def service_limiter(redis_url, prefix, monkeypatch):
    """Point the service's own limiter at the test Redis, under ``prefix``."""
    client = connect(redis_url)
    monkeypatch.setattr(
        rate_limit, "_limiter", OperationRateLimiter(client, key_prefix=prefix)
    )
    yield
    client.close()


def python(code, *args, redis_url, cwd, **env):
    """Run ``code`` in a new interpreter, as another process of the service."""
    return subprocess.Popen(
        [sys.executable, "-c", code, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        # Not the service directory: a developer's .env there is not ours
        # to read.
        cwd=str(cwd),
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(SERVICE_ROOT),
            "API_KEY": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "REDIS_URL": redis_url,
            **env,
        },
    )


def output_of(process):
    out, err = process.communicate(timeout=60)
    assert process.returncode == 0, err
    return out.strip()


# --- one count, whoever asks -------------------------------------------------


def test_the_limit_is_what_the_code_says(limiter):
    user = caller()

    granted = [limiter.allow(user, "active_scan", 3) for _ in range(5)]

    assert granted == [True, True, True, False, False]


def test_a_second_connection_sees_the_runs_of_the_first(redis_url, prefix):
    first = OperationRateLimiter(connect(redis_url), key_prefix=prefix)
    second = OperationRateLimiter(connect(redis_url), key_prefix=prefix)
    user = caller()

    assert first.allow(user, "destructive_test", 1) is True
    assert second.allow(user, "destructive_test", 1) is False
    assert first.allow(user, "destructive_test", 1) is False


def test_the_count_belongs_to_one_caller_and_one_operation(limiter):
    alice, bob = caller(), caller()

    assert limiter.allow(alice, "destructive_test", 1) is True
    assert limiter.allow(alice, "destructive_test", 1) is False
    # Another caller, and another operation of the same caller, are untouched.
    assert limiter.allow(bob, "destructive_test", 1) is True
    assert limiter.allow(alice, "credential_test", 1) is True


CHECK_AS_THE_SERVICE = """
import sys
from app.security.authorization import OperationType, authorization_manager

allowed = authorization_manager.check_rate_limit(sys.argv[1], OperationType(sys.argv[2]))
print(int(allowed))
"""


def test_a_process_started_later_is_refused_what_the_first_one_used(
    redis_url, redis_client, tmp_path
):
    """The defect as reported: each process allowed the limit on its own.

    Two interpreters, one after the other, ask the service's own
    ``check_rate_limit`` for the one destructive test an hour. The second is
    the worker child the task lands on, or the API after a restart.
    """
    user = f"test-721-{uuid.uuid4()}"
    key = f"{rate_limit.KEY_PREFIX}:{user}:destructive_test"
    try:
        answers = [
            output_of(
                python(
                    CHECK_AS_THE_SERVICE,
                    user,
                    "destructive_test",
                    redis_url=redis_url,
                    cwd=tmp_path,
                )
            )
            for _ in range(3)
        ]
    finally:
        redis_client.delete(key)

    assert answers == ["1", "0", "0"]


HAMMER = """
import json, sys, time
import redis
from app.security.rate_limit import OperationRateLimiter

url, prefix, start, limit, attempts = sys.argv[1:6]
users = sys.argv[6:]
limiter = OperationRateLimiter(
    redis.Redis.from_url(url, decode_responses=True), key_prefix=prefix
)
limiter.allow("warm-up", "connect", 1)
time.sleep(max(0.0, float(start) - time.time()))
granted = {user: 0 for user in users}
for _ in range(int(attempts)):
    for user in users:
        granted[user] += int(limiter.allow(user, "active_scan", int(limit)))
print(json.dumps(granted))
"""


def test_processes_asking_at_once_share_exactly_the_limit(redis_url, prefix, tmp_path):
    """Checking and recording are one step.

    Six processes ask for the same callers at the same moment, each more
    often than the limit allows. Read-then-write would let two of them read
    "one left" and both take it.
    """
    limit, processes, attempts = 4, 6, 3
    users = [caller() for _ in range(25)]
    start = time.time() + 3.0

    running = [
        python(
            HAMMER,
            redis_url,
            prefix,
            str(start),
            str(limit),
            str(attempts),
            *users,
            redis_url=redis_url,
            cwd=tmp_path,
        )
        for _ in range(processes)
    ]
    totals = {user: 0 for user in users}
    for process in running:
        for user, granted in json.loads(output_of(process)).items():
            totals[user] += granted

    assert processes * attempts > limit
    assert set(totals.values()) == {limit}, {
        user: granted for user, granted in totals.items() if granted != limit
    }


# --- the window ---------------------------------------------------------------


def test_an_allowance_comes_back_when_its_run_is_a_window_old(redis_url, prefix):
    limiter = OperationRateLimiter(
        connect(redis_url), window_seconds=1, key_prefix=prefix
    )
    user = caller()

    assert limiter.allow(user, "destructive_test", 1) is True
    assert limiter.allow(user, "destructive_test", 1) is False
    time.sleep(1.2)
    assert limiter.allow(user, "destructive_test", 1) is True
    assert limiter.allow(user, "destructive_test", 1) is False


def test_the_window_slides_with_each_run(redis_url, prefix):
    """At most ``limit`` in any window, not ``limit`` per period of the clock."""
    limiter = OperationRateLimiter(
        connect(redis_url), window_seconds=2, key_prefix=prefix
    )
    user = caller()

    assert limiter.allow(user, "active_scan", 2) is True
    time.sleep(1.2)
    assert limiter.allow(user, "active_scan", 2) is True
    time.sleep(1.2)
    # The first run is 2.4 s old and gone; the second, 1.2 s old, still counts.
    assert limiter.allow(user, "active_scan", 2) is True
    assert limiter.allow(user, "active_scan", 2) is False


def test_a_refused_attempt_is_not_a_run(redis_url, redis_client, prefix):
    limiter = OperationRateLimiter(connect(redis_url), key_prefix=prefix)
    user = caller()

    limiter.allow(user, "destructive_test", 1)
    for _ in range(5):
        assert limiter.allow(user, "destructive_test", 1) is False

    assert redis_client.zcard(limiter.key(user, "destructive_test")) == 1


def test_the_key_expires_with_the_window(redis_client, limiter):
    user = caller()

    limiter.allow(user, "destructive_test", 1)

    ttl = redis_client.ttl(limiter.key(user, "destructive_test"))
    assert 0 < ttl <= rate_limit.WINDOW_SECONDS
    assert rate_limit.WINDOW_SECONDS == 3600


def test_a_run_sent_twice_takes_one_allowance(redis_url, redis_client, prefix):
    """What makes the retry after a dropped connection safe."""
    client = connect(redis_url)
    script = client.register_script(rate_limit.ALLOW_SCRIPT)
    key = f"{prefix}:{caller()}:destructive_test"

    first = script(keys=[key], args=[1, 3600, "run-1"])
    again = script(keys=[key], args=[1, 3600, "run-1"])
    other = script(keys=[key], args=[1, 3600, "run-2"])

    assert (first, again, other) == (1, 1, 0)
    assert redis_client.zcard(key) == 1


class DropsTheFirstAnswer:
    """A script whose first call reaches Redis and then loses the connection."""

    def __init__(self, script):
        self._script = script
        self.calls = 0

    def __call__(self, keys, args):
        self.calls += 1
        answer = self._script(keys=keys, args=args)
        if self.calls == 1:
            raise redis.exceptions.ConnectionError("Connection reset by peer")
        return answer


def test_a_dropped_connection_is_retried_once_and_counted_once(
    redis_url, redis_client, prefix
):
    limiter = OperationRateLimiter(connect(redis_url), key_prefix=prefix)
    limiter._script = DropsTheFirstAnswer(limiter._script)
    user = caller()

    assert limiter.allow(user, "destructive_test", 1) is True

    assert limiter._script.calls == 2
    assert redis_client.zcard(limiter.key(user, "destructive_test")) == 1


# --- the service's limits ------------------------------------------------------


def test_the_hourly_limits_by_operation():
    assert HOURLY_LIMITS == {
        OperationType.READ_ONLY: 1000,
        OperationType.PASSIVE_SCAN: 100,
        OperationType.ACTIVE_SCAN: 10,
        OperationType.DESTRUCTIVE_TEST: 1,
        OperationType.CREDENTIAL_TEST: 5,
        OperationType.VULNERABILITY_EXPLOIT: 1,
    }
    assert set(HOURLY_LIMITS) == set(OperationType)
    assert DEFAULT_HOURLY_LIMIT == 10


@pytest.mark.parametrize(
    "operation", [OperationType.DESTRUCTIVE_TEST, OperationType.CREDENTIAL_TEST]
)
def test_check_rate_limit_applies_the_operations_limit(service_limiter, operation):
    user = caller()
    limit = HOURLY_LIMITS[operation]

    answers = [
        authorization_manager.check_rate_limit(user, operation)
        for _ in range(limit + 2)
    ]

    assert answers == [True] * limit + [False, False]


def test_the_manager_keeps_no_count_of_its_own():
    assert not hasattr(authorization_manager, "rate_limits")


def test_the_service_limiter_counts_in_the_services_redis(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(rate_limit, "_limiter", None)
    monkeypatch.setattr(settings, "redis_url", "redis://:pw@wildbox-redis:6379/2")

    limiter = rate_limit.get_rate_limiter()

    kwargs = limiter._redis.connection_pool.connection_kwargs
    assert (kwargs["host"], kwargs["port"], kwargs["db"]) == ("wildbox-redis", 6379, 2)
    # An unreachable Redis is reported in seconds, not when the kernel gives up.
    assert 0 < kwargs["socket_connect_timeout"] <= 5
    assert 0 < kwargs["socket_timeout"] <= 5
    assert limiter.key("u", "destructive_test") == (
        "wildbox:tools:operation-limit:u:destructive_test"
    )
    assert rate_limit.get_rate_limiter() is limiter


# --- when Redis cannot say -------------------------------------------------------


@pytest.fixture
def unreachable(monkeypatch):
    """The service's limiter, on a port where nothing listens."""
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]
    client = redis.Redis.from_url(
        f"redis://127.0.0.1:{closed_port}/0",
        decode_responses=True,
        socket_connect_timeout=1,
    )
    monkeypatch.setattr(rate_limit, "_limiter", OperationRateLimiter(client))
    yield
    client.close()


def test_an_unreachable_redis_refuses_the_run(unreachable):
    with pytest.raises(RateLimitUnavailable) as refused:
        authorization_manager.check_rate_limit(caller(), OperationType.DESTRUCTIVE_TEST)

    # What a caller may be told names no host; the log line does.
    assert str(refused.value) == "Rate limiting temporarily unavailable"
    assert "127.0.0.1" in refused.value.reason
    assert not isinstance(refused.value, PermissionError)


def test_without_a_redis_url_the_run_is_refused(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(rate_limit, "_limiter", None)
    monkeypatch.setattr(settings, "redis_url", None)

    with pytest.raises(RateLimitUnavailable) as refused:
        authorization_manager.check_rate_limit(caller(), OperationType.DESTRUCTIVE_TEST)

    assert refused.value.reason == "REDIS_URL is not set"


@pytest.fixture
def granted(monkeypatch):
    """A caller who may run the scanner against TARGET, and the requests sent."""
    from app.tools.sql_injection_scanner import main as sqli_scanner

    user = caller()
    monkeypatch.setattr(
        authorization_manager,
        "user_permissions",
        {user: [OperationType.DESTRUCTIVE_TEST]},
    )
    monkeypatch.setattr(authorization_manager, "authorized_targets", {PUBLIC_IP})
    sent = []

    class FakeResponse:
        text = "<html>ok</html>"

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None, timeout=None):
            sent.append(url)
            return FakeResponse()

    monkeypatch.setattr(sqli_scanner, "guarded_requests_session", FakeSession)
    return user, sent


@pytest.fixture
def client(granted, monkeypatch):
    from app.api import router as router_module
    from app.auth import verify_api_key
    from app.execution_manager import ToolExecutionManager
    from app.tool_loader import load_tool_module
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    user, _ = granted
    monkeypatch.setattr(router_module, "execution_manager", ToolExecutionManager())
    if not any(
        getattr(route, "path", "") == f"/api/tools/{TOOL}"
        for route in router_module.router.routes
    ):
        router_module.register_tool_endpoint(None, TOOL, load_tool_module(TOOL))

    app = FastAPI()
    app.include_router(router_module.router)
    app.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=user, team_id=str(uuid.uuid4()), role="member"
    )
    return TestClient(app, raise_server_exceptions=False)


def test_the_endpoint_answers_503_and_does_not_run_the_tool(
    client, granted, unreachable
):
    _, sent = granted

    response = client.post(f"/api/tools/{TOOL}", json={"target_url": TARGET})

    assert response.status_code == 503, response.text
    assert response.json() == {"detail": "Rate limiting temporarily unavailable"}
    assert "127.0.0.1" not in response.text
    assert sent == [], "a run that could not be counted was started"


def test_the_endpoint_counts_in_redis_and_refuses_the_second_run(
    client, granted, service_limiter
):
    _, sent = granted

    first = client.post(f"/api/tools/{TOOL}", json={"target_url": TARGET})
    requests_of_the_first = len(sent)
    second = client.post(f"/api/tools/{TOOL}", json={"target_url": TARGET})

    assert first.status_code == 200, first.text
    assert requests_of_the_first > 0
    assert second.status_code == 403, second.text
    assert "Rate limit exceeded for destructive_test" in second.json()["detail"]
    assert len(sent) == requests_of_the_first


def test_a_run_that_cannot_be_counted_is_not_an_execution(
    granted, unreachable, monkeypatch
):
    """No run, so nothing in the execution counter either: the 503 is the record."""
    import asyncio

    from app import execution_manager as execution_module
    from app.execution_manager import ToolExecutionManager
    from app.tools.sql_injection_scanner import main as sqli_scanner
    from app.tools.sql_injection_scanner.schemas import SQLInjectionScannerInput

    user, sent = granted
    counted = []

    class Recorder:
        def labels(self, **labels):
            counted.append(labels)
            return self

        def inc(self):
            pass

    monkeypatch.setattr(execution_module, "TOOL_EXECUTIONS", Recorder())

    with pytest.raises(RateLimitUnavailable):
        asyncio.run(
            ToolExecutionManager().execute_tool(
                tool_func=sqli_scanner.execute_tool,
                input_data=SQLInjectionScannerInput(target_url=TARGET),
                tool_name=TOOL,
                user_id=user,
            )
        )

    assert counted == []
    assert sent == []


def test_the_api_counts_off_the_event_loop(granted, monkeypatch):
    """A Redis that is slow to answer must not hold up every other request."""
    import asyncio
    import threading

    from app.execution_manager import ExecutionStatus, ToolExecutionManager
    from app.tools.sql_injection_scanner import main as sqli_scanner
    from app.tools.sql_injection_scanner.schemas import SQLInjectionScannerInput

    user, _ = granted
    asked_from = []

    class Limiter:
        def allow(self, user_id, operation, limit):
            asked_from.append(threading.current_thread())
            return True

    monkeypatch.setattr(rate_limit, "_limiter", Limiter())

    async def run():
        loop_thread = threading.current_thread()
        result = await ToolExecutionManager().execute_tool(
            tool_func=sqli_scanner.execute_tool,
            input_data=SQLInjectionScannerInput(target_url=TARGET),
            tool_name=TOOL,
            user_id=user,
        )
        return loop_thread, result

    loop_thread, result = asyncio.run(run())

    assert result.status is ExecutionStatus.COMPLETED, result.error
    assert len(asked_from) == 1
    assert asked_from[0] is not loop_thread


def test_the_worker_does_not_run_a_tool_it_cannot_count(
    granted, unreachable, monkeypatch
):
    pytest.importorskip("celery")
    from app import tasks

    user, sent = granted
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kwargs: None)

    # Raised, not returned: the task fails (after Celery's retries) and the
    # tool has not run.
    with pytest.raises(RateLimitUnavailable):
        tasks.execute_tool_async.run(
            tool_name=TOOL, input_data={"target_url": TARGET}, user_id=user
        )

    assert sent == []


def test_the_worker_shares_the_count_with_the_api(
    client, granted, service_limiter, monkeypatch
):
    """One allowance an hour, whichever path the run takes."""
    pytest.importorskip("celery")
    from app import tasks

    user, sent = granted
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kwargs: None)

    through_the_api = client.post(f"/api/tools/{TOOL}", json={"target_url": TARGET})
    requests_of_the_first = len(sent)
    in_the_worker = tasks.execute_tool_async.run(
        tool_name=TOOL, input_data={"target_url": TARGET}, user_id=user
    )

    assert through_the_api.status_code == 200, through_the_api.text
    assert in_the_worker["status"] == "refused"
    assert "Rate limit exceeded for destructive_test" in in_the_worker["error"]
    assert len(sent) == requests_of_the_first
