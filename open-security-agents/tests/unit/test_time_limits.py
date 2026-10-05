"""A task that ends where it cannot record why is still recorded (#727).

At the hard time limit Celery kills the process the task runs in, and a
process can also die under a task (out of memory, SIGKILL). Nothing in the
task body runs after either, so neither a failure code nor ``failed_today``
was recorded: the task read as failed with the generic reason, and the
counter missed it. A task whose whole worker was gone read as running until
its record expired.

Each is now recorded where it can be seen, once:

- at the soft time limit, by the task, which Celery interrupts with a margin
  before the hard one;
- at the hard limit, or when the task's process dies, by the worker's main
  process, on Celery's ``task_failure`` signal;
- when neither could, by the API, from what Celery holds for the task.

These tests exercise the hooks directly, with Redis and Celery's results
replaced. tests/unit/test_time_limits_real_worker.py hits the limits against
a real worker and a real Redis.
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from celery import signals
from celery.exceptions import (
    SoftTimeLimitExceeded,
    TimeLimitExceeded,
    WorkerLostError,
)
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage
from pydantic import ValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import config, failures, main, stats, worker  # noqa: E402
from app.agents.threat_enrichment_agent import ThreatEnrichmentAgent  # noqa: E402
from app.config import Settings, settings  # noqa: E402
from app.failures import AnalysisFailed  # noqa: E402
from app.tools.wildbox_client import (  # noqa: E402
    CallerIdentityUnavailable,
    _caller_identity,
)
from scripted_model import ScriptedModel  # noqa: E402

SECRET = "gateway-secret-for-tests"
CALLER = {
    "user_id": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "team_id": "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b",
    "role": "member",
}
IOC = {"type": "domain", "value": "example.com"}
TASK_ID = "11111111-2222-4333-8444-555555555555"
OTHER_TASK_ID = "66666666-7777-4888-8999-aaaaaaaaaaaa"
ERROR_KEY = f"task:{TASK_ID}:error"


class FakeRedis:
    """The subset of redis-py the worker and the endpoint call."""

    def __init__(self):
        self.store = {}
        self.ttl = {}

    def get(self, key):
        value = self.store.get(key)
        if value is None:
            return None
        return value if isinstance(value, bytes) else str(value).encode()

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        self.ttl[key] = ex
        return True

    def setex(self, key, ttl, value):
        self.store[key] = value
        self.ttl[key] = ttl

    def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1

    def expire(self, key, ttl):
        return True

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)

    def pipeline(self):
        return self

    def execute(self):
        return []


@pytest.fixture(autouse=True)
def no_identity_left_behind():
    _caller_identity.set(None)
    yield
    _caller_identity.set(None)


@pytest.fixture
def redis(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(worker, "redis_client", redis)
    monkeypatch.setattr(main, "redis_client", redis)
    return redis


def failed_today(redis):
    return stats.read_today(redis, stats.FAILED)


def task_kwargs(task_id=TASK_ID):
    """The arguments the API enqueues the task with (app/main.py)."""
    return {"task_id": task_id, "ioc": dict(IOC), "caller": dict(CALLER)}


def celery_marks_failed(exception, task_id=TASK_ID, sender=None):
    """What Celery does where it marks a task failed: send task_failure."""
    signals.task_failure.send(
        sender=sender or worker.run_threat_enrichment_task,
        task_id="celery-task-1",
        exception=exception,
        args=[],
        kwargs=task_kwargs(task_id),
        traceback=None,
        einfo=None,
    )


# --- The two limits ----------------------------------------------------------


def test_the_task_is_told_to_stop_before_it_is_killed():
    conf = worker.celery_app.conf
    assert conf.task_time_limit == settings.task_timeout
    assert (
        conf.task_time_limit - conf.task_soft_time_limit
        == config.SOFT_LIMIT_MARGIN_SECONDS
    )
    # Recording a failure is two Redis commands; the margin is far above it.
    assert config.SOFT_LIMIT_MARGIN_SECONDS >= 10
    assert conf.task_soft_time_limit > 0


@pytest.mark.parametrize("value", ["0", "30", "59", "-600"])
def test_a_timeout_that_leaves_no_time_to_run_stops_the_service(monkeypatch, value):
    """The soft limit is the timeout minus the margin: 30 made it zero."""
    monkeypatch.setenv("TASK_TIMEOUT", value)
    with pytest.raises(ValidationError, match="TASK_TIMEOUT"):
        Settings(_env_file=None)


@pytest.mark.parametrize("value", ["60", "600", "3600"])
def test_a_timeout_with_room_for_the_margin_is_accepted(monkeypatch, value):
    monkeypatch.setenv("TASK_TIMEOUT", value)
    assert Settings(_env_file=None).task_timeout == int(value)


# --- Which code an exception gets --------------------------------------------


@pytest.mark.parametrize(
    "error, code",
    [
        (TimeLimitExceeded(600), failures.TIMED_OUT),
        (SoftTimeLimitExceeded(), failures.TIMED_OUT),
        (WorkerLostError("Worker exited prematurely: signal 9"), failures.INTERRUPTED),
        (AnalysisFailed(failures.REPORT_FAILED), failures.REPORT_FAILED),
        (CallerIdentityUnavailable("no caller"), failures.NO_CALLER),
        (ValueError("anything else"), failures.INTERNAL),
        (None, failures.INTERNAL),
        ("not an exception", failures.INTERNAL),
    ],
    ids=lambda value: type(value).__name__ if not isinstance(value, str) else value,
)
def test_the_code_for_what_a_task_ended_with(error, code):
    assert worker.failure_code(error) == code
    assert code in failures.REASONS


# --- Recording once ----------------------------------------------------------


def test_a_failure_is_recorded_and_counted_once_whoever_sees_it(redis):
    assert worker.record_failure(redis, TASK_ID, failures.TIMED_OUT) is True
    assert worker.record_failure(redis, TASK_ID, failures.INTERRUPTED) is False
    assert worker.record_failure(redis, TASK_ID, failures.TIMED_OUT) is False

    # The first record stands, and the task was counted once.
    assert redis.store[ERROR_KEY] == failures.TIMED_OUT
    assert redis.store[f"task:{TASK_ID}:status"] == "failed"
    assert failed_today(redis) == 1


def test_each_task_is_counted(redis):
    worker.record_failure(redis, TASK_ID, failures.TIMED_OUT)
    worker.record_failure(redis, OTHER_TASK_ID, failures.TIMED_OUT)
    assert failed_today(redis) == 2


def test_the_record_lives_as_long_as_the_task_can_be_read(redis):
    """It is written after the task's other keys with the same lifetime, so
    it cannot expire, and the task be counted again, while the task is
    still addressable."""
    worker.record_failure(redis, TASK_ID, failures.TIMED_OUT)
    assert redis.ttl[ERROR_KEY] == settings.task_result_expires


# --- The worker's main process: hard limit, lost process ---------------------


@pytest.mark.parametrize(
    "error, code",
    [
        (TimeLimitExceeded(600), failures.TIMED_OUT),
        (
            WorkerLostError("Worker exited prematurely: signal 9 (SIGKILL)"),
            failures.INTERRUPTED,
        ),
    ],
    ids=["hard-time-limit", "process-lost"],
)
def test_a_task_killed_under_its_own_code_is_recorded_by_the_worker(redis, error, code):
    """Through Celery's signal, as the worker's main process receives it."""
    celery_marks_failed(error)

    assert redis.store[ERROR_KEY] == code
    assert redis.store[f"task:{TASK_ID}:status"] == "failed"
    assert failed_today(redis) == 1


def test_a_failure_the_task_recorded_is_not_recorded_again(monkeypatch, redis):
    """Celery sends the signal for every failure, in the task's process too."""
    monkeypatch.setattr(
        worker.run_threat_enrichment_task, "update_state", lambda *a, **k: None
    )

    class Agent:
        async def analyze_ioc(self, ioc):
            raise AnalysisFailed(failures.MODEL_UNAVAILABLE)

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", Agent)
    with pytest.raises(AnalysisFailed) as failed:
        worker.run_threat_enrichment_task(**task_kwargs())

    celery_marks_failed(failed.value)
    # Even a signal that would map to another code changes nothing.
    celery_marks_failed(TimeLimitExceeded(600))

    assert redis.store[ERROR_KEY] == failures.MODEL_UNAVAILABLE
    assert failed_today(redis) == 1


def test_another_tasks_failure_is_not_an_analysis_failure(redis):
    celery_marks_failed(TimeLimitExceeded(600), sender=worker.cleanup_expired_tasks)
    assert redis.store == {}


@pytest.mark.parametrize("kwargs", [{}, None, {"task_id": None}, {"task_id": 7}])
def test_a_failure_without_a_task_id_records_nothing(redis, kwargs):
    worker._record_unrecorded_failure(
        sender=worker.run_threat_enrichment_task,
        exception=TimeLimitExceeded(600),
        args=[],
        kwargs=kwargs,
    )
    assert redis.store == {}


def test_a_task_enqueued_with_positional_arguments_is_recorded(redis):
    worker._record_unrecorded_failure(
        sender=worker.run_threat_enrichment_task,
        exception=TimeLimitExceeded(600),
        args=[TASK_ID, dict(IOC), dict(CALLER)],
        kwargs={},
    )
    assert redis.store[ERROR_KEY] == failures.TIMED_OUT


def test_redis_down_in_the_hook_does_not_raise_into_celery(monkeypatch, redis):
    def down(*args, **kwargs):
        raise ConnectionError("redis is down")

    monkeypatch.setattr(redis, "set", down)

    worker._record_unrecorded_failure(
        sender=worker.run_threat_enrichment_task,
        exception=TimeLimitExceeded(600),
        args=[],
        kwargs=task_kwargs(),
    )

    assert failed_today(redis) == 0


# --- The soft limit, wherever it is raised -----------------------------------


def test_the_soft_limit_during_the_report_is_a_timeout_not_a_failed_report(
    monkeypatch, redis
):
    """Celery raises it wherever the task is. In the report's generation it
    was caught with every other exception and recorded as "its report could
    not be generated"."""
    monkeypatch.setattr(
        worker.run_threat_enrichment_task, "update_state", lambda *a, **k: None
    )
    model = ScriptedModel(
        responses=[AIMessage(content="Notes.")], report=SoftTimeLimitExceeded()
    )
    monkeypatch.setattr(ThreatEnrichmentAgent, "_initialize_llm", lambda self: model)
    agent = ThreatEnrichmentAgent()

    with pytest.raises(SoftTimeLimitExceeded):
        asyncio.run(agent.analyze_ioc(dict(IOC)))

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", lambda: agent)
    with pytest.raises(SoftTimeLimitExceeded):
        worker.run_threat_enrichment_task(**task_kwargs())

    assert redis.store[ERROR_KEY] == failures.TIMED_OUT
    assert failed_today(redis) == 1


def test_the_task_says_when_it_started(monkeypatch, redis):
    states = []
    monkeypatch.setattr(
        worker.run_threat_enrichment_task,
        "update_state",
        lambda state=None, meta=None: states.append((state, meta)),
    )

    class Agent:
        async def analyze_ioc(self, ioc):
            return {"verdict": "Benign"}

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", Agent)
    before = datetime.now(timezone.utc)
    worker.run_threat_enrichment_task(**task_kwargs())
    after = datetime.now(timezone.utc)

    assert [state for state, _ in states] == ["STARTED", "STARTED"]
    started = {meta["started_at"] for _, meta in states}
    assert len(started) == 1, "the start time changed between two updates"
    assert before <= datetime.fromisoformat(started.pop()) <= after
    assert all(meta["progress"] for _, meta in states)


# --- The API: what Celery holds for the task ---------------------------------


class CeleryResult:
    """What the endpoint reads of a Celery result.

    ``info`` is, as in Celery, the exception of a failed task and what a
    running task wrote about itself.
    """

    state = "PENDING"
    info = None
    result = None
    date_done = None

    def __init__(self, task_id, app=None):
        self.id = task_id


@pytest.fixture
def api(monkeypatch, redis):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(main, "AsyncResult", CeleryResult)
    for name in ("state", "info", "result", "date_done"):
        monkeypatch.setattr(CeleryResult, name, getattr(CeleryResult, name))
    redis.setex(f"task:{TASK_ID}:celery_id", 3600, "celery-task-1")
    redis.setex(f"task:{TASK_ID}:user_id", 3600, CALLER["user_id"])
    redis.setex(
        f"task:{TASK_ID}:metadata", 3600, '{"created_at": "2026-10-05T10:00:00+00:00"}'
    )
    return TestClient(main.app)


def celery_holds(monkeypatch, state, info=None, date_done=None):
    monkeypatch.setattr(CeleryResult, "state", state)
    monkeypatch.setattr(CeleryResult, "info", info)
    monkeypatch.setattr(CeleryResult, "date_done", date_done)


def read(api):
    response = api.get(
        f"/v1/analyze/{TASK_ID}",
        headers={
            "X-Wildbox-User-ID": CALLER["user_id"],
            "X-Wildbox-Team-ID": CALLER["team_id"],
            "X-Wildbox-Role": CALLER["role"],
            "X-Gateway-Secret": SECRET,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize(
    "error, code",
    [
        (TimeLimitExceeded(600), failures.TIMED_OUT),
        (
            WorkerLostError("Worker exited prematurely: signal 9 (SIGKILL)"),
            failures.INTERRUPTED,
        ),
        (ValueError("raised while Redis was down"), failures.INTERNAL),
        (None, failures.INTERNAL),
    ],
    ids=["hard-time-limit", "process-lost", "unrecorded-error", "no-exception"],
)
def test_a_failure_nobody_recorded_gets_its_reason_from_celery(
    monkeypatch, api, redis, error, code
):
    """It was the generic "Analysis failed. Please retry or contact
    support." for all of them."""
    celery_holds(monkeypatch, "FAILURE", error)

    body = read(api)

    assert body["status"] == "failed"
    assert body["error"] == failures.REASONS[code]
    assert body["error"] != failures.GENERIC_REASON
    assert redis.store[ERROR_KEY] == code


def test_reading_a_failed_task_counts_it_once(monkeypatch, api, redis):
    celery_holds(monkeypatch, "FAILURE", TimeLimitExceeded(600))

    assert failed_today(redis) == 0
    for _ in range(3):
        assert read(api)["status"] == "failed"

    assert failed_today(redis) == 1


@pytest.mark.parametrize("first", ["api", "worker"])
def test_the_worker_and_the_api_together_count_a_killed_task_once(
    monkeypatch, api, redis, first
):
    """Celery stores the failure before it sends the signal, so the API can
    read a killed task before the worker has recorded it."""
    celery_holds(monkeypatch, "FAILURE", TimeLimitExceeded(600))

    if first == "api":
        read(api)
    celery_marks_failed(TimeLimitExceeded(600))
    read(api)
    read(api)

    assert redis.store[ERROR_KEY] == failures.TIMED_OUT
    assert failed_today(redis) == 1


def test_a_recorded_failure_is_not_replaced_by_celerys(monkeypatch, api, redis):
    """The task's own record says more than the exception it ended with."""
    redis.setex(ERROR_KEY, 3600, failures.NOT_CONFIGURED)
    celery_holds(monkeypatch, "FAILURE", TimeLimitExceeded(600))

    assert read(api)["error"] == failures.REASONS[failures.NOT_CONFIGURED]
    assert failed_today(redis) == 0, "the task that recorded it counted it"


def test_a_failed_task_ended_when_celery_says_it_did(monkeypatch, api):
    """It was the time of the request."""
    ended = datetime(2026, 10, 5, 10, 10, tzinfo=timezone.utc)
    celery_holds(monkeypatch, "FAILURE", TimeLimitExceeded(600), date_done=ended)

    body = read(api)

    assert datetime.fromisoformat(body["completed_at"]) == ended
    assert body["started_at"] is None


@pytest.mark.parametrize(
    "stored",
    ["2026-10-05T10:10:00+00:00", "2026-10-05T10:10:00"],
    ids=["aware", "naive-utc"],
)
def test_the_end_time_is_read_from_the_text_the_backend_stores(
    monkeypatch, api, stored
):
    celery_holds(monkeypatch, "FAILURE", TimeLimitExceeded(600), date_done=stored)
    assert datetime.fromisoformat(read(api)["completed_at"]) == datetime(
        2026, 10, 5, 10, 10, tzinfo=timezone.utc
    )


# --- The API: a task whose worker is gone ------------------------------------


def running_since(monkeypatch, seconds_ago, **meta):
    started = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    info = {"progress": "Running AI analysis...", "started_at": started.isoformat()}
    info.update(meta)
    celery_holds(monkeypatch, "STARTED", info)
    return started


def test_a_running_task_reports_when_it_started(monkeypatch, api, redis):
    started = running_since(monkeypatch, 42)

    body = read(api)

    assert body["status"] == "running"
    assert datetime.fromisoformat(body["started_at"]) == started
    assert body["progress"] == "Running AI analysis..."
    assert body["error"] is None and body["completed_at"] is None
    assert failed_today(redis) == 0


def test_a_task_within_its_time_limit_is_running(monkeypatch, api, redis):
    """Up to the hard limit and the grace after it, the worker may still
    be about to report it."""
    running_since(
        monkeypatch, settings.task_timeout + main.LOST_WORKER_GRACE_SECONDS - 5
    )

    assert read(api)["status"] == "running"
    assert ERROR_KEY not in redis.store


def test_a_task_still_running_past_the_hard_limit_has_lost_its_worker(
    monkeypatch, api, redis
):
    """A worker kills a task at the hard limit. One still "running" after
    it was on a worker that is gone: it read as running until it expired."""
    started = running_since(
        monkeypatch, settings.task_timeout + main.LOST_WORKER_GRACE_SECONDS + 5
    )

    body = read(api)

    assert body["status"] == "failed"
    assert body["error"] == failures.REASONS[failures.INTERRUPTED]
    assert datetime.fromisoformat(body["started_at"]) == started
    # Nobody saw it end, and it is doing nothing.
    assert body["completed_at"] is None and body["progress"] is None
    assert redis.store[ERROR_KEY] == failures.INTERRUPTED

    read(api)
    read(api)
    assert failed_today(redis) == 1


@pytest.mark.parametrize(
    "info",
    [
        {"pid": 71, "hostname": "celery@worker"},
        {"progress": "Running AI analysis...", "started_at": "yesterday"},
        {"progress": "Running AI analysis...", "started_at": None},
        None,
    ],
    ids=["celerys-own-started", "unreadable", "missing", "nothing"],
)
def test_a_running_task_without_a_start_time_is_running(monkeypatch, api, redis, info):
    """Without knowing when it started, nothing says it is lost."""
    celery_holds(monkeypatch, "STARTED", info)

    body = read(api)

    assert body["status"] == "running"
    assert body["started_at"] is None
    assert ERROR_KEY not in redis.store


# --- The API: the other states -----------------------------------------------


def test_a_cancelled_task_reads_as_revoked(monkeypatch, api, redis):
    """Celery's REVOKED fell through to "pending", for ever."""
    celery_holds(monkeypatch, "REVOKED", Exception("revoked"))

    body = read(api)

    assert body["status"] == "revoked"
    assert body["error"] is None
    assert failed_today(redis) == 0 and ERROR_KEY not in redis.store


@pytest.mark.parametrize("state", ["PENDING", "RECEIVED", "RETRY"])
def test_a_task_not_started_yet_is_pending(monkeypatch, api, redis, state):
    celery_holds(monkeypatch, state)

    body = read(api)

    assert body["status"] == "pending"
    assert body["started_at"] is None and body["completed_at"] is None
    assert ERROR_KEY not in redis.store
