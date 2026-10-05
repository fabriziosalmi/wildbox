"""A task whose process keeps dying is failed, not redelivered for ever (#743).

With ``task_acks_late`` and ``task_reject_on_worker_lost`` Celery puts a task
back on the queue when the process running it dies. A tool that takes its
process down every time (out of memory, a native crash) came back without
end: it never ended, its owner read ``running`` for ever, and each round
killed a worker child.

The task now counts its starts in Redis and, when three of them left no
result, fails on the next delivery with that reason.
``test_async_task_lifecycle_worker.py`` does it with a real worker whose
child dies on every start; this file covers the counting.
"""

import os
import sys
from types import SimpleNamespace

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

pytest.importorskip("celery")

from app import async_metrics, tasks  # noqa: E402
from app.task_ownership import OWNER_TTL_SECONDS  # noqa: E402

TOOL = "hash_generator"
INPUT = {"input_text": "wildbox"}
KEY = "wildbox:tools:task-starts:{}"


def test_the_bound_is_three_lost_starts():
    assert tasks.MAX_LOST_STARTS == 3


def test_each_start_is_counted_and_the_count_expires(task_ownership, fake_redis):
    assert [task_ownership.count_start("task-1") for _ in range(3)] == [1, 2, 3]
    assert task_ownership.count_start("task-2") == 1

    assert fake_redis.kv[KEY.format("task-1")] == "3"
    assert fake_redis.ttl[KEY.format("task-1")] == OWNER_TTL_SECONDS


def test_a_first_start_has_lost_none(task_ownership):
    assert tasks._starts_lost("task-1", retries=0) == 0


def test_a_start_after_a_process_died_has_lost_one(task_ownership):
    tasks._starts_lost("task-1", retries=0)  # the start that died

    assert tasks._starts_lost("task-1", retries=0) == 1
    assert tasks._starts_lost("task-1", retries=0) == 2
    assert tasks._starts_lost("task-1", retries=0) == 3


def test_a_retry_is_not_a_lost_start(task_ownership):
    """Celery scheduled it: the start before it ended with a state."""
    assert tasks._starts_lost("task-1", retries=0) == 0
    assert tasks._starts_lost("task-1", retries=1) == 0
    assert tasks._starts_lost("task-1", retries=2) == 0
    # The second retry's process died and the task was redelivered.
    assert tasks._starts_lost("task-1", retries=2) == 1


def test_tasks_are_counted_apart(task_ownership):
    for _ in range(4):
        tasks._starts_lost("task-1", retries=0)

    assert tasks._starts_lost("task-2", retries=0) == 0


# --- the task --------------------------------------------------------------------------


@pytest.fixture
def worker(monkeypatch, task_ownership):
    seen = SimpleNamespace(outcomes=[], ownership=task_ownership)
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kw: None)
    monkeypatch.setattr(
        async_metrics,
        "record_outcome",
        lambda task_id, tool, outcome, **kw: seen.outcomes.append((tool, outcome)),
    )
    monkeypatch.setattr(async_metrics, "record_taken", lambda task_id: None)
    return seen


def run(task_id):
    """Run the task in this process through Celery's tracer, as a worker does."""
    return tasks.execute_tool_async.apply(
        kwargs={"tool_name": TOOL, "input_data": INPUT, "user_id": "u-1"},
        task_id=task_id,
    )


def test_after_three_lost_starts_the_task_fails_and_says_why(worker, monkeypatch):
    def must_not_run(*args, **kwargs):
        raise AssertionError("the task was started a fourth time")

    monkeypatch.setattr(tasks, "check_tool_request", must_not_run)
    for _ in range(3):
        worker.ownership.count_start("task-1")  # three starts that died

    result = run("task-1")

    assert result.state == "SUCCESS"  # the task ended; it reports how
    assert result.result["status"] == "failed"
    assert result.result["error"] == (
        "The worker process running this task was lost 3 times; "
        "the task was not started again"
    )
    assert "result" not in result.result
    # Counted, once, as a failure: it is one.
    assert worker.outcomes == [(TOOL, "failed")]


@pytest.mark.parametrize("lost", [0, 1, 2])
def test_below_the_bound_the_task_runs(worker, lost):
    for _ in range(lost):
        worker.ownership.count_start("task-1")

    result = run("task-1")

    assert result.result["status"] == "completed"
    assert worker.outcomes == [(TOOL, "completed")]


def test_a_start_that_cannot_be_counted_is_not_run_uncounted(
    worker, fake_redis, monkeypatch
):
    def must_not_run(*args, **kwargs):
        raise AssertionError("ran without being counted")

    def unreachable(key):
        raise RedisConnectionError("connection reset")

    monkeypatch.setattr(tasks, "check_tool_request", must_not_run)
    monkeypatch.setattr(fake_redis, "incr", unreachable)

    with pytest.raises(RedisConnectionError):
        tasks._starts_lost("task-1", retries=0)
    assert run("task-1").state != "SUCCESS"


def test_without_redis_nothing_is_counted(monkeypatch):
    from app import task_ownership
    from app.config import settings

    monkeypatch.setattr(task_ownership, "_ownership", None)
    monkeypatch.setattr(settings, "redis_url", None)

    assert tasks._starts_lost("task-1", retries=0) == 0
    assert tasks._starts_lost(None, retries=0) == 0
