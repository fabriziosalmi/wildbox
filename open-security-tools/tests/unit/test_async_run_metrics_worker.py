"""Asynchronous runs are counted however they end, in a real worker (#721).

An asynchronous run executes in ``tools-worker``, a Celery prefork worker
that Prometheus cannot scrape, and nothing counted it. The ends that matter
most are the ones the child process that ran the task never sees: it is
killed at the hard time limit, or the task is cancelled. Celery settles
those in the worker's main process.

So these tests start the service's own Celery app as a prefork worker
(``support/async_worker_app.py``) against a Redis server, with one child
that is replaced after every task, and make tasks end in each way. What is
checked is what Prometheus would scrape: the counts in Redis, and for the
hard kill the text the API serves at ``/metrics``.
"""

import os
import re
import sys
import time
import uuid

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

pytest.importorskip("celery")

from app import async_metrics  # noqa: E402
from app.async_metrics import AsyncRunCounts  # noqa: E402
from prometheus_client.parser import text_string_to_metric_families  # noqa: E402
from worker_stack import PROBE  # noqa: E402  (tests/unit/support, see conftest)

# The worker these tests send tasks to is the ``stack`` fixture of conftest.py:
# one for the session, started from support/async_worker_app.py.


# --- the two ends the child never sees ----------------------------------------


def test_a_task_killed_at_the_hard_time_limit_is_counted_as_a_timeout(
    stack, monkeypatch
):
    """The case the issue names: no handler runs in a process that is killed."""
    before = stack.outcomes()
    mark = stack.mark()

    # The probe ignores the soft limit (1 s), so the hard one (2 s) ends it.
    result = stack.probe("hang", seconds=60, soft_time_limit=1, time_limit=2)
    meta = stack.state(result, {"FAILURE"})

    assert "TimeLimitExceeded" in repr(meta["result"])
    # Killed, not stopped: the worker says so, and that the process is gone.
    stack.logged(mark, "Hard time limit (2s) exceeded")
    stack.logged(mark, "exited with 'signal 9 (SIGKILL)'")
    stack.settled(before, {(PROBE, "timeout"): 1})

    # And what Prometheus reads from the API process, which ran nothing.
    from app.config import settings
    from app.main import create_app
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "redis_url", "redis://configured")
    monkeypatch.setattr(async_metrics, "OUTCOMES_KEY", stack.outcomes_key)
    monkeypatch.setattr(async_metrics, "CONSUMED_KEY", stack.consumed_key)
    monkeypatch.setattr(
        async_metrics,
        "_counts",
        (os.getpid(), AsyncRunCounts(stack.redis, queue=stack.queue)),
    )
    text = TestClient(create_app()).get("/metrics").text

    scraped = {
        (sample.name, tuple(sorted(sample.labels.items()))): sample.value
        for family in text_string_to_metric_families(text)
        for sample in family.samples
    }
    timeouts = stack.outcomes()[(PROBE, "timeout")]
    assert (
        scraped[
            (
                "wildbox_tool_async_executions_total",
                (("outcome", "timeout"), ("tool", PROBE)),
            )
        ]
        == timeouts
        >= 1
    )
    assert scraped[("wildbox_tool_async_metrics_up", ())] == 1
    assert scraped[("wildbox_tool_async_queue_length", ())] == 0


def test_a_task_cancelled_while_it_runs_is_counted_as_cancelled(stack):
    before = stack.outcomes()

    result = stack.probe("sleep", seconds=60)
    stack.state(result, {"STARTED", "RUNNING"})
    result.revoke(terminate=True)
    stack.state(result, {"REVOKED"})

    stack.settled(before, {(PROBE, "cancelled"): 1})


def test_a_task_cancelled_while_it_waits_is_counted_and_was_consumed(stack):
    before = stack.outcomes()
    consumed = stack.consumed()

    # One child: the second task waits behind the first, and is cancelled there.
    blocker = stack.probe("sleep", seconds=3)
    waiting = stack.probe("return")
    waiting.revoke()
    stack.state(blocker, {"SUCCESS"})
    stack.state(waiting, {"REVOKED"})

    stack.settled(before, {(PROBE, "completed"): 1, (PROBE, "cancelled"): 1})
    # The blocker's start, and the task the worker took only to drop it.
    assert stack.consumed() == consumed + 2


def test_a_task_whose_process_died_is_counted_when_it_does_end(stack, tmp_path):
    """Celery puts such a task back on the queue; that is not an end."""
    before = stack.outcomes()
    consumed = stack.consumed()
    mark = stack.mark()

    result = stack.send(
        input_data={"behaviour": "die_once", "marker": str(tmp_path / "died")}
    )
    meta = stack.state(result, {"SUCCESS"})

    assert (tmp_path / "died").exists()
    stack.logged(mark, "exited with 'signal 9 (SIGKILL)'")
    assert meta["result"]["status"] == "completed"
    # Not a failure for the attempt that died, and two starts.
    stack.settled(before, {(PROBE, "completed"): 1})
    assert stack.consumed() == consumed + 2


# --- the ends the task reports itself -------------------------------------------


def test_a_task_stopped_at_the_soft_time_limit_is_counted_as_a_timeout(stack):
    before = stack.outcomes()

    result = stack.probe("sleep", seconds=60, soft_time_limit=1, time_limit=30)
    meta = stack.state(result, {"SUCCESS"})

    assert meta["result"]["status"] == "timeout"
    stack.settled(before, {(PROBE, "timeout"): 1})


def test_completed_runs_are_counted_across_children_that_are_replaced(stack):
    before = stack.outcomes()
    consumed = stack.consumed()
    mark = stack.mark()

    results = [stack.probe("return") for _ in range(3)]
    for result in results:
        meta = stack.state(result, {"SUCCESS"})
        assert meta["result"]["status"] == "completed"

    stack.settled(before, {(PROBE, "completed"): 3})
    assert stack.consumed() == consumed + 3
    # Three tasks, each in a child that was started for it.
    children = set(re.findall(r"ForkPoolWorker-(\d+)", stack.log_since(mark)))
    assert len(children) >= 3, children


def test_a_tool_that_raises_is_counted_as_failed(stack):
    before = stack.outcomes()

    meta = stack.state(stack.probe("raise"), {"SUCCESS"})

    assert meta["result"]["status"] == "failed"
    stack.settled(before, {(PROBE, "failed"): 1})


def test_a_task_that_fails_after_its_retries_is_counted_once(stack):
    before = stack.outcomes()
    consumed = stack.consumed()

    # A RuntimeError before the tool is called (the probe's input model
    # raises it): the task itself fails. Two retries, then FAILURE. This
    # test made the tool raise it, which Celery retried too: a failing tool
    # was called three times (#774; the next test).
    result = stack.probe("fault_before")
    meta = stack.state(result, {"FAILURE"})

    assert "RuntimeError" in repr(meta["result"])
    stack.settled(before, {(PROBE, "failed"): 1})
    # Three starts of one task: a retry is consumed again, not failed again.
    assert stack.consumed() == consumed + 3


def test_a_tool_that_crashes_is_called_once_and_counted_once(stack, tmp_path):
    """Whatever the class of what it raises (#774)."""
    before = stack.outcomes()
    consumed = stack.consumed()
    starts = tmp_path / "starts"

    result = stack.send(input_data={"behaviour": "crash", "starts": str(starts)})
    meta = stack.state(result, {"SUCCESS", "FAILURE"})

    assert meta["status"] == "SUCCESS", meta
    assert meta["result"]["status"] == "failed"
    assert meta["result"]["error"] == "Tool execution failed (RuntimeError)"
    # settled() waits and looks again: longer than a retry would take to come.
    stack.settled(before, {(PROBE, "failed"): 1})
    assert starts.read_text(encoding="utf-8").splitlines() == ["called"]
    assert stack.consumed() == consumed + 1


def test_a_task_that_never_starts_its_tool_is_refused_not_failed(stack):
    """Input that does not validate is the caller's error, as a 422 is.

    The synchronous path answers it before a run exists, so its counter
    never holds it; counted as failed here it would raise the failure rate
    of the asynchronous runs for every malformed request.
    """
    before = stack.outcomes()

    result = stack.send(input_data={"behaviour": "no such behaviour"})
    meta = stack.state(result, {"SUCCESS"})

    # What the client reads is unchanged.
    assert meta["result"]["status"] == "failed"
    stack.settled(before, {(PROBE, "refused"): 1})


def test_a_tool_name_that_is_no_tool_is_one_label(stack):
    """The name is a path segment the caller wrote: it must not be a label."""
    before = stack.outcomes()

    names = [f"no_such_tool_{uuid.uuid4().hex}" for _ in range(3)]
    for name in names:
        meta = stack.state(stack.send(tool=name), {"SUCCESS"})
        assert meta["result"]["status"] == "failed"

    stack.settled(before, {("unknown", "refused"): 3})
    assert not {tool for tool, _ in stack.outcomes()} & set(names)


# --- a worker that consumes nothing ------------------------------------------------


def test_tasks_nobody_takes_stay_in_the_queue_length(stack):
    def replied(replies):
        return bool(replies) and all(
            "ok" in reply[stack.worker.node] for reply in replies
        )

    consumed = stack.consumed()
    assert stack.queued() == 0

    # The worker is up and stops reading its queue: what a worker that lost
    # its broker connection, or a stopped one, looks like from outside.
    assert replied(
        stack.app.control.cancel_consumer(
            stack.queue, destination=[stack.worker.node], reply=True, timeout=10
        )
    )
    try:
        results = [stack.probe("return") for _ in range(2)]
        time.sleep(2.0)

        assert stack.queued() == 2
        assert stack.consumed() == consumed
        assert {stack.meta(result)["status"] for result in results} == {"PENDING"}
    finally:
        assert replied(
            stack.app.control.add_consumer(
                stack.queue, destination=[stack.worker.node], reply=True, timeout=10
            )
        )

    for result in results:
        stack.state(result, {"SUCCESS"})
    assert stack.queued() == 0
    assert stack.consumed() == consumed + 2
