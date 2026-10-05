"""What becomes of a task when workers stop, start and die, with real workers (#743).

The service's own Celery app runs as prefork workers against a Redis server
(the ``stack`` fixture). Each test here needs a worker in a particular
state, so it starts its own on a queue of its own: one that starts only
after the task was cancelled, one whose child dies on every start, one that
is killed whole while it holds a task.
"""

import os
import sys
import time

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

pytest.importorskip("celery")

from app.task_ownership import TaskOwnership  # noqa: E402
from worker_stack import PROBE  # noqa: E402  (tests/unit/support, see conftest)

FINAL = {"SUCCESS", "FAILURE", "REVOKED"}


# --- a cancellation holds when no worker heard it ---------------------------------


def test_a_task_cancelled_while_no_worker_runs_does_not_run_when_one_starts(
    stack, tmp_path
):
    """The defect: Celery's revocation is kept by the workers alive when it is sent.

    The task waits in a queue nobody reads, its owner cancels it, and only
    then does a worker start: one that never heard the revocation. It used
    to run the task.
    """
    queue = stack.new_queue()
    ran = tmp_path / "ran"
    before = stack.outcomes()
    consumed = stack.consumed()

    result = stack.send(
        input_data={"behaviour": "touch", "marker": str(ran)}, queue=queue
    )
    # What DELETE /api/tasks/{id} does, in its order: the record, then the
    # broadcast.
    TaskOwnership(stack.redis).cancel(result.id)
    result.revoke(terminate=True)
    assert stack.meta(result)["status"] == "PENDING"
    assert stack.queued(queue) == 1

    worker = stack.start_worker(queue)
    try:
        meta = stack.state(result, FINAL)

        assert meta["status"] == "REVOKED", meta
        assert not ran.exists(), "the cancelled task ran"
        # Taken off the queue, counted once as cancelled, and nothing else.
        stack.settled(before, {(PROBE, "cancelled"): 1})
        assert stack.queued(queue) == 0
        assert stack.consumed() == consumed + 1
        assert "cancelled before it started" in worker.log_since()
    finally:
        worker.stop()


def test_a_task_nobody_cancelled_runs_on_a_worker_that_starts_later(stack, tmp_path):
    """The control: the same wait, no cancellation, and the tool runs."""
    queue = stack.new_queue()
    ran = tmp_path / "ran"
    before = stack.outcomes()

    result = stack.send(
        input_data={"behaviour": "touch", "marker": str(ran)}, queue=queue
    )
    time.sleep(0.5)

    worker = stack.start_worker(queue)
    try:
        meta = stack.state(result, FINAL)

        assert meta["status"] == "SUCCESS", meta
        assert ran.exists()
        stack.settled(before, {(PROBE, "completed"): 1})
    finally:
        worker.stop()


# --- a task that keeps killing its process is not redelivered for ever ---------------


def test_a_task_whose_process_dies_every_time_is_failed_after_three_starts(
    stack, tmp_path
):
    """The defect: Celery put it back on the queue each time, without end.

    The probe kills its own process on every start, as a tool does that
    runs out of memory or crashes in native code. It is started three times
    and then failed, and the worker goes on to the next task.
    """
    starts = tmp_path / "starts"
    before = stack.outcomes()
    consumed = stack.consumed()
    mark = stack.mark()

    result = stack.send(input_data={"behaviour": "die", "marker": str(starts)})
    meta = stack.state(result, FINAL, seconds=90)

    assert starts.read_text(encoding="utf-8").count("started") == 3
    assert meta["status"] == "SUCCESS", meta  # it ended, and reports how
    assert meta["result"]["status"] == "failed"
    assert meta["result"]["error"] == (
        "The worker process running this task was lost 3 times; "
        "the task was not started again"
    )
    # Three starts that died and the delivery that gave up: one failure.
    stack.settled(before, {(PROBE, "failed"): 1})
    assert stack.consumed() == consumed + 4
    assert stack.queued() == 0
    assert stack.log_since(mark).count("exited with 'signal 9 (SIGKILL)'") == 3

    # The worker is not harmed: the next task runs.
    after = stack.probe("return")
    assert stack.state(after, FINAL)["status"] == "SUCCESS"
    stack.settled(before, {(PROBE, "failed"): 1, (PROBE, "completed"): 1})


# --- a worker killed whole: what becomes of the task it held --------------------------


def test_a_task_held_by_a_worker_killed_whole_comes_back_after_the_visibility_timeout(
    stack, tmp_path
):
    """What `docker kill`, or the kernel on the container, does to a running task.

    The whole worker is killed by SIGKILL, main process and child, while it
    runs a task. Nobody acknowledged the task and nobody put it back: the
    broker keeps it for the dead worker until its visibility timeout has
    passed, and then only a worker that is running returns it to the queue.
    The service sets that timeout to an hour (app/celery_app.py); here it is
    three seconds, so that the wait fits in a test.
    """
    queue = stack.new_queue()
    short = {"TOOLS_TEST_VISIBILITY_TIMEOUT": "3"}
    started = tmp_path / "started"
    before = stack.outcomes()
    consumed = stack.consumed()

    first = stack.start_worker(queue, env=short)
    result = stack.send(
        input_data={
            "behaviour": "sleep_once",
            "seconds": 120,
            "marker": str(started),
        },
        queue=queue,
    )
    deadline = time.monotonic() + 30
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert started.exists(), first.log_since()[-2000:]
    taken = time.monotonic()

    first.kill()

    # Not in the queue, so the queue length the API exports does not see it,
    # and still "running" to whoever reads the task.
    assert stack.queued(queue) == 0
    assert stack.meta(result)["status"] in {"STARTED", "RUNNING"}
    # Past the timeout, with no worker running, nothing has returned it.
    time.sleep(5)
    assert stack.queued(queue) == 0
    assert stack.meta(result)["status"] in {"STARTED", "RUNNING"}
    assert stack.outcomes() == before

    second = stack.start_worker(queue, env=short)
    try:
        meta = stack.state(result, FINAL, seconds=90)
        waited = time.monotonic() - taken

        assert meta["status"] == "SUCCESS", meta
        assert meta["result"]["status"] == "completed"
        # Longer than the timeout, and not much: a worker looks for such
        # tasks when it starts (and every hundred seconds after that).
        assert 3 < waited < 60, waited
        # One task, started twice, ended once; the start that was killed
        # counts as one lost start, far from the bound.
        stack.settled(before, {(PROBE, "completed"): 1})
        assert stack.consumed() == consumed + 2
    finally:
        second.stop()
