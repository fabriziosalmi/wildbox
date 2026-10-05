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
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

pytest.importorskip("celery")

from app import async_metrics  # noqa: E402
from app.async_metrics import AsyncRunCounts  # noqa: E402
from prometheus_client.parser import text_string_to_metric_families  # noqa: E402

SERVICE_ROOT = Path(__file__).resolve().parents[2]
SUPPORT = Path(__file__).resolve().parent / "support"
TASK = "app.tasks.execute_tool_async"
PROBE = "metrics_probe"


class Stack:
    """A running worker, a client to send it tasks, and the counts it writes."""

    def __init__(self, client_app, counts, queue, node, log_path):
        self.app = client_app
        self.counts = counts
        self.queue = queue
        self.node = node
        self.log_path = log_path

    def send(self, tool=PROBE, input_data=None, user_id=None, **options):
        return self.app.send_task(
            TASK,
            kwargs={
                "tool_name": tool,
                "input_data": input_data or {},
                "user_id": user_id or str(uuid.uuid4()),
            },
            queue=self.queue,
            **options,
        )

    def probe(self, behaviour, seconds=0.0, **options):
        return self.send(
            input_data={"behaviour": behaviour, "seconds": seconds}, **options
        )

    def meta(self, result):
        return self.app.backend.get_task_meta(result.id)

    def state(self, result, among, seconds=60):
        """Wait for the task to reach one of ``among``; return its meta."""
        deadline = time.monotonic() + seconds
        meta = self.meta(result)
        while meta["status"] not in among and time.monotonic() < deadline:
            time.sleep(0.1)
            meta = self.meta(result)
        assert meta["status"] in among, (meta, self.log())
        return meta

    def outcomes(self):
        return dict(self.counts.read().outcomes)

    def settled(self, before, expected, seconds=30):
        """Wait until the outcome counts grew by exactly ``expected``.

        Then wait a little longer and look again: the count must stay there,
        which is what "counted once" means.
        """

        def grown():
            now = self.outcomes()
            return {
                key: now.get(key, 0) - before.get(key, 0)
                for key in set(now) | set(before)
                if now.get(key, 0) != before.get(key, 0)
            }

        deadline = time.monotonic() + seconds
        while grown() != expected and time.monotonic() < deadline:
            time.sleep(0.1)
        assert grown() == expected, self.log()
        time.sleep(1.0)
        assert grown() == expected, self.log()

    def log(self):
        """The end of the worker's log, for a failure message."""
        return self.log_since(0)[-4000:]

    def mark(self):
        """Where the worker's log ends now."""
        return len(self.log_since(0))

    def log_since(self, mark):
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return text[mark:]

    def logged(self, mark, wanted, seconds=30):
        """Wait for the worker to log ``wanted`` after ``mark``; return that log.

        The worker writes its log after it stores a task's state, so a line
        about a task can follow the state the test waited for.
        """
        deadline = time.monotonic() + seconds
        text = self.log_since(mark)
        while wanted.lower() not in text.lower() and time.monotonic() < deadline:
            time.sleep(0.1)
            text = self.log_since(mark)
        assert wanted.lower() in text.lower(), text[-4000:]
        return text


@pytest.fixture(scope="module")
def stack(redis_url, tmp_path_factory):
    import redis
    from celery import Celery

    run = uuid.uuid4().hex[:12]
    queue = f"wildbox-tools-test-{run}"
    node = f"probe-{run}@localhost"
    outcomes_key = f"wildbox:tools:test-{run}:async-outcomes"
    consumed_key = f"wildbox:tools:test-{run}:async-consumed"
    workdir = tmp_path_factory.mktemp("worker")
    log_path = workdir / "worker.log"

    patch = pytest.MonkeyPatch()
    patch.setattr(async_metrics, "OUTCOMES_KEY", outcomes_key)
    patch.setattr(async_metrics, "CONSUMED_KEY", consumed_key)

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    client_app = Celery(f"client-{run}", broker=redis_url, backend=redis_url)
    client_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        broker_connection_retry_on_startup=True,
    )

    with open(log_path, "w", encoding="utf-8") as log:
        worker = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "celery",
                "-A",
                "async_worker_app:celery_app",
                "worker",
                "--pool=prefork",
                "--concurrency=1",
                # Every task in a child of its own: a count kept in a child
                # would never get past one.
                "--max-tasks-per-child=1",
                "--loglevel=info",
                "--without-gossip",
                "--without-mingle",
                "-Q",
                queue,
                "-n",
                node,
            ],
            # Not the service directory: a developer's .env there is not ours
            # to read.
            cwd=str(workdir),
            stdout=log,
            stderr=subprocess.STDOUT,
            env={
                "PATH": os.environ.get("PATH", ""),
                "PYTHONPATH": os.pathsep.join([str(SERVICE_ROOT), str(SUPPORT)]),
                "API_KEY": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                "REDIS_URL": redis_url,
                "TOOLS_TEST_EXTRA_TOOLS": str(SUPPORT / "tools"),
                "TOOLS_TEST_OUTCOMES_KEY": outcomes_key,
                "TOOLS_TEST_CONSUMED_KEY": consumed_key,
                "TOOLS_TEST_QUEUE": queue,
            },
        )
    running = Stack(
        client_app, AsyncRunCounts(client, queue=queue), queue, node, log_path
    )
    try:
        deadline = time.monotonic() + 90
        ready = False
        while not ready and time.monotonic() < deadline:
            assert worker.poll() is None, running.log()
            replies = client_app.control.inspect(destination=[node], timeout=1).ping()
            ready = bool(replies and node in replies)
        assert ready, running.log()
        yield running
    finally:
        worker.terminate()
        try:
            worker.wait(timeout=30)
        except subprocess.TimeoutExpired:
            worker.kill()
        patch.undo()
        client.delete(outcomes_key, consumed_key, queue)
        client_app.close()
        client.close()


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
    monkeypatch.setattr(async_metrics, "_counts", (os.getpid(), stack.counts))
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
    consumed = stack.counts.read().consumed

    # One child: the second task waits behind the first, and is cancelled there.
    blocker = stack.probe("sleep", seconds=3)
    waiting = stack.probe("return")
    waiting.revoke()
    stack.state(blocker, {"SUCCESS"})
    stack.state(waiting, {"REVOKED"})

    stack.settled(before, {(PROBE, "completed"): 1, (PROBE, "cancelled"): 1})
    # The blocker's start, and the task the worker took only to drop it.
    assert stack.counts.read().consumed == consumed + 2


def test_a_task_whose_process_died_is_counted_when_it_does_end(stack, tmp_path):
    """Celery puts such a task back on the queue; that is not an end."""
    before = stack.outcomes()
    consumed = stack.counts.read().consumed
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
    assert stack.counts.read().consumed == consumed + 2


# --- the ends the task reports itself -------------------------------------------


def test_a_task_stopped_at_the_soft_time_limit_is_counted_as_a_timeout(stack):
    before = stack.outcomes()

    result = stack.probe("sleep", seconds=60, soft_time_limit=1, time_limit=30)
    meta = stack.state(result, {"SUCCESS"})

    assert meta["result"]["status"] == "timeout"
    stack.settled(before, {(PROBE, "timeout"): 1})


def test_completed_runs_are_counted_across_children_that_are_replaced(stack):
    before = stack.outcomes()
    consumed = stack.counts.read().consumed
    mark = stack.mark()

    results = [stack.probe("return") for _ in range(3)]
    for result in results:
        meta = stack.state(result, {"SUCCESS"})
        assert meta["result"]["status"] == "completed"

    stack.settled(before, {(PROBE, "completed"): 3})
    assert stack.counts.read().consumed == consumed + 3
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
    consumed = stack.counts.read().consumed

    # RuntimeError is not a type the task catches: two retries, then FAILURE.
    result = stack.probe("crash")
    meta = stack.state(result, {"FAILURE"})

    assert "RuntimeError" in repr(meta["result"])
    stack.settled(before, {(PROBE, "failed"): 1})
    # Three starts of one task: a retry is consumed again, not failed again.
    assert stack.counts.read().consumed == consumed + 3


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
        return bool(replies) and all("ok" in reply[stack.node] for reply in replies)

    consumed = stack.counts.read().consumed
    assert stack.counts.read().queued == 0

    # The worker is up and stops reading its queue: what a worker that lost
    # its broker connection, or a stopped one, looks like from outside.
    assert replied(
        stack.app.control.cancel_consumer(
            stack.queue, destination=[stack.node], reply=True, timeout=10
        )
    )
    try:
        results = [stack.probe("return") for _ in range(2)]
        time.sleep(2.0)

        reading = stack.counts.read()
        assert reading.queued == 2
        assert reading.consumed == consumed
        assert {stack.meta(result)["status"] for result in results} == {"PENDING"}
    finally:
        assert replied(
            stack.app.control.add_consumer(
                stack.queue, destination=[stack.node], reply=True, timeout=10
            )
        )

    for result in results:
        stack.state(result, {"SUCCESS"})
    reading = stack.counts.read()
    assert reading.queued == 0
    assert reading.consumed == consumed + 2
