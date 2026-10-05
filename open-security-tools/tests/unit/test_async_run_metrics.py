"""The counts of asynchronous runs, and what the API exports of them (#721).

``test_async_run_metrics_worker.py`` makes tasks end in a real worker. This
file holds what needs no worker: the counts themselves (against a Redis
server), the handlers that write them (driven as Celery drives them, with
its signals), and the collector the API serves them from, also when Redis
does not answer.
"""

import logging
import os
import socket
import sys
import uuid

import pytest
import redis
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.parser import text_string_to_metric_families

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

pytest.importorskip("celery")

from app import async_metrics, tasks  # noqa: E402
from app.async_metrics import AsyncRunCounts, AsyncRunsCollector  # noqa: E402
from app.execution_manager import ExecutionStatus  # noqa: E402
from celery import signals  # noqa: E402
from celery.exceptions import TimeLimitExceeded, WorkerLostError  # noqa: E402

TOOL = "hash_generator"
SCANNER = "sql_injection_scanner"
METRICS = (
    "wildbox_tool_async_executions_total",
    "wildbox_tool_async_tasks_consumed_total",
    "wildbox_tool_async_queue_length",
    "wildbox_tool_async_metrics_up",
)


@pytest.fixture
def counts(redis_client, monkeypatch):
    """The service's counts, in keys and a queue of this test's own."""
    run = uuid.uuid4().hex
    outcomes = f"wildbox:tools:test-{run}:async-outcomes"
    consumed = f"wildbox:tools:test-{run}:async-consumed"
    queue = f"wildbox-tools-test-{run}"
    monkeypatch.setattr(async_metrics, "OUTCOMES_KEY", outcomes)
    monkeypatch.setattr(async_metrics, "CONSUMED_KEY", consumed)
    mine = AsyncRunCounts(redis_client, queue=queue)
    monkeypatch.setattr(async_metrics, "_counts", (os.getpid(), mine))
    mine.queue = queue
    yield mine
    redis_client.delete(outcomes, consumed, queue)


@pytest.fixture
def unreachable(monkeypatch):
    """The service's counts, on a port where nothing listens."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    client = redis.Redis.from_url(
        f"redis://127.0.0.1:{port}/0", decode_responses=True, socket_connect_timeout=1
    )
    monkeypatch.setattr(
        async_metrics, "_counts", (os.getpid(), AsyncRunCounts(client, queue="celery"))
    )
    yield
    client.close()


def scrape(collector):
    """{(sample, labels): value} and {family: type}, as /metrics serves them."""
    registry = CollectorRegistry()
    registry.register(collector)
    text = generate_latest(registry).decode()
    samples, types = {}, {}
    for family in text_string_to_metric_families(text):
        types[family.name] = family.type
        for sample in family.samples:
            samples[(sample.name, tuple(sorted(sample.labels.items())))] = sample.value
    return samples, types, text


# --- the counts ---------------------------------------------------------------


def test_outcomes_are_counted_by_tool_and_outcome(counts):
    counts.task_settled(TOOL, "completed")
    counts.task_settled(TOOL, "completed")
    counts.task_settled(TOOL, "failed")
    counts.task_settled("dns_resolver", "timeout")

    assert counts.read().outcomes == {
        (TOOL, "completed"): 2,
        (TOOL, "failed"): 1,
        ("dns_resolver", "timeout"): 1,
    }


def test_the_outcomes_are_the_ones_the_synchronous_counter_uses():
    assert set(async_metrics.OUTCOMES) == {
        status.value for status in ExecutionStatus
    } - {"pending", "running"}


def test_something_that_is_not_an_outcome_is_not_counted(counts):
    with pytest.raises(ValueError):
        counts.task_settled(TOOL, "exploded")

    assert counts.read().outcomes == {}


def test_two_connections_add_to_one_count(counts, redis_url):
    """The worker's main process and its children are connections like these."""
    other = redis.Redis.from_url(redis_url, decode_responses=True)
    try:
        elsewhere = AsyncRunCounts(other, queue=counts.queue)
        counts.task_settled(TOOL, "completed")
        elsewhere.task_settled(TOOL, "completed")
        elsewhere.task_taken()
        counts.task_taken()

        for reader in (counts, elsewhere):
            reading = reader.read()
            assert reading.outcomes == {(TOOL, "completed"): 2}
            assert reading.consumed == 2
    finally:
        other.close()


def test_a_task_dropped_before_it_started_is_consumed_when_it_is_counted(counts):
    counts.task_settled(TOOL, "cancelled", taken_now=True)
    counts.task_settled(TOOL, "cancelled")

    reading = counts.read()
    assert reading.outcomes == {(TOOL, "cancelled"): 2}
    assert reading.consumed == 1


def test_the_queue_length_is_the_brokers(counts, redis_client):
    assert counts.read().queued == 0

    redis_client.lpush(counts.queue, "a task", "another")

    assert counts.read().queued == 2


def test_a_field_that_is_not_a_count_of_ours_is_left_out(counts, redis_client):
    redis_client.hset(
        async_metrics.OUTCOMES_KEY,
        mapping={"no separator": 3, f"{TOOL}|exploded": 4, "|completed": 5},
    )
    counts.task_settled(TOOL, "completed")

    assert counts.read().outcomes == {(TOOL, "completed"): 1}


def test_a_tool_label_is_a_tool_or_unknown():
    assert async_metrics.tool_label(TOOL) == TOOL
    assert async_metrics.tool_label(SCANNER) == SCANNER
    for name in ("no_such_tool", "", None, "hash_generator.main", "wordlists", 7):
        assert async_metrics.tool_label(name) == "unknown"


# --- the service's own client ----------------------------------------------------


def test_without_a_redis_url_there_is_nothing_to_count_in(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(async_metrics, "_counts", None)
    monkeypatch.setattr(settings, "redis_url", None)

    assert async_metrics.get_counts() is None
    # And the worker's writes are then nothing, not an error.
    async_metrics.record_taken("task-1")
    async_metrics.record_outcome("task-1", TOOL, "completed")


def test_the_service_counts_in_its_redis_and_reads_its_queue(monkeypatch):
    from app.celery_app import celery_app
    from app.config import settings

    monkeypatch.setattr(async_metrics, "_counts", None)
    monkeypatch.setattr(settings, "redis_url", "redis://:pw@wildbox-redis:6379/2")

    mine = async_metrics.get_counts()

    kwargs = mine._redis.connection_pool.connection_kwargs
    assert (kwargs["host"], kwargs["port"], kwargs["db"]) == ("wildbox-redis", 6379, 2)
    # A scrape waits seconds for Redis, not for as long as the kernel does.
    assert 0 < kwargs["socket_connect_timeout"] <= 5
    assert 0 < kwargs["socket_timeout"] <= 5
    assert mine._queue == celery_app.conf.task_default_queue == "celery"
    assert async_metrics.get_counts() is mine


def test_a_forked_process_gets_a_client_of_its_own(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "redis_url", "redis://wildbox-redis:6379/2")
    inherited = AsyncRunCounts(
        redis.Redis.from_url("redis://wildbox-redis:6379/2"), queue="celery"
    )
    # What a child holds after the fork: the parent's object, under its pid.
    monkeypatch.setattr(async_metrics, "_counts", (os.getpid() + 1, inherited))

    assert async_metrics.get_counts() is not inherited


def test_a_write_that_fails_is_logged_and_does_not_raise(unreachable, caplog):
    with caplog.at_level(logging.WARNING, logger="app.async_metrics"):
        async_metrics.record_taken("task-1")
        async_metrics.record_outcome("task-1", TOOL, "completed")

    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 2
    assert "could not record that task task-1 was taken" in messages[0]
    assert "could not record the outcome completed of task task-1" in messages[1]


# --- the handlers, driven by Celery's signals ----------------------------------------


class Request:
    def __init__(self, task_id, **kwargs):
        self.id = task_id
        self.kwargs = kwargs


def task_instance():
    """The task instance Celery passes as the sender."""
    from app.celery_app import celery_app

    return celery_app.tasks[tasks.TASK_NAME]


def einfo():
    """What Celery passes as ``einfo`` to a failure handler; not read here."""
    return None


def test_a_hard_time_limit_reported_by_the_main_process_is_a_timeout(counts):
    """As Request.on_failure sends it after the pool killed the child."""
    signals.task_failure.send(
        sender=task_instance(),
        task_id="task-1",
        exception=TimeLimitExceeded(600),
        args=[],
        kwargs={"tool_name": TOOL, "input_data": {}},
        traceback=None,
        einfo=einfo(),
    )

    assert counts.read().outcomes == {(TOOL, "timeout"): 1}


@pytest.mark.parametrize(
    "exception", [RuntimeError("boom"), WorkerLostError("signal 9 (SIGKILL)")]
)
def test_any_other_failure_is_failed(counts, exception):
    signals.task_failure.send(
        sender=task_instance(),
        task_id="task-1",
        exception=exception,
        args=[],
        kwargs={"tool_name": TOOL, "input_data": {}},
        traceback=None,
        einfo=einfo(),
    )

    assert counts.read().outcomes == {(TOOL, "failed"): 1}


@pytest.mark.parametrize("terminated, consumed", [(True, 0), (False, 1)])
def test_a_revoked_task_is_cancelled(counts, terminated, consumed):
    signals.task_revoked.send(
        sender=task_instance(),
        request=Request("task-1", tool_name=TOOL, input_data={}),
        terminated=terminated,
        signum=15 if terminated else None,
        expired=False,
    )

    reading = counts.read()
    assert reading.outcomes == {(TOOL, "cancelled"): 1}
    # Cancelled while it ran, its start was counted; while it waited, nothing
    # had counted it.
    assert reading.consumed == consumed


def test_a_start_is_consumed(counts):
    signals.task_prerun.send(
        sender=task_instance(),
        task_id="task-1",
        task=task_instance(),
        args=[],
        kwargs={},
    )

    reading = counts.read()
    assert reading.consumed == 1
    assert reading.outcomes == {}


def test_another_task_of_the_app_is_not_a_tool_run(counts):
    class OtherTask:
        name = "celery.backend_cleanup"
        request = Request("task-9")

    other = OtherTask()
    signals.task_prerun.send(
        sender=other, task_id="task-9", task=other, args=[], kwargs={}
    )
    signals.task_success.send(sender=other, result=None)
    signals.task_failure.send(
        sender=other,
        task_id="task-9",
        exception=RuntimeError(),
        args=[],
        kwargs={},
        traceback=None,
        einfo=einfo(),
    )
    signals.task_revoked.send(
        sender=other,
        request=other.request,
        terminated=False,
        signum=None,
        expired=False,
    )

    reading = counts.read()
    assert reading.outcomes == {}
    assert reading.consumed == 0


# --- the task itself, run by Celery's tracer -------------------------------------------


def run_task(**kwargs):
    """Run the task in this process through Celery's tracer, signals included."""
    return tasks.execute_tool_async.apply(kwargs=kwargs)


@pytest.fixture
def no_state_updates(monkeypatch):
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kwargs: None)


def test_a_completed_run_is_counted_once(counts, no_state_updates):
    result = run_task(tool_name=TOOL, input_data={"input_text": "wildbox"})

    assert result.result["status"] == "completed"
    reading = counts.read()
    assert reading.outcomes == {(TOOL, "completed"): 1}
    assert reading.consumed == 1


def test_a_caller_who_may_not_run_the_tool_is_refused(counts, no_state_updates):
    # No caller at all: the scanner acts for one.
    result = run_task(
        tool_name=SCANNER, input_data={"target_url": "http://93.184.215.14/?id=1"}
    )

    assert result.result["status"] == "refused"
    assert counts.read().outcomes == {(SCANNER, "refused"): 1}


@pytest.mark.parametrize(
    "tool, input_data, label",
    [
        # Input the schema rejects.
        (TOOL, {"input_text": "x", "hash_types": ["md5"]}, TOOL),
        # A target the policy refuses.
        (
            "http_security_scanner",
            {"url": "http://169.254.169.254/"},
            "http_security_scanner",
        ),
        # No such tool.
        ("no_such_tool", {}, "unknown"),
    ],
)
def test_a_task_that_ends_before_its_tool_starts_is_refused_not_failed(
    counts, no_state_updates, tool, input_data, label
):
    result = run_task(tool_name=tool, input_data=input_data)

    # What the client reads has not changed.
    assert result.result["status"] == "failed"
    assert counts.read().outcomes == {(label, "refused"): 1}


def test_a_tool_that_raises_is_failed(counts, no_state_updates, monkeypatch):
    def raises(tool_name):
        class Module:
            class schemas:  # noqa: N801 - the attribute a tool module has
                from pydantic import BaseModel

                class ProbeInput(BaseModel):
                    pass

            @staticmethod
            def execute_tool(data):
                raise ValueError("the tool failed")

        return Module

    monkeypatch.setattr(tasks, "_load_tool_module", raises)

    result = run_task(tool_name=TOOL, input_data={})

    assert result.result["status"] == "failed"
    assert counts.read().outcomes == {(TOOL, "failed"): 1}


# --- what the API exports ---------------------------------------------------------------


def test_the_collector_exports_the_counts(counts, redis_client):
    counts.task_settled(TOOL, "completed")
    counts.task_settled(TOOL, "completed")
    counts.task_settled(TOOL, "failed")
    counts.task_taken()
    redis_client.lpush(counts.queue, "a task")

    samples, types, _ = scrape(AsyncRunsCollector())

    assert samples == {
        (
            "wildbox_tool_async_executions_total",
            (("outcome", "completed"), ("tool", TOOL)),
        ): 2,
        (
            "wildbox_tool_async_executions_total",
            (("outcome", "failed"), ("tool", TOOL)),
        ): 1,
        ("wildbox_tool_async_tasks_consumed_total", ()): 1,
        ("wildbox_tool_async_queue_length", ()): 1,
        ("wildbox_tool_async_metrics_up", ()): 1,
    }
    assert types == {
        "wildbox_tool_async_executions": "counter",
        "wildbox_tool_async_tasks_consumed": "counter",
        "wildbox_tool_async_queue_length": "gauge",
        "wildbox_tool_async_metrics_up": "gauge",
    }


def test_before_any_run_the_counters_that_alerts_compare_are_zero_not_absent(counts):
    samples, _, _ = scrape(AsyncRunsCollector())

    assert samples == {
        ("wildbox_tool_async_tasks_consumed_total", ()): 0,
        ("wildbox_tool_async_queue_length", ()): 0,
        ("wildbox_tool_async_metrics_up", ()): 1,
    }


def test_when_redis_does_not_answer_no_number_is_exported(unreachable, caplog):
    """A zero would be a counter that fell to nothing, and then came back."""
    with caplog.at_level(logging.WARNING, logger="app.async_metrics"):
        samples, _, text = scrape(AsyncRunsCollector())

    assert samples == {("wildbox_tool_async_metrics_up", ()): 0}
    # The metrics are still named: a rule that reads them reads something.
    for metric in METRICS:
        assert f"# TYPE {metric} " in text
    assert any("could not read the counts" in r.getMessage() for r in caplog.records)


def test_the_api_serves_them_from_metrics(counts, monkeypatch):
    from app.config import settings
    from app.main import create_app
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "redis_url", "redis://configured")
    counts.task_settled(TOOL, "timeout")

    response = TestClient(create_app()).get("/metrics")

    assert response.status_code == 200
    scraped = {
        (sample.name, tuple(sorted(sample.labels.items()))): sample.value
        for family in text_string_to_metric_families(response.text)
        for sample in family.samples
    }
    assert (
        scraped[
            (
                "wildbox_tool_async_executions_total",
                (("outcome", "timeout"), ("tool", TOOL)),
            )
        ]
        == 1
    )
    assert scraped[("wildbox_tool_async_metrics_up", ())] == 1


def test_the_api_serves_metrics_when_redis_is_down(unreachable, monkeypatch):
    """The scrape must not fail with the store: the other metrics are in it."""
    from app.config import settings
    from app.main import create_app
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "redis_url", "redis://configured")

    response = TestClient(create_app()).get("/metrics")

    assert response.status_code == 200
    assert "wildbox_tool_async_metrics_up 0.0" in response.text
    assert "wildbox_http_requests_total" in response.text
