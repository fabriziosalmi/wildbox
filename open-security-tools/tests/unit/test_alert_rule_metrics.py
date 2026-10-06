"""The alert rules read metrics this service really exports (#658).

Prometheus loads a rule on a metric or a label that does not exist without a
word: the expression is empty for ever and the alert can never fire. So this
runs the service, produces every outcome a synchronous tool run can have,
records every outcome an asynchronous one can have where the worker records
it, scrapes ``/metrics`` and checks each ``wildbox_*`` selector in
``monitoring/alert_rules.yml`` against what was scraped: the metric, the
labels it matches or aggregates on, and the label values it names.

It also pins what ``wildbox_tool_executions_total`` counts, because the rule
``WildboxSyncToolFailureRate`` is named and described for it: runs the api
process executes, by outcome. Asynchronous runs execute in the worker and
are counted in Redis, which the api exports as
``wildbox_tool_async_executions_total`` (#721); how each end of a task gets
there is tested with a real worker in ``test_async_run_metrics_worker.py``.
The asynchronous counts are read from a Redis server, so this module needs
one (the ``redis_url`` fixture).
"""

import asyncio
import importlib.util
import os
import re
import sys
import time
import uuid
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import async_metrics  # noqa: E402
from app.execution_manager import (  # noqa: E402
    ExecutionStatus,
    ToolExecutionManager,
)
from app.main import create_app  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
ALERT_RULES = REPO_ROOT / "monitoring" / "alert_rules.yml"
CHECKER = REPO_ROOT / "scripts" / "check_monitoring_config.py"

pytestmark = pytest.mark.skipif(
    not ALERT_RULES.exists(),
    reason="monitoring/ is not next to this service (not a full checkout)",
)

PREFIX = "wildbox_"
TOOL = "alert_rule_contract"
# A tool of the service: the asynchronous counter labels nothing else by name.
ASYNC_TOOL = "hash_generator"


def _checker():
    spec = importlib.util.spec_from_file_location("check_monitoring_config", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _completes(_input):
    return {"success": True}


def _reports_a_failure_in_its_result(_input):
    # What a tool answers for an unreachable target (app/tool_errors.py).
    return {"success": False, "error": "target unreachable"}


def _raises(_input):
    raise ValueError("a failure the tool does not handle")


def _raises_what_nothing_catches(_input):
    # Not one of the types the execution manager catches by name.
    raise RuntimeError("an error nobody expected")


def _never_finishes(_input):
    time.sleep(0.5)


def _run(manager, tool_func, tool_name=TOOL, **kwargs):
    return asyncio.run(
        manager.execute_tool(
            tool_func=tool_func, input_data=None, tool_name=tool_name, **kwargs
        )
    )


def _counted(tool_name):
    """{outcome: count} the execution counter holds for one tool, as exported."""
    from open_security_shared.observability import metrics_response

    counts = {}
    for family in text_string_to_metric_families(metrics_response().body.decode()):
        for sample in family.samples:
            if (
                sample.name == "wildbox_tool_executions_total"
                and sample.labels["tool"] == tool_name
            ):
                counts[sample.labels["outcome"]] = sample.value
    return counts


@pytest.fixture(scope="module")
def async_counts(redis_url):
    """The service's asynchronous counts, in keys of this module's own."""
    import redis
    from app.config import settings

    run = uuid.uuid4().hex
    keys = [
        f"wildbox:tools:test-{run}:async-outcomes",
        f"wildbox:tools:test-{run}:async-consumed",
    ]
    client = redis.Redis.from_url(redis_url, decode_responses=True)
    counts = async_metrics.AsyncRunCounts(client, queue=f"wildbox-tools-test-{run}")
    patch = pytest.MonkeyPatch()
    patch.setattr(async_metrics, "OUTCOMES_KEY", keys[0])
    patch.setattr(async_metrics, "CONSUMED_KEY", keys[1])
    patch.setattr(async_metrics, "_counts", (os.getpid(), counts))
    # With a REDIS_URL the service exports the counts; without, there is no
    # asynchronous execution.
    patch.setattr(settings, "redis_url", redis_url)
    try:
        yield counts
    finally:
        patch.undo()
        client.delete(*keys)
        client.close()


@pytest.fixture(scope="module")
def scraped(async_counts):
    """{metric: {label: {values}}} from /metrics after every outcome."""
    # An asynchronous task of each outcome, written as the worker writes it.
    async_metrics.record_taken("task-0")
    for outcome in async_metrics.OUTCOMES:
        async_metrics.record_outcome("task-0", ASYNC_TOOL, outcome)

    manager = ToolExecutionManager()
    assert _run(manager, _completes).status is ExecutionStatus.COMPLETED
    assert (
        _run(manager, _reports_a_failure_in_its_result).status
        is ExecutionStatus.COMPLETED
    )
    assert _run(manager, _raises).status is ExecutionStatus.FAILED
    assert (
        _run(manager, _never_finishes, timeout=0.05).status is ExecutionStatus.TIMEOUT
    )

    client = TestClient(create_app(), raise_server_exceptions=False)
    client.get("/api/tools")  # one request, so the HTTP counter has a sample
    response = client.get("/metrics")
    assert response.status_code == 200

    exported = {}
    for family in text_string_to_metric_families(response.text):
        for sample in family.samples:
            labels = exported.setdefault(sample.name, {})
            for label, value in sample.labels.items():
                labels.setdefault(label, set()).add(value)
    return exported


@pytest.fixture(scope="module")
def expressions():
    """[(alert, expr)] for the rules that read a wildbox_* metric."""
    rules = yaml.safe_load(ALERT_RULES.read_text(encoding="utf-8"))
    found = [
        (rule["alert"], rule["expr"])
        for group in rules["groups"]
        for rule in group["rules"]
        if PREFIX in rule["expr"]
    ]
    assert found, "no rule reads a wildbox_* metric: nothing would be checked"
    return found


def _wildbox_metrics(checker, expr):
    return {m for m in checker.rule_metric_names(expr) if m.startswith(PREFIX)}


def test_every_wildbox_metric_in_the_rules_is_exported(scraped, expressions):
    checker = _checker()
    for alert, expr in expressions:
        metrics = _wildbox_metrics(checker, expr)
        assert metrics, f"{alert}: no wildbox_* metric read from {expr!r}"
        for metric in metrics:
            assert metric in scraped, f"{alert}: {metric} is not in /metrics"


def test_every_label_the_rules_match_exists_on_the_metric(scraped, expressions):
    checker = _checker()
    for alert, expr in expressions:
        for metric, labels in checker.rule_selectors(expr).items():
            if not metric.startswith(PREFIX):
                continue
            for label in labels:
                assert (
                    label in scraped[metric]
                ), f"{alert}: {metric} has no label {label!r} (it has {sorted(scraped[metric])})"


def test_every_label_the_rules_aggregate_on_exists(scraped, expressions):
    checker = _checker()
    for alert, expr in expressions:
        metrics = _wildbox_metrics(checker, expr)
        for label in checker.grouping_labels(expr):
            for metric in metrics:
                assert (
                    label in scraped[metric]
                ), f"{alert}: aggregates {metric} by {label!r}, a label it does not have"


def test_every_outcome_the_rules_name_is_one_the_service_reports(expressions):
    # `outcome="failure"` would load, match nothing and never fire.
    checker = _checker()
    reported = {
        "wildbox_tool_executions_total": {status.value for status in ExecutionStatus},
        "wildbox_tool_async_executions_total": set(async_metrics.OUTCOMES),
    }
    named = []
    for alert, expr in expressions:
        selectors = checker.rule_selectors(expr)
        for metric, outcomes in reported.items():
            for operator, value in selectors.get(metric, {}).get("outcome", []):
                assert operator in (
                    "=",
                    "!=",
                ), f"{alert}: check {operator}{value!r} by hand"
                assert value in outcomes, f"{alert}: no run ever has outcome {value!r}"
                named.append((metric, value))
    assert named == [
        ("wildbox_tool_executions_total", "failed"),
        ("wildbox_tool_async_executions_total", "failed"),
    ]


def test_the_execution_counter_has_the_labels_and_outcomes_the_rule_describes(scraped):
    executions = scraped["wildbox_tool_executions_total"]

    assert set(executions) == {"tool", "outcome"}
    # A failure reported inside the result is "completed": only a run that
    # raised is "failed", which is what the rule calls a failure.
    assert {"completed", "failed", "timeout"} <= executions["outcome"]


# What the rule's description says each outcome is, checked on the counter
# itself: one run per tool name, so each count is that run's and no other's.


def test_a_run_that_raises_a_handled_type_is_counted_failed():
    tool = f"{TOOL}_raises"

    assert _run(ToolExecutionManager(), _raises, tool).status is ExecutionStatus.FAILED
    assert _counted(tool) == {"failed": 1.0}


def test_a_run_that_raises_anything_else_is_counted_failed_too():
    # The manager catches five exception types by name. Any other leaves it
    # through the `finally` that counts, with the status it started with.
    tool = f"{TOOL}_raises_unexpected"

    with pytest.raises(RuntimeError):
        _run(ToolExecutionManager(), _raises_what_nothing_catches, tool)

    assert _counted(tool) == {"failed": 1.0}


def test_a_failure_reported_in_the_result_is_counted_completed():
    tool = f"{TOOL}_reports"

    _run(ToolExecutionManager(), _reports_a_failure_in_its_result, tool)

    assert _counted(tool) == {"completed": 1.0}


def test_a_run_past_its_time_limit_is_counted_timeout_not_failed():
    tool = f"{TOOL}_slow"

    _run(ToolExecutionManager(), _never_finishes, tool, timeout=0.05)

    assert _counted(tool) == {"timeout": 1.0}


def test_the_http_counter_has_the_labels_the_rule_reads(scraped):
    requests = scraped["wildbox_http_requests_total"]

    assert set(requests) == {"service", "method", "path", "status"}
    assert requests["service"] == {"tools"}
    assert "401" in requests["status"]  # a status code, as the rule's 5.. expects


# --- the asynchronous runs ------------------------------------------------------


def test_the_asynchronous_counter_has_the_labels_and_outcomes_the_rule_describes(
    scraped,
):
    executions = scraped["wildbox_tool_async_executions_total"]

    assert set(executions) == {"tool", "outcome"}
    assert executions["outcome"] == {
        "completed",
        "failed",
        "timeout",
        "cancelled",
        "refused",
    }
    assert ASYNC_TOOL in executions["tool"]


def test_the_queue_metrics_are_plain_numbers(scraped):
    # WildboxAsyncToolTasksNotConsumed compares them with `and on ()`: no
    # label of either may be needed to tell two series apart.
    for metric in (
        "wildbox_tool_async_queue_length",
        "wildbox_tool_async_tasks_consumed_total",
        "wildbox_tool_async_metrics_up",
    ):
        assert scraped[metric] == {}, metric


def test_a_synchronous_run_is_not_in_the_asynchronous_counter(async_counts):
    """Each alert measures its own runs: the two counters share nothing."""
    tool = f"{TOOL}_sync_only"
    before = dict(async_counts.read().outcomes)

    _run(ToolExecutionManager(), _raises, tool)

    assert _counted(tool) == {"failed": 1.0}
    assert async_counts.read().outcomes == before


def test_an_asynchronous_run_is_not_in_the_synchronous_counter(async_counts):
    # Not a tool of the service, so the asynchronous counter files it under
    # "unknown"; neither name may appear in the synchronous one.
    tool = f"{TOOL}_async_only"
    before = async_counts.read().outcomes.get(("unknown", "failed"), 0)

    async_metrics.record_outcome("task-1", tool, "failed")

    assert async_counts.read().outcomes[("unknown", "failed")] == before + 1
    assert _counted(tool) == {}
    assert _counted("unknown") == {}


def _seconds(duration):
    value, unit = re.fullmatch(r"(\d+)([smh])", duration).groups()
    return int(value) * {"s": 1, "m": 60, "h": 3600}[unit]


def test_no_task_can_run_for_as_long_as_the_queue_alert_waits():
    """What makes "queued and nothing taken for 15 minutes" mean a dead worker.

    A worker that is alive frees a child within the hard time limit and then
    takes the next task. If a task could run for the whole window, a busy
    worker would look like one that consumes nothing.
    """
    from app.celery_app import celery_app

    rules = yaml.safe_load(ALERT_RULES.read_text(encoding="utf-8"))
    (rule,) = [
        rule
        for group in rules["groups"]
        for rule in group["rules"]
        if rule["alert"] == "WildboxAsyncToolTasksNotConsumed"
    ]
    (window,) = re.findall(
        r"increase\(wildbox_tool_async_tasks_consumed_total\[(\w+)\]\)", rule["expr"]
    )
    hard_limit = celery_app.conf.task_time_limit

    assert celery_app.conf.task_soft_time_limit < hard_limit == 600
    assert hard_limit < _seconds(window) == 900
    # And the queue must have been non-empty for at least as long.
    assert _seconds(rule["for"]) >= _seconds(window)


def test_the_worker_reads_the_queue_the_api_measures():
    """The queue length is the length of the list the worker consumes.

    docker-compose.yml starts the worker without -Q, so it reads the app's
    default queue, which is also where the api sends the tasks.
    """
    from app.celery_app import celery_app

    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text("utf-8"))
    command = compose["services"]["tools-worker"]["command"]

    assert "celery -A app.celery_app worker" in command
    assert " -Q" not in command and "--queues" not in command
    assert celery_app.conf.task_default_queue == "celery"
    assert celery_app.conf.task_routes is None


# --- the broker's visibility timeout (#743) -------------------------------------


def test_the_visibility_timeout_is_a_setting_of_the_service():
    """It was kombu's default: an hour because a library said so."""
    from app.celery_app import VISIBILITY_TIMEOUT_SECONDS, celery_app

    assert VISIBILITY_TIMEOUT_SECONDS == 3600
    assert dict(celery_app.conf.broker_transport_options) == {
        "visibility_timeout": VISIBILITY_TIMEOUT_SECONDS
    }
    # And it is what a connection of the app is opened with.
    assert celery_app.connection().transport_options["visibility_timeout"] == 3600


def test_a_task_a_live_worker_holds_is_never_handed_to_a_second_one():
    """The timeout outlasts the longest a worker can hold a task.

    The broker gives a task to another worker when the first has held it,
    unacknowledged, for the visibility timeout. A retry waits in the
    worker's memory for up to retry_backoff_max and then runs for up to the
    hard time limit; if the timeout were shorter than that, a task still
    running would be started a second time.
    """
    from app.celery_app import VISIBILITY_TIMEOUT_SECONDS, celery_app
    from app.tasks import ToolExecutionTask

    longest_hold = ToolExecutionTask.retry_backoff_max + celery_app.conf.task_time_limit

    assert longest_hold == 1200
    assert VISIBILITY_TIMEOUT_SECONDS >= 2 * longest_hold


def test_the_documentation_states_the_configured_timeout():
    """The rule comment and the guides said "an hour" for a value nothing set."""
    from app.celery_app import VISIBILITY_TIMEOUT_SECONDS

    stated = f"{VISIBILITY_TIMEOUT_SECONDS} seconds"
    for path in (
        ALERT_RULES,
        REPO_ROOT / "docs" / "guides" / "deployment.md",
        REPO_ROOT / "docs" / "api" / "tools" / "endpoints.md",
    ):
        text = " ".join(path.read_text(encoding="utf-8").replace("#", " ").split())
        assert "visibility timeout" in text, path
        assert stated in text, path
        assert "broker_transport_options" in text, path
