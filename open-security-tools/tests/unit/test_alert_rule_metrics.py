"""The alert rules read metrics this service really exports (#658).

Prometheus loads a rule on a metric or a label that does not exist without a
word: the expression is empty for ever and the alert can never fire. So this
runs the service, produces every outcome a synchronous tool run can have,
scrapes ``/metrics`` and checks each ``wildbox_*`` selector in
``monitoring/alert_rules.yml`` against what was scraped: the metric, the
labels it matches or aggregates on, and the label values it names.

It also pins what ``wildbox_tool_executions_total`` counts, because the rule
``WildboxSyncToolFailureRate`` is named and described for it: runs the api
process executes, by outcome. Asynchronous runs execute in the worker, which
exports no metrics.
"""

import asyncio
import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

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
def scraped():
    """{metric: {label: {values}}} from /metrics after every sync outcome."""
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
    outcomes = {status.value for status in ExecutionStatus}
    named = []
    for alert, expr in expressions:
        selectors = checker.rule_selectors(expr)
        for operator, value in selectors.get("wildbox_tool_executions_total", {}).get(
            "outcome", []
        ):
            assert operator in (
                "=",
                "!=",
            ), f"{alert}: check {operator}{value!r} by hand"
            assert value in outcomes, f"{alert}: no run ever has outcome {value!r}"
            named.append(value)
    assert named == ["failed"]


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


def test_an_asynchronous_run_is_not_counted():
    # The rule says so; this is why. The Celery task records nothing in the
    # counter, and the worker serves no /metrics for Prometheus to read.
    source = (Path(__file__).resolve().parents[2] / "app" / "tasks.py").read_text()
    told = (
        "the worker now counts runs: rename WildboxSyncToolFailureRate and "
        "rewrite its description in monitoring/alert_rules.yml, which say "
        "asynchronous runs are not measured"
    )

    assert "TOOL_EXECUTIONS" not in source, told
    assert "outcome_counter" not in source, told
