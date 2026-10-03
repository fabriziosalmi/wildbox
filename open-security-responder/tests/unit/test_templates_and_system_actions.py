"""Step templates, conditions and the system connector's actions (#582).

These come from test_advanced.py, test_basic.py and test_e2e.py at the root of
this service, which CI never ran (the Unit Tests job collects tests/unit only)
and which could not fail: each wrapped its checks in a try/except that printed
the error and carried on. What they covered that is not already in
test_playbooks_are_executable.py is checked here against the engine itself;
test_e2e.py re-implemented the execution loop instead of calling it, so the
parts of it worth keeping are the rendering and the actions below.
"""

import os
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

from app.connectors import connector_registry  # noqa: E402
from app.workflow_engine import TemplateRenderError, WorkflowEngine  # noqa: E402

CONTEXT = {
    "trigger": {"ip": "192.168.1.100", "message": "Test message"},
    "steps": {"validate_ip": {"output": {"valid": True, "version": 4}}},
}


@pytest.fixture
def engine():
    return WorkflowEngine()


# --- Templates -------------------------------------------------------------


def test_a_template_reads_the_trigger(engine):
    assert (
        engine.render_template("IP: {{ trigger.ip }}", CONTEXT) == "IP: 192.168.1.100"
    )


def test_a_template_reads_an_earlier_steps_output(engine):
    rendered = engine.render_template(
        "Valid: {{ steps.validate_ip.output.valid }}", CONTEXT
    )
    assert rendered == "Valid: True"


def test_a_value_that_is_not_a_string_is_passed_through(engine):
    assert engine.render_template(42, CONTEXT) == 42


def test_step_input_is_rendered_at_every_level(engine):
    rendered = engine.render_step_input(
        {
            "target": "{{ trigger.ip }}",
            "metadata": {"source": "test", "note": "{{ trigger.message }}"},
            "targets": ["{{ trigger.ip }}", 7],
            "retries": 3,
        },
        CONTEXT,
    )
    assert rendered == {
        "target": "192.168.1.100",
        "metadata": {"source": "test", "note": "Test message"},
        "targets": ["192.168.1.100", 7],
        "retries": 3,
    }


@pytest.mark.parametrize(
    "template", ["{{ trigger.no_such_field }}", "{{ steps.no_such_step.output }}"]
)
def test_a_reference_to_nothing_is_an_error_not_an_empty_string(engine, template):
    # StrictUndefined: a misspelt name must not render as "" and run the step
    # with an empty argument.
    with pytest.raises(TemplateRenderError):
        engine.render_template(template, CONTEXT)


@pytest.mark.parametrize(
    "template",
    [
        "{{ trigger.__class__ }}",
        "{{ ''.__class__.__mro__ }}",
        "{{ cycler.__init__.__globals__ }}",
    ],
)
def test_a_template_reaching_for_python_internals_is_refused(engine, template):
    with pytest.raises(TemplateRenderError):
        engine.render_template(template, CONTEXT)


# --- Conditions ------------------------------------------------------------


def test_a_condition_that_holds_is_true(engine):
    assert engine.evaluate_condition("trigger.ip == '192.168.1.100'", CONTEXT) is True


def test_a_condition_that_does_not_hold_is_false(engine):
    assert engine.evaluate_condition("trigger.ip == '10.0.0.1'", CONTEXT) is False


def test_a_condition_on_an_earlier_step_is_evaluated(engine):
    assert engine.evaluate_condition("steps.validate_ip.output.valid", CONTEXT) is True


def test_no_condition_means_the_step_runs(engine):
    assert engine.evaluate_condition("", CONTEXT) is True


def test_a_condition_reaching_for_python_internals_is_false(engine):
    assert engine.evaluate_condition("trigger.__class__", CONTEXT) is False


# --- System connector ------------------------------------------------------


def run(action, **params):
    return connector_registry.execute_action("system", action, params)


def test_log_reports_what_it_logged():
    result = run("log", message="hello", level="warning")
    assert result["status"] == "logged"
    assert result["message"] == "hello"
    assert result["level"] == "warning"


def test_log_falls_back_to_info_for_an_unknown_level():
    assert run("log", message="hello", level="loud")["level"] == "info"


@pytest.mark.parametrize(
    "kind, value, valid",
    [
        ("ip_address", "192.168.1.1", True),
        ("ip_address", "999.1.1.1", False),
        ("url", "https://example.com/a", True),
        ("url", "example.com", False),
        ("email", "a@example.com", True),
        ("email", "not-an-email", False),
        ("domain", "example.com", True),
        ("domain", "-bad-.com", False),
        ("hash", "d41d8cd98f00b204e9800998ecf8427e", True),
        ("hash", "d41d8cd9", False),
    ],
)
def test_validate_tells_valid_from_invalid(kind, value, valid):
    result = run("validate", type=kind, value=value)
    assert result["valid"] is valid
    assert result["type"] == kind


def test_validate_reports_the_ip_version_and_scope():
    details = run("validate", type="ip_address", value="192.168.1.1")["details"]
    assert details["version"] == 4
    assert details["is_private"] is True


def test_validate_refuses_an_unknown_type_and_names_the_known_ones():
    result = run("validate", type="colour", value="red")
    assert result["valid"] is False
    assert "ip_address" in result["supported_types"]


def test_timestamp_returns_the_requested_format():
    result = run("timestamp", format="unix")
    assert isinstance(result["timestamp"], int)
    assert result["timestamp"] == result["all_formats"]["unix"]


def test_a_step_output_feeds_the_next_steps_condition(engine):
    """The chain test_e2e.py simulated by hand: validate, then branch on it."""
    context = {"trigger": {"ip": "192.168.1.1"}, "steps": {}}
    step_input = engine.render_step_input(
        {"type": "ip_address", "value": "{{ trigger.ip }}"}, context
    )
    context["steps"]["validate_ip"] = {"output": run("validate", **step_input)}
    assert engine.evaluate_condition("steps.validate_ip.output.valid", context) is True

    context["trigger"]["ip"] = "not-an-ip"
    step_input = engine.render_step_input(
        {"type": "ip_address", "value": "{{ trigger.ip }}"}, context
    )
    context["steps"]["validate_ip"] = {"output": run("validate", **step_input)}
    assert engine.evaluate_condition("steps.validate_ip.output.valid", context) is False
