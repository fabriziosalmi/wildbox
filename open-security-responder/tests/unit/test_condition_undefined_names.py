"""What a step condition does with a name that is not defined (#595).

A condition that references an undefined name evaluates to false, so the
step is skipped, and the run log says which reference was undefined. Every
other template error in a condition still raises, and action inputs stay
strict: an undefined name there is an error, as before.
"""

import logging
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

from app.workflow_engine import TemplateRenderError, WorkflowEngine  # noqa: E402

# A value that must never reach a log line.
SENSITIVE = "s3cr3t-value-0123456789"

CONTEXT = {
    "trigger": {"ip": "192.168.1.100", "token": SENSITIVE},
    "steps": {"validate_ip": {"output": {"valid": True}}},
}


@pytest.fixture
def engine():
    """An engine whose run log is a list instead of Redis."""
    engine = WorkflowEngine.__new__(WorkflowEngine)
    engine.run_log = []
    engine.add_log = lambda run_id, message, level="INFO": engine.run_log.append(
        (run_id, level, message)
    )
    return engine


def test_an_undefined_name_is_false_and_logged(engine, caplog):
    with caplog.at_level(logging.WARNING, logger="app.workflow_engine"):
        result = engine.evaluate_condition(
            "trigger.no_such_field == 'x'", CONTEXT, run_id="run-1"
        )

    assert result is False
    assert engine.run_log == [
        (
            "run-1",
            "WARNING",
            "Condition references an undefined name ('trigger.no_such_field'); "
            "evaluating it as false",
        )
    ]
    assert "trigger.no_such_field" in caplog.text


def test_an_undefined_top_level_name_is_false(engine):
    assert engine.evaluate_condition("no_such_name", CONTEXT, run_id="r") is False
    assert "'no_such_name'" in engine.run_log[0][2]


def test_a_defined_name_is_evaluated(engine):
    assert engine.evaluate_condition("trigger.ip == '192.168.1.100'", CONTEXT) is True
    assert engine.evaluate_condition("trigger.ip == '10.0.0.1'", CONTEXT) is False
    assert engine.evaluate_condition("steps.validate_ip.output.valid", CONTEXT) is True
    assert engine.run_log == []


def test_a_nested_undefined_attribute_is_false(engine):
    """The first missing link is the one reported, not the last."""
    result = engine.evaluate_condition(
        "trigger.no_such_field.deeper == 1", CONTEXT, run_id="r"
    )
    assert result is False
    assert "'trigger.no_such_field'" in engine.run_log[0][2]


def test_an_undefined_step_output_is_false(engine):
    result = engine.evaluate_condition(
        "steps.validate_ip.output.score > 5", CONTEXT, run_id="r"
    )
    assert result is False
    assert "'steps.validate_ip.output.score'" in engine.run_log[0][2]


def test_the_log_never_carries_a_value(engine):
    """A key computed from the context is not spelled out: it is a value."""
    result = engine.evaluate_condition("trigger[trigger.token]", CONTEXT, run_id="r")
    assert result is False
    assert SENSITIVE not in engine.run_log[0][2]
    assert "a key computed at run time" in engine.run_log[0][2]


def test_is_defined_still_guards_an_optional_field(engine):
    assert engine.evaluate_condition("trigger.no_such_field is defined", CONTEXT) is (
        False
    )
    assert engine.run_log == []


def test_a_syntax_error_still_raises(engine):
    with pytest.raises(TemplateRenderError, match="not a valid expression"):
        engine.evaluate_condition("trigger.ip ==", CONTEXT, run_id="r")
    assert engine.run_log == []


def test_a_braced_condition_is_a_syntax_error(engine):
    """`{{ }}` inside `{% if %}` is not an expression; it must not read as false."""
    with pytest.raises(TemplateRenderError):
        engine.evaluate_condition("{{ trigger.no_such_field }}", CONTEXT)


def test_a_sandbox_violation_still_raises(engine):
    """`__self__` is not in the blocked-pattern list; the sandbox stops it."""
    with pytest.raises(TemplateRenderError, match="blocked by sandbox"):
        engine.evaluate_condition("trigger.keys.__self__", CONTEXT, run_id="r")
    assert engine.run_log == []


def test_an_undefined_name_in_an_action_input_still_raises(engine):
    with pytest.raises(TemplateRenderError, match="no_such_field"):
        engine.render_step_input({"value": "{{ trigger.no_such_field }}"}, CONTEXT)


def test_a_defined_name_in_an_action_input_renders(engine):
    rendered = engine.render_step_input({"value": "{{ trigger.ip }}"}, CONTEXT)
    assert rendered == {"value": "192.168.1.100"}


def test_a_run_skips_the_step_and_carries_on(monkeypatch):
    """Through the actor: the step is skipped, the run completes, the log says why."""
    from app import workflow_engine as module
    from app.models import Playbook

    playbook = Playbook(
        playbook_id="optional_field",
        name="optional field",
        trigger={"type": "api"},
        steps=[
            {
                "name": "only_when_tagged",
                "action": "system.log",
                "input": {"message": "tagged"},
                "condition": "trigger.tag == 'urgent'",
            },
            {
                "name": "always",
                "action": "system.log",
                "input": {"message": "{{ trigger.ip }}"},
            },
        ],
    )
    run_log = []
    executed = []
    engine = module.workflow_engine
    monkeypatch.setattr(module.playbook_parser, "playbooks", {"x": playbook})
    monkeypatch.setattr(module.playbook_parser, "get_playbook", lambda _id: playbook)
    monkeypatch.setattr(engine, "get_execution_state", lambda run_id: None)
    monkeypatch.setattr(engine, "save_execution_state", lambda run_id, result: None)
    monkeypatch.setattr(
        engine,
        "add_log",
        lambda run_id, message, level="INFO": run_log.append((run_id, level, message)),
    )
    monkeypatch.setattr(
        module.connector_registry,
        "execute_action",
        lambda connector, action, params: executed.append(params) or {"ok": True},
    )

    result = module.execute_playbook_actor.fn(
        "run-7", "optional_field", {"ip": "192.168.1.100"}
    )

    assert result["status"] == "completed"
    assert result["step_results"][0]["output"] == {
        "skipped": True,
        "reason": "condition_failed",
    }
    assert executed == [{"message": "192.168.1.100"}]
    assert (
        "run-7",
        "WARNING",
        "Condition references an undefined name ('trigger.tag'); "
        "evaluating it as false",
    ) in run_log
