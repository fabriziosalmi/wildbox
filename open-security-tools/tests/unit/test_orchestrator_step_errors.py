"""A workflow step that fails inside the service does not show how.

The orchestrator runs other tools as the steps of a workflow and returns each
step's error in the workflow result. For a failure of the service itself the
error was the text of the exception: the connection error of a 503, with the
address it could not reach, the class name of whatever a 500 came from, the
module path of an import that failed. Those go to the log now. What the
caller got wrong (a refused target, a parameter of the wrong type) is still
said in full.
"""

import asyncio
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.tools.security_automation_orchestrator.main as orchestrator  # noqa: E402
from app.tools.network_port_scanner import main as scanner  # noqa: E402
from app.tools.security_automation_orchestrator.schemas import (  # noqa: E402
    AutomationWorkflowInput,
)

UNAVAILABLE = "Tool execution failed: a service it needs is unavailable"
INTERNAL = "Internal error executing tool"


def run_step(monkeypatch, failure=None, parameters=None, tool="network_port_scanner"):
    """Run a one-step workflow; return the step's result."""

    async def execute(_input):
        if failure is not None:
            raise failure
        return {"success": True}

    monkeypatch.setattr(scanner, "execute_tool", execute)
    # The target policy has its own tests; here every target is allowed.
    monkeypatch.setattr(orchestrator, "enforce_target_policy", lambda *_: None)
    workflow = AutomationWorkflowInput(
        workflow_name="wf",
        trigger_type="manual",
        workflow_steps=[
            {"tool": tool, "parameters": parameters or {"target": "example.com"}}
        ],
        execution_mode="sequential",
    )
    output = asyncio.run(orchestrator.execute_tool(workflow))
    return output.workflow_execution.step_results[0]


@pytest.mark.parametrize(
    "failure, message",
    [
        (ConnectionError("connect to cache-7.internal:6379 refused"), UNAVAILABLE),
        (TimeoutError("no answer from 10.20.30.40 in 5 s"), UNAVAILABLE),
        (RuntimeError("/app/app/tools/x/main.py: unexpected state"), INTERNAL),
        (OSError("[Errno 13] Permission denied: '/var/lib/wildbox/key'"), INTERNAL),
    ],
    ids=lambda value: type(value).__name__ if isinstance(value, Exception) else None,
)
def test_a_failure_of_the_service_is_reported_without_its_cause(
    monkeypatch, caplog, failure, message
):
    with caplog.at_level("ERROR"):
        step = run_step(monkeypatch, failure)

    assert step.status == "failed"
    assert step.error_message == message
    # Neither the text of the exception nor its class.
    assert str(failure) not in step.error_message
    assert type(failure).__name__ not in step.error_message
    # The log has both, for whoever operates the service.
    assert str(failure) in caplog.text


def test_a_tool_that_cannot_be_imported_is_not_found_without_the_module_path(
    monkeypatch, caplog
):
    def no_schemas(name, *args, **kwargs):
        raise ImportError(f"No module named '{name}'")

    monkeypatch.setattr(orchestrator.importlib, "import_module", no_schemas)
    with caplog.at_level("ERROR"):
        step = run_step(monkeypatch)

    assert step.status == "failed"
    assert step.error_message == "Tool 'network_port_scanner' has no input schema"
    assert "No module named" in caplog.text


def test_what_the_caller_got_wrong_is_still_said(monkeypatch):
    step = run_step(monkeypatch, parameters={"target": "example.com", "ports": 7})

    assert step.status == "failed"
    assert step.error_message == (
        "Invalid parameters for 'network_port_scanner': "
        "ports: Input should be a valid string"
    )


def test_a_refused_parameter_is_named_and_not_quoted(monkeypatch):
    # str() of pydantic's error, which the step used to report, quotes every
    # value it refused: a parameter can be a credential.
    refused = {"nested": "token-9f3a-not-for-the-result"}
    step = run_step(monkeypatch, parameters={"target": "example.com", "ports": refused})

    assert step.status == "failed"
    assert step.error_message.startswith(
        "Invalid parameters for 'network_port_scanner': ports:"
    )
    assert "token-9f3a" not in step.error_message
    assert "input_value" not in step.error_message


def test_a_step_that_succeeds_is_unchanged(monkeypatch):
    step = run_step(monkeypatch)

    assert step.status == "completed"
    assert step.error_message is None
