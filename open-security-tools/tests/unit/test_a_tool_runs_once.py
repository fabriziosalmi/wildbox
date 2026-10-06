"""A tool is called once, however it fails (#774).

Two layers called a failing tool again:

* ``app.security_integration``, on the synchronous path, with
  ``SECURITY_CONTROLS_ENABLED`` and outside strict mode: the tool was called
  inside the handler meant for a failed check, so a ValueError, KeyError,
  TypeError, ConnectionError or TimeoutError of the tool's own was taken for
  one and the tool was called a second time, "without security";
* the Celery task: any other class (a RuntimeError, an OSError) was raised
  to Celery, whose retry policy called the tool twice more.

A second call is a second scan of someone's host, and a second time whatever
else the tool does. The first failure was never reported: the caller read
the outcome of the last call. These tests count the calls, in every mode
and on every path, and check that the caller reads the tool's own error.

They also pin what a failed check does, which is the one thing the two
modes of the security layer differ in, and what a task that fails outside
its tool leaves behind: the class and the line, never the text.
"""

import asyncio
import logging
import os
import sys
import uuid

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

pytest.importorskip("celery")

from app import security_integration as integration_module  # noqa: E402
from app import tasks  # noqa: E402
from app.api import async_router  # noqa: E402
from app.execution_manager import ExecutionStatus, ToolExecutionManager  # noqa: E402
from app.security_integration import SecurityIntegration  # noqa: E402
from pydantic import BaseModel  # noqa: E402

TOOL = "counting_tool"
MARKER = "do-not-keep-" + uuid.uuid4().hex

# The classes the security layer took for a failed check of its own.
MISTAKEN = [ValueError, KeyError, TypeError, ConnectionError, TimeoutError]
# Classes the Celery task did not catch, and so retried.
RETRIED = [RuntimeError, OSError, ZeroDivisionError]

STRICT = "strict"
GRACEFUL = "graceful"
OFF = "off"


class CountingInput(BaseModel):
    target_url: str = "https://example.com/"


class CountingOutput(BaseModel):
    ok: bool = True


class Counted:
    """A tool that counts its calls and fails the way the test asks."""

    def __init__(self, error, recover=False):
        self.error = error
        self.recover = recover
        self.calls = 0

    def _call(self):
        self.calls += 1
        if self.recover and self.calls > 1:
            return CountingOutput()
        raise self.error(f"call {self.calls} failed over {MARKER}")

    def sync(self, data):
        return self._call()

    async def coroutine(self, data):
        return self._call()

    def as_written(self, kind):
        return self.sync if kind == "sync" else self.coroutine


def layer(mode, monkeypatch):
    """The security layer in one of its modes, with its real components."""
    monkeypatch.setenv("SECURITY_CONTROLS_ENABLED", "false" if mode == OFF else "true")
    monkeypatch.setenv("SECURITY_STRICT_MODE", "true" if mode == STRICT else "false")
    return SecurityIntegration()


# --- the security layer: the tool's own failure -----------------------------------


@pytest.mark.parametrize("error", MISTAKEN + RETRIED)
@pytest.mark.parametrize("mode", [STRICT, GRACEFUL])
@pytest.mark.parametrize("kind", ["sync", "coroutine"])
def test_the_layer_calls_a_failing_tool_once(mode, kind, error, monkeypatch):
    tool = Counted(error)
    secured = layer(mode, monkeypatch).secure_tool_execution(TOOL)(
        tool.as_written(kind)
    )

    with pytest.raises(error) as raised:
        asyncio.run(secured(CountingInput()))

    assert tool.calls == 1
    # The tool's own error, as it was raised: of the first call, not a later one.
    assert raised.value.args == (f"call 1 failed over {MARKER}",)


@pytest.mark.parametrize("mode", [STRICT, GRACEFUL])
def test_a_failure_is_not_hidden_by_a_second_call_that_would_succeed(mode, monkeypatch):
    """The second call used to answer for the first: the caller read
    "completed" for a tool that had failed once and run twice."""
    tool = Counted(ValueError, recover=True)
    secured = layer(mode, monkeypatch).secure_tool_execution(TOOL)(tool.sync)

    with pytest.raises(ValueError):
        asyncio.run(secured(CountingInput()))

    assert tool.calls == 1


@pytest.mark.parametrize("error", [ValueError, KeyError, TypeError, ConnectionError])
@pytest.mark.parametrize("mode", [OFF, STRICT, GRACEFUL])
def test_the_synchronous_path_calls_a_failing_tool_once(mode, error, monkeypatch):
    """Through the execution manager, which is what wraps the tool."""
    monkeypatch.setattr(
        integration_module, "security_integration", layer(mode, monkeypatch)
    )
    tool = Counted(error)

    result = asyncio.run(
        ToolExecutionManager().execute_tool(tool.sync, CountingInput(), TOOL)
    )

    assert tool.calls == 1
    assert result.status is ExecutionStatus.FAILED
    assert result.error == str(error(f"call 1 failed over {MARKER}"))


# --- the security layer: a failed check -----------------------------------------------


class FailingValidator:
    """A check that fails with what the test gives it."""

    def __init__(self, error):
        self.error = error
        self.asked = 0

    def validate_url(self, url, allow_private=False):
        self.asked += 1
        raise self.error(f"the check failed over {MARKER}")


def returning_tool():
    calls = []

    def tool(data):
        calls.append(data)
        return CountingOutput()

    return tool, calls


@pytest.mark.parametrize("error", MISTAKEN)
def test_in_strict_mode_a_failed_check_stops_the_run(error, monkeypatch, caplog):
    strict = layer(STRICT, monkeypatch)
    strict.validator = FailingValidator(error)
    tool, calls = returning_tool()

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(error) as raised:
            asyncio.run(strict.secure_tool_execution(TOOL)(tool)(CountingInput()))

    assert calls == []
    assert strict.validator.asked == 1
    # The failure of the check is what the caller of the layer gets.
    assert raised.value.args == (f"the check failed over {MARKER}",)
    (record,) = [r for r in caplog.records if "Security check failed" in r.message]
    assert record.levelno == logging.ERROR
    assert "the tool is not run" in record.message
    assert MARKER not in record.message


@pytest.mark.parametrize("error", MISTAKEN)
def test_outside_strict_mode_a_failed_check_is_logged_and_the_tool_runs_once(
    error, monkeypatch, caplog
):
    """What the service calls "graceful" when it starts: the one difference
    between the modes. It is an error in the log, not a silent pass."""
    graceful = layer(GRACEFUL, monkeypatch)
    graceful.validator = FailingValidator(error)
    tool, calls = returning_tool()

    with caplog.at_level(logging.DEBUG):
        result = asyncio.run(
            graceful.secure_tool_execution(TOOL)(tool)(CountingInput())
        )

    assert result == CountingOutput()
    assert len(calls) == 1
    assert graceful.validator.asked == 1
    (record,) = [r for r in caplog.records if "Security check failed" in r.message]
    assert record.levelno == logging.ERROR
    assert TOOL in record.message
    assert "the tool runs WITHOUT this check" in record.message
    assert record.message.split(": ", 1)[1].startswith(f"{error.__name__} at ")
    assert MARKER not in record.message


def test_a_failed_check_and_a_failing_tool_are_one_call_and_the_tools_error(
    monkeypatch,
):
    graceful = layer(GRACEFUL, monkeypatch)
    graceful.validator = FailingValidator(ValueError)
    tool = Counted(ValueError)

    with pytest.raises(ValueError) as raised:
        asyncio.run(graceful.secure_tool_execution(TOOL)(tool.sync)(CountingInput()))

    assert tool.calls == 1
    assert raised.value.args == (f"call 1 failed over {MARKER}",)


@pytest.mark.parametrize("mode", [STRICT, GRACEFUL])
def test_a_check_that_breaks_in_another_way_stops_the_run_in_both_modes(
    mode, monkeypatch
):
    """Not one of the errors a check answers with: nothing is known about
    the input, and the tool is not run on it."""
    integration = layer(mode, monkeypatch)
    integration.validator = FailingValidator(RuntimeError)
    tool, calls = returning_tool()

    with pytest.raises(RuntimeError):
        asyncio.run(integration.secure_tool_execution(TOOL)(tool)(CountingInput()))

    assert calls == []


@pytest.mark.parametrize("mode,runs", [(STRICT, 0), (GRACEFUL, 1)])
def test_the_real_check_refuses_a_target_url_that_is_no_http_url(
    mode, runs, monkeypatch
):
    """With the layer's own validator, not a stand-in."""
    integration = layer(mode, monkeypatch)
    tool, calls = returning_tool()
    secured = integration.secure_tool_execution(TOOL)(tool)
    refused = CountingInput(target_url="ftp://example.com/")

    if mode == STRICT:
        with pytest.raises(ValueError, match="Invalid URL format"):
            asyncio.run(secured(refused))
    else:
        asyncio.run(secured(refused))

    assert len(calls) == runs
    # An accepted one runs in both modes.
    asyncio.run(secured(CountingInput()))
    assert len(calls) == runs + 1


# --- the Celery task ----------------------------------------------------------------------


@pytest.fixture
def task(monkeypatch):
    """The task, run in this process with Celery's retries applied at once."""
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kw: None)

    def run(tool, **input_data):
        schemas = type(
            "schemas",
            (),
            {"CountingInput": CountingInput, "CountingOutput": CountingOutput},
        )
        module = type(
            "module", (), {"schemas": schemas, "execute_tool": staticmethod(tool)}
        )
        monkeypatch.setattr(tasks, "_load_tool_module", lambda name: module)
        return tasks.execute_tool_async.apply(
            kwargs={"tool_name": TOOL, "input_data": input_data}
        )

    return run


@pytest.mark.parametrize("error", MISTAKEN + RETRIED)
@pytest.mark.parametrize("mode", [OFF, STRICT, GRACEFUL])
@pytest.mark.parametrize("kind", ["sync", "coroutine"])
def test_the_task_calls_a_failing_tool_once(
    mode, kind, error, task, monkeypatch, caplog
):
    monkeypatch.setattr(
        integration_module, "security_integration", layer(mode, monkeypatch)
    )
    tool = Counted(error)

    with caplog.at_level(logging.DEBUG):
        outcome = task(tool.as_written(kind))

    assert tool.calls == 1
    # Returned, not raised: nothing for Celery to retry.
    assert outcome.state == "SUCCESS", outcome.result
    assert outcome.result["status"] == "failed"
    assert outcome.result["error"] == f"Tool execution failed ({error.__name__})"
    # Neither what Redis keeps nor what the worker logs has the error's text.
    assert MARKER not in str(outcome.result)
    assert outcome.traceback is None
    for record in caplog.records:
        assert MARKER not in record.getMessage()
        assert MARKER not in str(record.__dict__)
    (record,) = [
        r
        for r in caplog.records
        if r.getMessage().startswith("Async tool execution failed")
    ]
    assert record.error_type.startswith(f"{error.__name__} at ")


def test_a_tool_that_fails_after_it_returned_is_not_called_again(task):
    """What the task does with the tool's output is after the call too."""

    class Unprintable:
        def __str__(self):
            raise RuntimeError(f"cannot print {MARKER}")

    calls = []

    def tool(data):
        calls.append(data)
        return Unprintable()

    outcome = task(tool)

    assert len(calls) == 1
    assert outcome.state == "SUCCESS"
    assert outcome.result["error"] == "Tool execution failed (RuntimeError)"


def test_a_task_that_fails_before_its_tool_is_retried_and_never_calls_it(
    task, monkeypatch, caplog
):
    """A retry is safe there: the tool has not run. What Celery stores and
    logs of the failure is the class and the line, not the text."""
    asked = []

    def unavailable(execute, tool_name, validated, user_id):
        asked.append(tool_name)
        raise RuntimeError(f"the allowance of {MARKER} cannot be counted")

    monkeypatch.setattr(tasks, "authorize_tool_call", unavailable)
    tool, calls = returning_tool()

    with caplog.at_level(logging.DEBUG):
        outcome = task(tool)

    assert calls == []
    # The first start and the two retries of the task's policy.
    assert len(asked) == 3
    assert outcome.state == "FAILURE"
    failure = outcome.result
    assert type(failure) is tasks.TaskFailed
    (site,) = failure.args
    assert site.startswith("RuntimeError at test_a_tool_runs_once.py:")
    assert site.endswith(" in unavailable")
    # Nothing Celery keeps of it has the text: the exception, its context,
    # the traceback.
    assert failure.__cause__ is None and failure.__context__ is None
    assert MARKER not in repr(failure)
    assert MARKER not in outcome.traceback
    assert "TaskFailed: RuntimeError at " in outcome.traceback
    for record in caplog.records:
        assert MARKER not in record.getMessage()
        assert MARKER not in str(record.__dict__)
    ours = [
        r
        for r in caplog.records
        if r.getMessage().startswith("Async tool execution failed before its tool ran")
    ]
    assert len(ours) == 3
    assert {r.error_type for r in ours} == {site}


def test_an_error_of_the_request_before_the_tool_is_answered_and_not_retried(
    task, monkeypatch
):
    """As before: one of the five classes, raised before the tool, is the
    request's own error. The same request would fail the same way."""
    asked = []

    def refuses(execute, tool_name, validated, user_id):
        asked.append(tool_name)
        raise ValueError(f"cannot authorize {MARKER}")

    monkeypatch.setattr(tasks, "authorize_tool_call", refuses)
    tool, calls = returning_tool()

    outcome = task(tool)

    assert calls == [] and len(asked) == 1
    assert outcome.state == "SUCCESS"
    assert outcome.result["error"] == "Tool execution failed (ValueError)"
    assert MARKER not in str(outcome.result)


def test_a_cancelled_task_is_still_ignored_and_not_a_failure(task, monkeypatch):
    """Celery's own signals pass through the handler that replaces errors."""
    from celery.exceptions import Ignore

    def cancelled(self, *args):
        raise Ignore()

    monkeypatch.setattr(tasks, "_execute_tool_task", cancelled)

    with pytest.raises(Ignore):
        tasks.execute_tool_async.run(tool_name=TOOL, input_data={})


# --- what the owner of a failed task reads -------------------------------------------------


@pytest.mark.parametrize(
    "stored,name",
    [
        # As Celery stores a TaskFailed with the JSON serializer.
        (
            {
                "exc_type": "TaskFailed",
                "exc_message": ["RedisError at task_ownership.py:120 in is_cancelled"],
                "exc_module": "app.tasks",
            },
            "RedisError",
        ),
        (
            tasks.TaskFailed("RateLimitUnavailable at rate_limit.py:95 in allow"),
            "RateLimitUnavailable",
        ),
        # error_site of an exception that has no traceback is its class.
        ({"exc_type": "TaskFailed", "exc_message": ["KeyError"]}, "KeyError"),
        # Any other exception is named as it was.
        ({"exc_type": "TimeLimitExceeded", "exc_message": [600]}, "TimeLimitExceeded"),
        # An argument that is no site names nothing but the class it has.
        (
            {"exc_type": "TaskFailed", "exc_message": [f"{MARKER} and more"]},
            "TaskFailed",
        ),
        ({"exc_type": "TaskFailed", "exc_message": [f"<{MARKER}>"]}, "TaskFailed"),
        ({"exc_type": "TaskFailed", "exc_message": []}, "TaskFailed"),
        ({"exc_type": "TaskFailed", "exc_message": [7]}, "TaskFailed"),
        ({"exc_type": "TaskFailed"}, "TaskFailed"),
    ],
)
def test_the_api_names_the_class_that_failed_the_task(stored, name):
    assert async_router._failure_name(stored) == name
    assert async_router._failure_message(stored) == f"Task execution failed ({name})"
