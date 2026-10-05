"""What is checked before a tool runs, in one place (#743).

Three things are settled before a run exists: that the name is a tool, that
the input is what the tool's own model accepts, and that the target is one a
tool may be pointed at (``app.target_policy``). The synchronous route did all
three and answered 404, 422 and 400. The asynchronous submission did none:
it queued whatever it was given and answered 202, and the caller read the
refusal back from the task as ``failed``, after the request had taken a place
in the queue and a worker. The Celery task carried a second copy of the
checks, which was the only one the asynchronous path had.

Now the synchronous route, the asynchronous submission and the task call the
functions below, so the three cannot drift apart:

* ``check_tool_input``: the input and the target, for a tool whose module the
  caller already holds (the synchronous route is registered per tool);
* ``check_tool_request``: the same, after finding the tool by name;
* ``http_error``: the answer both routes give for each refusal.

The task checks again when it runs, because the answer can change between
submission and run: a host name resolves to another address, the operator's
allowlist changes, a deployment removes a tool. Whether the caller may run a
tool that acts for them (``authorize_tool_call``) is decided at run time only,
on both paths: it takes one of the caller's hourly allowances, which a
submission must not spend.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from app.target_policy import TargetRefused, enforce_target_policy
from app.tool_loader import find_schema_classes, load_tool_module
from fastapi import HTTPException, status
from pydantic import ValidationError

TOOL_NOT_FOUND = "Tool not found"
INPUT_INVALID = "Input validation failed"


class UnknownTool(LookupError):
    """No usable tool has this name."""

    def __init__(self, reason: str = TOOL_NOT_FOUND):
        super().__init__(reason)


class InvalidToolInput(ValueError):
    """The tool's input model refuses the input.

    ``errors`` lists where and why, without the values that were refused (a
    field may hold a credential); None when the model raised something other
    than a validation error.
    """

    def __init__(self, errors: Optional[List[Dict[str, Any]]] = None):
        super().__init__(INPUT_INVALID)
        self.errors = errors


# What a caller is refused for before a run exists.
PRE_RUN_REFUSALS = (UnknownTool, InvalidToolInput, TargetRefused)


@dataclass
class ToolRequest:
    """A request that passed: the tool to call and its validated input."""

    tool_name: str
    module: Any
    execute: Callable
    validated_input: Any


def input_field_errors(error: ValidationError) -> List[Dict[str, Any]]:
    """The location, message and type of each validation error, nothing else.

    Pydantic's own error list also carries the rejected input and, for a
    custom validator, the exception object in ``ctx``: the first can be a
    secret, the second is not JSON.
    """
    return [
        {"loc": list(item["loc"]), "msg": item["msg"], "type": item["type"]}
        for item in error.errors(include_url=False)
    ]


def check_tool_input(tool_name: str, tool_module: Any, input_data: Any) -> ToolRequest:
    """Validate the input of a known tool and apply the target policy.

    Raises UnknownTool when the module cannot be run (no ``execute_tool``, no
    input model), InvalidToolInput and TargetRefused. The target policy
    resolves host names, so call this off the event loop.
    """
    execute = getattr(tool_module, "execute_tool", None)
    input_model, _ = find_schema_classes(getattr(tool_module, "schemas", None))
    if execute is None or input_model is None:
        raise UnknownTool()
    if not isinstance(input_data, dict):
        raise InvalidToolInput()
    try:
        validated = input_model(**input_data)
    except ValidationError as error:
        raise InvalidToolInput(input_field_errors(error)) from None
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError):
        raise InvalidToolInput() from None

    enforce_target_policy(tool_name, validated)
    return ToolRequest(tool_name, tool_module, execute, validated)


def check_tool_request(
    tool_name: str,
    input_data: Any,
    load: Callable[[str], Any] = load_tool_module,
) -> ToolRequest:
    """Find the tool by name, then ``check_tool_input``."""
    module = load(tool_name)
    if module is None:
        raise UnknownTool()
    return check_tool_input(tool_name, module, input_data)


def refusal_log(refusal: Exception) -> str:
    """A refusal for the log: for invalid input, the fields and not the values."""
    if isinstance(refusal, InvalidToolInput) and refusal.errors is not None:
        fields = ", ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['type']}"
            for item in refusal.errors
        )
        return f"{refusal} ({fields})"
    return str(refusal)


def http_error(refusal: Exception) -> HTTPException:
    """The HTTP answer for a pre-run refusal, the same on every route."""
    if isinstance(refusal, UnknownTool):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(refusal))
    if isinstance(refusal, InvalidToolInput):
        # Which fields failed and why, so a client can point at them (#585).
        detail: Any = INPUT_INVALID
        if refusal.errors is not None:
            detail = {"reason": INPUT_INVALID, "errors": refusal.errors}
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail
        )
    if isinstance(refusal, TargetRefused):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(refusal)
        )
    raise TypeError(f"not a pre-run refusal: {type(refusal).__name__}")
