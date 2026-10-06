"""
The single implementation of the tool-plugin loading contract.

Both the API process (app.main) and the Celery worker (app.tasks) load tools
through this module. Previously each had its own copy that mutated sys.path and
sys.modules around ``spec_from_file_location``, with different sequencing, so a
tool's loading semantics depended on which process loaded it (WILDBO-ARCH-06).

Tools are ordinary Python packages under ``app.tools``. They are imported with
``importlib.import_module``, which means:

* ``__package__`` is set, so relative imports work -- ``from .schemas import X``
  and ``from ..wordlists import load_wordlist`` resolve normally. Under the old
  loader the latter raised ImportError on every load and silently disabled the
  api_security_tester's endpoint discovery (WILDBO-ARCH-03).
* No sys.path or sys.modules mutation, so tools cannot collide with each other
  or with host modules, and nothing depends on the container working directory
  (WILDBO-ARCH-07).
* Python's own module cache applies, so a tool is executed once per process
  rather than re-imported on every Celery task (WILDBO-PERF-05).
"""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType
from typing import Any, Dict, List, Optional, Tuple

from app.logging_config import get_logger

logger = get_logger(__name__)

TOOLS_PACKAGE = "app.tools"

# Names under app/tools that are support packages, not tools.
_NON_TOOL_PACKAGES = {"wordlists"}

# A tool module must expose these to be usable.
_REQUIRED_ATTRS = ("execute_tool",)


def list_tool_names() -> List[str]:
    """Names of every candidate tool package under app.tools."""
    pkg = importlib.import_module(TOOLS_PACKAGE)
    names = []
    for mod in pkgutil.iter_modules(pkg.__path__):
        if not mod.ispkg:
            continue
        if mod.name.startswith("_") or mod.name in _NON_TOOL_PACKAGES:
            continue
        names.append(mod.name)
    return sorted(names)


def load_tool_module(tool_name: str) -> Optional[ModuleType]:
    """
    Import one tool's ``main`` module, or return None if it cannot be used.

    Import errors are logged with the tool name and the exception; they are not
    swallowed into a stub, because a tool that cannot be imported must not look
    like a tool that works.
    """
    # A tool's name is one package name. The asynchronous route takes it from
    # the URL, and a name with a dot in it ("hash_generator.main") would be
    # imported as a path below app.tools (#743).
    if not isinstance(tool_name, str) or not tool_name.isidentifier():
        return None
    if tool_name.startswith("_") or tool_name in _NON_TOOL_PACKAGES:
        return None

    module_path = f"{TOOLS_PACKAGE}.{tool_name}.main"
    try:
        main_module = importlib.import_module(module_path)
    except ModuleNotFoundError as exc:
        if exc.name in (f"{TOOLS_PACKAGE}.{tool_name}", module_path):
            # No such tool: a caller's mistake, not a tool that is broken.
            return None
        logger.error(
            f"Tool {tool_name} failed to import: {type(exc).__name__}: {exc}",
            exc_info=True,
        )
        return None
    except Exception as exc:  # noqa: BLE001 - a bad tool must not kill discovery
        logger.error(
            f"Tool {tool_name} failed to import: {type(exc).__name__}: {exc}",
            exc_info=True,
        )
        return None

    missing = [attr for attr in _REQUIRED_ATTRS if not hasattr(main_module, attr)]
    if missing:
        logger.error(f"Tool {tool_name} is not loadable: missing {', '.join(missing)}")
        return None

    # Tools reference their own schemas module; attach it for the callers that
    # introspect it (the web form generator and the async task input parser).
    if not hasattr(main_module, "schemas"):
        try:
            main_module.schemas = importlib.import_module(
                f"{TOOLS_PACKAGE}.{tool_name}.schemas"
            )
        except ImportError:
            logger.warning(f"Tool {tool_name} has no schemas module")

    if not hasattr(main_module, "TOOL_INFO"):
        logger.warning(f"Tool {tool_name} missing TOOL_INFO metadata")
        main_module.TOOL_INFO = {
            "name": tool_name,
            "display_name": tool_name.replace("_", " ").title(),
            "description": "No description provided",
            "version": "unknown",
            "author": "unknown",
            "category": "general",
        }

    return main_module


_BASE_SCHEMA_NAMES = {"BaseToolInput", "BaseToolOutput"}


def find_schema_classes(schemas_module: Any) -> Tuple[Optional[type], Optional[type]]:
    """
    The (input, output) Pydantic models of a tool's schemas module.

    The input model is a BaseModel subclass whose name contains "input" or
    "request", the output model one whose name contains "output" or
    "response", the shared base classes excluded. When several match, the last
    in ``dir()`` order wins, as the endpoint always chose.

    This is the one place that answers the question. The endpoint validated a
    request with one model while ``/info`` published another (it matched any
    name containing "Input", so for a tool whose model sorts before
    "BaseToolInput" it published the base class), and the worker picked the
    first match instead of the last (#611).
    """
    from pydantic import BaseModel

    input_cls: Optional[type] = None
    output_cls: Optional[type] = None
    if schemas_module is None:
        return None, None
    for attr_name in dir(schemas_module):
        attr = getattr(schemas_module, attr_name, None)
        if not (isinstance(attr, type) and issubclass(attr, BaseModel)):
            continue
        if attr is BaseModel or attr.__name__ in _BASE_SCHEMA_NAMES:
            continue
        name = attr.__name__.lower()
        if "input" in name or "request" in name:
            input_cls = attr
        elif "output" in name or "response" in name:
            output_cls = attr
    return input_cls, output_cls


def discover_tools() -> Dict[str, Any]:
    """Import every usable tool. Returns {tool_name: module}."""
    tools: Dict[str, Any] = {}
    failed: List[str] = []

    for name in list_tool_names():
        module = load_tool_module(name)
        if module is None:
            failed.append(name)
            continue
        tools[name] = module

    logger.info(
        f"Tool discovery complete: {len(tools)} loaded"
        + (f", {len(failed)} failed ({', '.join(failed)})" if failed else "")
    )
    return tools
