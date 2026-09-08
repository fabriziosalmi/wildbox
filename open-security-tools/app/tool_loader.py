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
from typing import Any, Dict, List, Optional

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
    if tool_name.startswith("_") or tool_name in _NON_TOOL_PACKAGES:
        return None

    module_path = f"{TOOLS_PACKAGE}.{tool_name}.main"
    try:
        main_module = importlib.import_module(module_path)
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
