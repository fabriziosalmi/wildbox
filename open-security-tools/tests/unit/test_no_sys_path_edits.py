"""No module of the tools service edits ``sys.path`` (#646).

Seven tool modules still appended the service's ``app`` directory to
``sys.path`` when they were imported, a leftover from before the tools were
loaded as packages (``app.tool_loader``). They import their siblings with
relative imports, so the entry was not needed, and it was not harmless: with
``app`` on the path every module in it can also be imported by its bare name
(``config``, ``auth``, ``standardized_schemas``), as a second copy with its
own classes and its own state.
"""

import ast
import importlib.util
import os
import sys
from pathlib import Path

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.tool_loader import discover_tools  # noqa: E402

APP_DIR = Path(__file__).resolve().parents[2] / "app"


def _is_sys_path(node):
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "path"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _sys_path_edits(source):
    """Line numbers where ``source`` calls a method of, or assigns, sys.path."""
    lines = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _is_sys_path(node.func.value)
        ):
            lines.append(node.lineno)
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(_is_sys_path(target) for target in targets):
                lines.append(node.lineno)
    return lines


def test_the_check_recognizes_the_ways_of_editing_sys_path():
    assert _sys_path_edits("import sys\nsys.path.append('x')\n") == [2]
    assert _sys_path_edits("import sys\nsys.path.insert(0, 'x')\n") == [2]
    assert _sys_path_edits("import sys\nsys.path += ['x']\n") == [2]
    assert _sys_path_edits("import sys\nsys.path = ['x']\n") == [2]
    assert _sys_path_edits("import sys\nprint(sys.path)\nsys.exit(0)\n") == []


def test_no_module_of_the_service_edits_sys_path():
    edits = {
        str(path.relative_to(APP_DIR)): lines
        for path in sorted(APP_DIR.rglob("*.py"))
        for lines in [_sys_path_edits(path.read_text(encoding="utf-8"))]
        if lines
    }

    assert edits == {}


def test_loading_every_tool_does_not_put_the_app_directory_on_the_path():
    tools = discover_tools()
    assert "header_analyzer" in tools and "port_scanner" in tools

    assert [
        entry for entry in sys.path if entry and Path(entry).resolve() == APP_DIR
    ] == []
    # ... so the service's modules have one name each, under the app package.
    assert importlib.util.find_spec("standardized_schemas") is None
    assert importlib.util.find_spec("app.standardized_schemas") is not None
