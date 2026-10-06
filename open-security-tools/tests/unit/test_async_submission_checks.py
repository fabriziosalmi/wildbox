"""Nothing invalid is queued (#743).

``POST /api/tools/{tool}/async`` recorded an owner and queued a task for
whatever name and body it was given, and answered 202. The synchronous route
answers 404 for a name that is no tool, 422 for input the tool's model
refuses and 400 for a target the policy refuses, before a run exists. The
asynchronous caller read the same back from the task, as ``failed``, after
the request had taken a place in the queue and a worker.

Both routes and the Celery task now call one check (``app.prerun``). These
tests ask both routes the same thing and compare the answers, and check that
a refused submission leaves nothing behind: no task, no owner record.
"""

import logging
import os
import sys
import uuid

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

pytest.importorskip("celery")

from app import prerun, tasks  # noqa: E402
from app.target_policy import TargetRefused  # noqa: E402
from app.tool_loader import load_tool_module  # noqa: E402

CALLER = str(uuid.uuid4())
SECRET = "hunter2-do-not-echo-this"
TOOLS = ("hash_generator", "http_security_scanner", "port_scanner")

# (tool, body, status): what both routes must refuse, and with what.
REFUSED = [
    # Input the tool's model refuses.
    ("hash_generator", {"input_text": "x", "hash_types": ["md5"]}, 422),
    ("hash_generator", {}, 422),
    ("hash_generator", {"input_text": "x", "iterations": SECRET}, 422),
    # A target the policy refuses: cloud metadata, loopback.
    ("http_security_scanner", {"url": "http://169.254.169.254/latest/"}, 400),
    ("port_scanner", {"target": "127.0.0.1"}, 400),
]


@pytest.fixture
def api(monkeypatch, task_ownership):
    """Both routers, a signed-in caller, and what was queued."""
    from app.api import async_router
    from app.api import router as router_module
    from app.auth import verify_api_key
    from app.execution_manager import ToolExecutionManager
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    monkeypatch.setattr(router_module, "execution_manager", ToolExecutionManager())
    registered = {getattr(route, "path", "") for route in router_module.router.routes}
    for tool in TOOLS:
        if f"/api/tools/{tool}" not in registered:
            router_module.register_tool_endpoint(None, tool, load_tool_module(tool))

    queued = []

    def apply_async(task_id=None, kwargs=None):
        queued.append((task_id, kwargs))

    monkeypatch.setattr(async_router.execute_tool_async, "apply_async", apply_async)

    app = FastAPI()
    app.include_router(router_module.router)
    app.include_router(async_router.router)
    app.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=CALLER, team_id=str(uuid.uuid4()), role="member", auth_type="session"
    )
    client = TestClient(app, raise_server_exceptions=False)
    client.queued = queued
    client.ownership = task_ownership
    return client


# --- the two routes give one answer ------------------------------------------


@pytest.mark.parametrize("tool, body, expected", REFUSED)
def test_the_submission_is_refused_as_the_synchronous_route_refuses(
    api, tool, body, expected
):
    synchronous = api.post(f"/api/tools/{tool}", json=body)
    submitted = api.post(f"/api/tools/{tool}/async", json=body)

    assert synchronous.status_code == expected, synchronous.text
    assert submitted.status_code == expected, submitted.text
    assert submitted.json() == synchronous.json()
    # And nothing was left behind: no task, no owner record to list.
    assert api.queued == []
    assert api.ownership.list_for(CALLER, 10) == []
    assert api.get("/api/tasks").json() == {"tasks": [], "count": 0}


@pytest.mark.parametrize(
    "name",
    [
        "no_such_tool",
        "hash_generator.main",  # a path below a tool's package
        "hash_generator.schemas",
        "wordlists",  # a support package, not a tool
        "_private",
        "Hash_Generator",
        "hash-generator",
        "hash_generator ",
    ],
)
def test_a_name_that_is_no_tool_is_a_404_on_both_routes(api, name):
    body = {"input_text": "wildbox"}

    synchronous = api.post(f"/api/tools/{name}", json=body)
    submitted = api.post(f"/api/tools/{name}/async", json=body)

    assert synchronous.status_code == 404, synchronous.text
    assert submitted.status_code == 404, submitted.text
    assert submitted.json() == {"detail": "Tool not found"}
    assert api.queued == []
    assert api.ownership.list_for(CALLER, 10) == []


def test_a_valid_request_is_queued_with_the_callers_input(api):
    body = {"input_text": "wildbox", "hash_types": ["sha256"]}

    response = api.post("/api/tools/hash_generator/async", json=body)

    assert response.status_code == 202, response.text
    ((task_id, kwargs),) = api.queued
    assert response.json()["task_id"] == task_id
    assert kwargs["tool_name"] == "hash_generator"
    assert kwargs["input_data"] == body
    assert kwargs["user_id"] == CALLER
    assert [owner["task_id"] for owner in api.ownership.list_for(CALLER, 10)] == [
        task_id
    ]


def test_a_refused_value_is_in_neither_the_answer_nor_the_log(api, caplog):
    body = {"input_text": "x", "iterations": SECRET}

    with caplog.at_level(logging.DEBUG):
        response = api.post("/api/tools/hash_generator/async", json=body)

    assert response.status_code == 422
    assert response.json()["detail"]["errors"][0]["loc"] == ["iterations"]
    assert SECRET not in response.text
    assert SECRET not in caplog.text
    # The log says which field and why.
    assert "iterations: int_parsing" in caplog.text


def test_the_synchronous_route_does_not_log_a_refused_value_either(api, caplog):
    with caplog.at_level(logging.DEBUG):
        response = api.post(
            "/api/tools/hash_generator", json={"input_text": "x", "iterations": SECRET}
        )

    assert response.status_code == 422
    assert SECRET not in response.text
    assert SECRET not in caplog.text


# --- one check, three callers ---------------------------------------------------


def test_the_two_routes_and_the_task_run_the_same_check(api, monkeypatch):
    """Change the one policy and all three change with it."""
    asked = []

    def refuse(tool_name, validated):
        asked.append(tool_name)
        raise TargetRefused("refused by the test's policy")

    monkeypatch.setattr(prerun, "enforce_target_policy", refuse)
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kw: None)
    body = {"input_text": "wildbox"}

    synchronous = api.post("/api/tools/hash_generator", json=body)
    submitted = api.post("/api/tools/hash_generator/async", json=body)
    in_the_worker = tasks.execute_tool_async.run(
        tool_name="hash_generator", input_data=body, user_id=CALLER
    )

    assert synchronous.status_code == submitted.status_code == 400
    assert synchronous.json() == submitted.json()
    assert synchronous.json() == {"detail": "refused by the test's policy"}
    assert in_the_worker["status"] == "failed"
    assert in_the_worker["error"] == "refused by the test's policy"
    assert asked == ["hash_generator"] * 3
    assert api.queued == []


# --- the task checks again when it runs --------------------------------------------


@pytest.fixture
def run_task(monkeypatch):
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kw: None)

    def run(tool, body):
        return tasks.execute_tool_async.run(
            tool_name=tool, input_data=body, user_id=CALLER
        )

    return run


@pytest.mark.parametrize("tool, body, expected", REFUSED)
def test_the_task_refuses_what_the_submission_refuses(run_task, tool, body, expected):
    """What can change between submission and run is checked at the run."""
    outcome = run_task(tool, body)

    assert outcome["status"] == "failed", outcome
    assert "result" not in outcome


@pytest.mark.parametrize("name", ["no_such_tool", "hash_generator.main", "wordlists"])
def test_the_task_does_not_load_a_name_that_is_no_tool(run_task, name):
    outcome = run_task(name, {"input_text": "wildbox"})

    assert outcome["status"] == "failed"
    assert outcome["error"] == "Tool not found"


def test_the_tasks_error_names_the_field_and_not_the_value(run_task):
    """The error is stored with the task, where its owner reads it back.

    It used to be pydantic's own message, which quotes the value refused.
    """
    outcome = run_task("hash_generator", {"input_text": "x", "iterations": SECRET})

    assert outcome["status"] == "failed"
    assert outcome["error"] == "Input validation failed (iterations: int_parsing)"
    assert SECRET not in str(outcome)


# --- the loader ------------------------------------------------------------------------


def test_the_loader_refuses_what_is_not_a_package_name():
    for name in ("hash_generator.schemas", "..config", "os", "a.b", "", None, 7):
        assert load_tool_module(name) is None


IMPORTED_BY_A_DOTTED_NAME = """
import sys
from app.tool_loader import load_tool_module

loaded = load_tool_module("base64_tool.schemas")
print(loaded is None, "app.tools.base64_tool.schemas" in sys.modules)
"""


def test_a_dotted_name_imports_nothing_below_the_tools_package(tmp_path):
    """The name comes from the URL of the asynchronous route.

    ``base64_tool.schemas`` is not a tool, and looking it up used to import
    ``app.tools.base64_tool.schemas`` on the way to finding that out: a
    caller chose which modules of the tools package the service imported.
    In a fresh interpreter, where nothing has imported that module yet.
    """
    import subprocess

    result = subprocess.run(
        [sys.executable, "-c", IMPORTED_BY_A_DOTTED_NAME],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", ".."),
            "API_KEY": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "LOG_LEVEL": "ERROR",
        },
        timeout=120,
    )

    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.split() == ["True", "False"]


def test_a_name_that_is_no_tool_is_not_logged_as_a_broken_tool(caplog):
    with caplog.at_level(logging.ERROR):
        assert load_tool_module("no_such_tool") is None

    assert caplog.records == []


def test_a_tool_that_cannot_be_imported_is_still_logged(monkeypatch, caplog):
    """A missing dependency of a real tool is the operator's to see."""
    import importlib

    def broken(name):
        raise ModuleNotFoundError("No module named 'nmap'", name="nmap")

    monkeypatch.setattr(importlib, "import_module", broken)

    with caplog.at_level(logging.ERROR):
        assert load_tool_module("port_scanner") is None

    assert "Tool port_scanner failed to import" in caplog.text
