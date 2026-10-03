"""How the authenticated caller reaches tools that act on their behalf (#563).

A tool whose ``execute_tool`` declares a ``user_id`` parameter acts on behalf
of a caller. ``ToolExecutionManager`` used to call every tool as
``tool_func(input_data)``, so sql_injection_scanner, the one tool that
declares it, raised PermissionError on every API execution, however the caller
had authenticated.

The rule these tests pin: for such a tool the execution path (the execution
manager for the synchronous API, the Celery task for the asynchronous one)
refuses to run it without a caller, asks the authorization manager whether that
caller may run it against its target, and then passes the caller to the tool.
Tools that do not declare ``user_id`` are called exactly as before.

No test touches the network: the guarded HTTP session is replaced with a fake and the
targets are IP literals, so the SSRF guard resolves nothing.
"""

import asyncio
import json
import os
import sys
import uuid

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import execution_manager as execution_module  # noqa: E402
from app.execution_manager import ExecutionStatus, ToolExecutionManager  # noqa: E402
from app.security.authorization import (  # noqa: E402
    AuthorizationManager,
    OperationType,
    authorization_manager,
)
from app.tools.sql_injection_scanner import main as sqli_scanner  # noqa: E402
from app.tools.sql_injection_scanner.schemas import (  # noqa: E402
    SQLInjectionScannerInput,
)

TOOL = "sql_injection_scanner"
PUBLIC_IP = "93.184.215.14"
TARGET = f"http://{PUBLIC_IP}/page?id=1"
CALLER = str(uuid.uuid4())


class FakeResponse:
    text = "<html>ok</html>"


@pytest.fixture
def http(monkeypatch):
    """Record every request the scanner sends instead of sending it."""
    sent = []

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None, timeout=None):
            sent.append(url)
            return FakeResponse()

    monkeypatch.setattr(sqli_scanner, "guarded_requests_session", FakeSession)
    return sent


@pytest.fixture
def policy(monkeypatch):
    """An empty authorization policy on the global manager, restored afterwards.

    Empty is what a deployment without USER_PERMISSIONS_FILE and
    AUTHORIZED_TARGETS_FILE has: nobody may run a destructive test anywhere.
    """
    monkeypatch.setattr(authorization_manager, "user_permissions", {})
    monkeypatch.setattr(authorization_manager, "authorized_targets", set())
    monkeypatch.setattr(authorization_manager, "rate_limits", {})
    return authorization_manager


def grant(policy, user_id=CALLER, target=PUBLIC_IP):
    policy.user_permissions[user_id] = [OperationType.DESTRUCTIVE_TEST]
    policy.authorized_targets.add(target)


def run(manager, tool_func, input_data, tool_name=TOOL, **kwargs):
    return asyncio.run(
        manager.execute_tool(
            tool_func=tool_func,
            input_data=input_data,
            tool_name=tool_name,
            timeout=30,
            **kwargs,
        )
    )


def scanner_input():
    return SQLInjectionScannerInput(target_url=TARGET)


# --- the scanner through the execution manager -----------------------------


def test_authorized_caller_runs_the_scanner(policy, http):
    grant(policy)

    result = run(
        ToolExecutionManager(),
        sqli_scanner.execute_tool,
        scanner_input(),
        user_id=CALLER,
    )

    assert result.status is ExecutionStatus.COMPLETED, result.error
    assert result.result.success is True
    assert result.result.total_tests == len(sqli_scanner.SAFE_SQL_PAYLOADS)
    assert http and all(u.startswith(f"http://{PUBLIC_IP}/page?id=") for u in http)


def test_scanner_without_a_caller_is_refused(policy, http):
    grant(policy)

    result = run(ToolExecutionManager(), sqli_scanner.execute_tool, scanner_input())

    assert result.status is ExecutionStatus.REFUSED
    assert "requires an authenticated caller" in result.error
    assert http == []


def test_caller_without_permission_is_refused(policy, http):
    policy.authorized_targets.add(PUBLIC_IP)

    result = run(
        ToolExecutionManager(),
        sqli_scanner.execute_tool,
        scanner_input(),
        user_id=CALLER,
    )

    assert result.status is ExecutionStatus.REFUSED
    assert f"User {CALLER} not authorized for destructive_test" in result.error
    assert http == []


def test_target_outside_the_allowlist_is_refused(policy, http):
    grant(policy, target="198.51.100.7")

    result = run(
        ToolExecutionManager(),
        sqli_scanner.execute_tool,
        scanner_input(),
        user_id=CALLER,
    )

    assert result.status is ExecutionStatus.REFUSED
    assert "not authorized for destructive_test" in result.error
    assert http == []


def test_refusal_is_counted(policy, http, monkeypatch):
    counted = []

    class Recorder:
        def labels(self, **labels):
            counted.append(labels)
            return self

        def inc(self):
            pass

    monkeypatch.setattr(execution_module, "TOOL_EXECUTIONS", Recorder())
    manager = ToolExecutionManager()

    run(manager, sqli_scanner.execute_tool, scanner_input())

    assert counted == [{"tool": TOOL, "outcome": "refused"}]
    assert manager.get_execution_history()[-1]["status"] == "refused"


def test_enabled_security_layer_does_not_authorize_twice(policy, http, monkeypatch):
    """With SECURITY_CONTROLS_ENABLED the wrapper used to authorize as well.

    A destructive test is limited to one per caller per hour, so a second
    check in the wrapper consumed that one allowance and refused the run.
    """
    from app.security_integration import security_integration

    monkeypatch.setattr(security_integration, "security_enabled", True)
    monkeypatch.setattr(security_integration, "strict_mode", True)
    monkeypatch.setattr(
        security_integration, "authorization_manager", authorization_manager
    )
    monkeypatch.setattr(security_integration, "validator", None)
    grant(policy)

    result = run(
        ToolExecutionManager(),
        sqli_scanner.execute_tool,
        scanner_input(),
        user_id=CALLER,
    )

    assert result.status is ExecutionStatus.COMPLETED, result.error


# --- tools that do not act for a caller ------------------------------------


@pytest.fixture
def authorization_must_not_run(monkeypatch):
    def fail(**kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("tools without user_id are not authorized here")

    monkeypatch.setattr(authorization_manager, "require_authorization", fail)


@pytest.mark.parametrize("user_id", [None, CALLER])
def test_sync_tool_without_user_id_is_called_with_input_only(
    authorization_must_not_run, user_id
):
    calls = []

    def tool(input_data):
        calls.append(input_data)
        return {"echo": input_data}

    result = run(
        ToolExecutionManager(), tool, "payload", tool_name="echo", user_id=user_id
    )

    assert result.status is ExecutionStatus.COMPLETED
    assert result.result == {"echo": "payload"}
    assert calls == ["payload"]


@pytest.mark.parametrize("user_id", [None, CALLER])
def test_async_tool_without_user_id_is_called_with_input_only(
    authorization_must_not_run, user_id
):
    async def tool(request):
        return {"echo": request}

    result = run(
        ToolExecutionManager(), tool, "payload", tool_name="echo", user_id=user_id
    )

    assert result.status is ExecutionStatus.COMPLETED
    assert result.result == {"echo": "payload"}


def test_scanner_is_the_only_tool_that_declares_user_id():
    """The rule keys on the signature, so a new declaration is a policy change."""
    from pathlib import Path

    from app.tool_loader import load_tool_module

    tools_dir = Path(execution_module.__file__).parent / "tools"
    declaring = sorted(
        path.name
        for path in tools_dir.iterdir()
        if (path / "main.py").exists()
        and execution_module.tool_acts_for_caller(
            getattr(load_tool_module(path.name), "execute_tool", None)
        )
    )
    assert declaring == [TOOL]


# --- the HTTP endpoint passes the caller it authenticated ------------------


@pytest.fixture
def client(monkeypatch):
    from app.api import router as router_module
    from app.auth import verify_api_key
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    monkeypatch.setattr(router_module, "execution_manager", ToolExecutionManager())
    if not any(
        getattr(r, "path", "") == f"/api/tools/{TOOL}"
        for r in router_module.router.routes
    ):
        router_module.register_tool_endpoint(None, TOOL, sqli_scanner_module())

    app = FastAPI()
    app.include_router(router_module.router)
    app.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=CALLER, team_id=str(uuid.uuid4()), role="member"
    )
    return TestClient(app)


def sqli_scanner_module():
    from app.tool_loader import load_tool_module

    return load_tool_module(TOOL)


def test_endpoint_runs_the_scanner_for_the_authenticated_caller(client, policy, http):
    grant(policy)

    response = client.post(f"/api/tools/{TOOL}", json={"target_url": TARGET})

    assert response.status_code == 200, response.text
    assert response.json()["total_tests"] == len(sqli_scanner.SAFE_SQL_PAYLOADS)
    assert http


def test_endpoint_answers_403_when_the_caller_is_not_granted(client, policy, http):
    response = client.post(f"/api/tools/{TOOL}", json={"target_url": TARGET})

    assert response.status_code == 403, response.text
    assert "not authorized for destructive_test" in response.json()["detail"]
    assert http == []


# --- the asynchronous (Celery) path ----------------------------------------


@pytest.fixture
def celery_task(monkeypatch):
    pytest.importorskip("celery")
    from app import tasks

    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kwargs: None)
    return tasks.execute_tool_async


def test_celery_task_runs_the_scanner_for_the_caller(celery_task, policy, http):
    grant(policy)

    outcome = celery_task.run(
        tool_name=TOOL, input_data={"target_url": TARGET}, user_id=CALLER
    )

    assert outcome["status"] == "completed", outcome
    assert outcome["result"]["total_tests"] == len(sqli_scanner.SAFE_SQL_PAYLOADS)


def test_celery_task_refuses_without_a_caller(celery_task, policy, http):
    grant(policy)

    outcome = celery_task.run(tool_name=TOOL, input_data={"target_url": TARGET})

    assert outcome["status"] == "refused"
    assert "requires an authenticated caller" in outcome["error"]
    assert http == []


# --- the authorization policy files -----------------------------------------


def load_policy(tmp_path, monkeypatch, permissions=None, targets=None):
    perms_file = tmp_path / "user_permissions.json"
    targets_file = tmp_path / "authorized_targets.json"
    perms_file.write_text(json.dumps(permissions or {}))
    targets_file.write_text(json.dumps({"targets": targets or []}))
    monkeypatch.setenv("USER_PERMISSIONS_FILE", str(perms_file))
    monkeypatch.setenv("AUTHORIZED_TARGETS_FILE", str(targets_file))
    return AuthorizationManager()


def test_metadata_keys_do_not_stop_the_permissions_from_loading(tmp_path, monkeypatch):
    """The shipped example puts "description" beside the users.

    Iterating that string as a list of operations raised ValueError and
    abandoned the rest of the file, so users listed after it had no rights.
    """
    manager = load_policy(
        tmp_path,
        monkeypatch,
        permissions={
            "description": "User permissions for different operation types",
            "operation_types": {"read_only": "Information gathering"},
            CALLER: ["destructive_test", "no_such_operation"],
        },
    )

    assert manager.user_permissions == {CALLER: [OperationType.DESTRUCTIVE_TEST]}


def test_shipped_example_file_loads(monkeypatch):
    example = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "user_permissions.json.example"
    )
    monkeypatch.setenv("USER_PERMISSIONS_FILE", example)

    manager = AuthorizationManager()

    assert set(manager.user_permissions) == {
        "admin_user_123",
        "security_analyst_456",
        "junior_analyst_789",
    }


@pytest.mark.parametrize(
    "entry, target, allowed",
    [
        ("https://shop.example.com", "https://shop.example.com/page?id=1", True),
        ("https://shop.example.com/app", "https://shop.example.com/app/x?id=1", True),
        ("https://shop.example.com/app", "https://shop.example.com/other?id=1", False),
        # Dot segments resolve outside a path-scoped entry on the server.
        (
            "https://shop.example.com/app",
            "https://shop.example.com/app/../admin?id=1",
            False,
        ),
        (
            "https://shop.example.com/app",
            "https://shop.example.com/app/%2e%2e/admin",
            False,
        ),
        (
            "https://shop.example.com/app",
            "https://shop.example.com/app/.%2E/admin",
            False,
        ),
        ("https://shop.example.com", "https://shop.example.com/app/../x?id=1", True),
        ("https://shop.example.com", "http://shop.example.com/page?id=1", False),
        ("https://shop.example.com", "https://shop.example.com.evil.test/?id=1", False),
        (".example.com", "https://shop.example.com/?id=1", True),
        (".example.com", "https://badexample.com/?id=1", False),
        ("shop.example.com", "https://shop.example.com/?id=1", True),
        ("192.0.2.0/24", "http://192.0.2.10/?id=1", True),
        ("192.0.2.0/24", "http://198.51.100.1/?id=1", False),
    ],
)
def test_target_entries_match_url_targets(
    tmp_path, monkeypatch, entry, target, allowed
):
    manager = load_policy(tmp_path, monkeypatch, targets=[entry])

    assert (
        manager.is_target_authorized(target, OperationType.DESTRUCTIVE_TEST) is allowed
    )


# --- the asynchronous HTTP endpoints ----------------------------------------


@pytest.fixture
def async_client(task_ownership):
    pytest.importorskip("celery")
    from app.api import async_router
    from app.auth import verify_api_key
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    app = FastAPI()
    app.include_router(async_router.router)
    app.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=CALLER, team_id=str(uuid.uuid4()), role="member"
    )
    return TestClient(app), async_router


def test_async_submission_carries_the_authenticated_caller(async_client, monkeypatch):
    """The task ran for the literal caller "anonymous": nothing sets request.state.user_id."""
    client, async_router = async_client
    submitted = []

    def fake_apply_async(task_id=None, kwargs=None):
        submitted.append(kwargs)

    monkeypatch.setattr(
        async_router.execute_tool_async, "apply_async", fake_apply_async
    )

    response = client.post(f"/api/tools/{TOOL}/async", json={"target_url": TARGET})

    assert response.status_code == 202, response.text
    assert submitted[0]["user_id"] == CALLER


def test_async_status_reports_a_refused_task_as_refused(
    async_client, monkeypatch, task_ownership
):
    client, async_router = async_client
    # Only the task's owner can read it (#567).
    task_ownership.record("task-1", user_id=CALLER, team_id=str(uuid.uuid4()), tool_name=TOOL)

    class FakeResult:
        state = "SUCCESS"
        date_done = None
        result = {
            "status": "refused",
            "error": "not authorized",
            "tool_name": TOOL,
            "duration": 0,
        }

    monkeypatch.setattr(
        async_router, "AsyncResult", lambda task_id, app=None: FakeResult()
    )

    body = client.get("/api/tasks/task-1").json()

    assert body["status"] == "refused"
    assert body["error"] == "not authorized"
