"""Nothing a caller submits reaches a log line by value (#755).

The record of every run, "Executing tool", carried the tool's whole
validated input: a password to grade, a token to decode, a key to test. The
service's own formatter dropped the fields of every record, so that one did
not reach the service's output; any other handler would have written it, and
so would the formatter, once it wrote fields at all. It writes them now, the
ones named in ``LOGGED_FIELDS``, and a record says which tool, for whom,
under which request id and which fields were present.

The same holds for what the service logs elsewhere about a request: the URL
with its query, the text of an error a tool raises over its input, the
target of an authorization, the refusal of a target, and the text Celery
sends with a task for workers, ``inspect`` and Flower to show.
"""

import base64
import json
import logging
import os
import sys
import uuid

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

pytest.importorskip("celery")

from app import log_safety, logging_config, prerun, tasks  # noqa: E402
from app.api import async_router  # noqa: E402
from app.api import router as router_module  # noqa: E402
from app.auth import verify_api_key  # noqa: E402
from app.celery_app import celery_app  # noqa: E402
from app.execution_manager import ToolExecutionManager  # noqa: E402
from app.middleware import RequestLoggingMiddleware  # noqa: E402
from app.target_policy import TargetRefused  # noqa: E402
from app.tool_loader import load_tool_module  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from open_security_shared.errors import install_error_handlers  # noqa: E402
from open_security_shared.gateway_auth import GatewayUser  # noqa: E402

TOOL = "hash_generator"
MARKER = "do-not-log-" + uuid.uuid4().hex
USER = str(uuid.uuid4())
TEAM = str(uuid.uuid4())

# What may never be the name of a logged field: each holds a request's
# content, or a credential.
CONTENT_NAMES = {
    "input",
    "input_data",
    "validated_input",
    "body",
    "payload",
    "params",
    "parameters",
    "headers",
    "cookies",
    "query",
    "query_string",
    "url",
    "error",
    "detail",
    "result",
    "output",
    "token",
    "password",
    "secret",
    "api_key",
    "authorization",
    "broker",
    "backend",
    "redis_url",
}


def said(records, message):
    """The records whose message starts with ``message``."""
    found = [r for r in records if r.getMessage().startswith(message)]
    assert found, [r.getMessage() for r in records]
    return found


def nowhere_in(records):
    """The marker is in no record: not its message, not a field, not its text."""
    formatter = logging_config.JSONFormatter()
    for record in records:
        if record.name == "httpx":
            # The test client's own line, with the URL the test asked for.
            # The service quiets this logger (QUIETED_LOGGERS).
            continue
        assert MARKER not in record.getMessage()
        assert MARKER not in str(record.__dict__), record.getMessage()
        assert MARKER not in formatter.format(record)


@pytest.fixture
def client(monkeypatch, task_ownership):
    monkeypatch.setattr(router_module, "execution_manager", ToolExecutionManager())
    registered = {getattr(r, "path", "") for r in router_module.router.routes}
    if f"/api/tools/{TOOL}" not in registered:
        router_module.register_tool_endpoint(None, TOOL, load_tool_module(TOOL))

    sent = []

    def apply_async(task_id=None, kwargs=None, **options):
        sent.append({"task_id": task_id, "kwargs": kwargs, **options})

    monkeypatch.setattr(async_router.execute_tool_async, "apply_async", apply_async)

    app = FastAPI()
    install_error_handlers(app)
    app.add_middleware(RequestLoggingMiddleware)
    app.include_router(router_module.router)
    app.include_router(async_router.router)
    app.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=USER, team_id=TEAM, role="member", auth_type="session"
    )
    test_client = TestClient(app, raise_server_exceptions=False)
    test_client.sent = sent
    return test_client


# --- the record of a run --------------------------------------------------------


def test_a_run_is_logged_with_its_caller_and_field_names_and_no_value(client, caplog):
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            f"/api/tools/{TOOL}",
            json={"input_text": MARKER, "salt": MARKER, "hash_types": ["sha256"]},
            headers={"X-Request-ID": "req-755"},
        )

    assert response.status_code == 200, response.text
    nowhere_in(caplog.records)
    (record,) = said(caplog.records, "Executing tool")
    assert record.tool == TOOL
    assert record.user_id == USER
    assert record.team_id == TEAM
    assert record.request_id == "req-755"
    assert record.input_fields == ["hash_types", "input_text", "salt"]
    assert not hasattr(record, "input")


def test_the_line_the_service_writes_has_those_fields(client, caplog):
    """The formatter used to drop every field: the line had the message only."""
    with caplog.at_level(logging.DEBUG):
        client.post(
            f"/api/tools/{TOOL}",
            json={"input_text": MARKER},
            headers={"X-Request-ID": "req-755"},
        )

    (record,) = said(caplog.records, "Executing tool")
    line = json.loads(logging_config.JSONFormatter().format(record))
    assert line["message"] == f"Executing tool: {TOOL}"
    assert line["tool"] == TOOL
    assert line["user_id"] == USER
    assert line["team_id"] == TEAM
    assert line["request_id"] == "req-755"
    assert line["input_fields"] == ["input_text"]


def test_a_field_reaches_the_log_only_if_it_is_listed():
    record = logging.LogRecord("app", logging.INFO, __file__, 1, "run", None, None)
    record.tool = TOOL
    record.input = {"input_text": MARKER}
    record.body = MARKER
    record.color_message = "from a library"

    line = json.loads(logging_config.JSONFormatter().format(record))

    assert line["tool"] == TOOL
    assert set(line) == {"timestamp", "level", "logger", "message", "tool"}
    assert MARKER not in json.dumps(line)


def test_no_listed_field_is_a_name_for_a_requests_content():
    listed = set(logging_config.LOGGED_FIELDS)

    assert not listed & CONTENT_NAMES
    assert {"tool", "user_id", "team_id", "request_id", "input_fields"} <= listed


def test_field_names_are_the_models_and_not_the_callers():
    from pydantic import BaseModel, ConfigDict

    class Open(BaseModel):
        model_config = ConfigDict(extra="allow")
        target: str
        token: str = ""

    given = Open(**{"target": "example.com", "token": MARKER, MARKER: 1})

    assert log_safety.field_names(given) == ["target", "token"]
    assert log_safety.field_names({"target": MARKER}) == []
    assert log_safety.field_names(None) == []


# --- an error a tool raises over its input ------------------------------------------


@pytest.fixture
def quoting_tool(monkeypatch):
    """hash_generator fails with an error that quotes what it was given."""
    module = load_tool_module(TOOL)

    def execute(data):
        raise ValueError(f"cannot hash {data.input_text!r}")

    monkeypatch.setattr(module, "execute_tool", execute)
    return module


def test_a_tools_error_is_logged_by_class_and_line(client, caplog, monkeypatch):
    manager = router_module.execution_manager

    async def run(**kwargs):
        def execute(data):
            raise ValueError(f"cannot hash {data.input_text!r}")

        kwargs["tool_func"] = execute
        return await ToolExecutionManager.execute_tool(manager, **kwargs)

    monkeypatch.setattr(manager, "execute_tool", run)

    with caplog.at_level(logging.DEBUG):
        response = client.post(f"/api/tools/{TOOL}", json={"input_text": MARKER})

    assert response.status_code == 500, response.text
    assert MARKER not in response.text
    assert response.json()["error"]["message"] == "Tool execution failed"
    nowhere_in(caplog.records)
    failed = [r for r in caplog.records if getattr(r, "error_type", None)]
    assert failed, [r.getMessage() for r in caplog.records]
    for record in failed:
        assert record.error_type.startswith("ValueError at ")
        assert record.error_type.endswith(" in execute")
        assert not hasattr(record, "error")


def test_the_task_neither_logs_nor_stores_what_its_tool_raised(
    quoting_tool, caplog, monkeypatch
):
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kw: None)

    with caplog.at_level(logging.DEBUG):
        outcome = tasks.execute_tool_async.run(
            tool_name=TOOL, input_data={"input_text": MARKER}, user_id=USER
        )

    # The result is kept in Redis for an hour and read back by the caller.
    assert outcome["status"] == "failed"
    assert outcome["error"] == "Tool execution failed (ValueError)"
    assert MARKER not in str(outcome)
    nowhere_in(caplog.records)
    (record,) = said(caplog.records, "Async tool execution failed")
    assert record.error_type.startswith("ValueError at ")


def test_error_site_says_where_and_not_what():
    def parse(value):
        raise ValueError(f"not a port: {value}")

    try:
        parse(MARKER)
    except ValueError as error:
        site = log_safety.error_site(error)

    assert site.startswith("ValueError at test_no_input_values_in_logs.py:")
    assert site.endswith(" in parse")
    assert MARKER not in site
    assert log_safety.error_site(KeyError(MARKER)) == "KeyError"


# --- a refusal before the run ---------------------------------------------------------


def test_a_refused_target_is_answered_in_full_and_logged_by_kind(
    client, caplog, monkeypatch
):
    def refuse(tool_name, validated):
        raise TargetRefused(f"Target {validated.input_text!r} is internal")

    monkeypatch.setattr(prerun, "enforce_target_policy", refuse)
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kw: None)
    body = {"input_text": MARKER}

    with caplog.at_level(logging.DEBUG):
        synchronous = client.post(f"/api/tools/{TOOL}", json=body)
        submitted = client.post(f"/api/tools/{TOOL}/async", json=body)
        in_the_worker = tasks.execute_tool_async.run(
            tool_name=TOOL, input_data=body, user_id=USER
        )

    # The caller is told which target, in the answer that goes back to them.
    assert synchronous.status_code == submitted.status_code == 400
    assert MARKER in synchronous.json()["error"]["message"]
    assert in_the_worker["error"] == f"Target {MARKER!r} is internal"
    # The log says a target was refused, three times, and not which.
    nowhere_in(caplog.records)
    refusals = [
        r
        for r in caplog.records
        if prerun.TARGET_REFUSED in r.getMessage()
        or getattr(r, "reason", None) == prerun.TARGET_REFUSED
    ]
    assert len(refusals) == 3, [r.getMessage() for r in caplog.records]
    assert client.sent == []


def test_a_key_of_the_callers_own_is_not_logged_as_a_field(caplog, monkeypatch):
    """A model that forbids extra fields reports the caller's key as the place."""
    from pydantic import BaseModel, ConfigDict

    class Strict(BaseModel):
        model_config = ConfigDict(extra="forbid")
        target: str

    class Module:
        schemas = type("schemas", (), {"StrictInput": Strict})

        @staticmethod
        def execute_tool(data):
            return {}

    Strict.__name__ = "StrictInput"

    with pytest.raises(prerun.InvalidToolInput) as refused:
        prerun.check_tool_input("strict", Module, {"target": 7, MARKER: "x"})

    logged = prerun.refusal_log(refused.value)
    assert MARKER not in logged
    assert "target: string_type" in logged
    assert f"{prerun.UNDECLARED_FIELD}: extra_forbidden" in logged
    # The answer still points at the caller's own key, for the caller.
    assert MARKER in prerun.refusal_text(refused.value)


# --- the URL of a request ----------------------------------------------------------------


def test_a_request_is_logged_by_path_without_its_query(client, caplog):
    with caplog.at_level(logging.DEBUG):
        response = client.get(f"/api/tools?token={MARKER}")

    assert response.status_code == 200, response.text
    nowhere_in(caplog.records)
    (record,) = said(caplog.records, "HTTP request started")
    assert record.path == "/api/tools"
    assert not hasattr(record, "url")


def test_http_client_libraries_do_not_log_the_address_they_call(monkeypatch):
    """httpx logs "HTTP Request: GET <url>" at INFO: the caller's target."""
    libraries = [logging.getLogger(name) for name in ("httpx", "httpcore", "urllib3")]
    for library in libraries:
        monkeypatch.setattr(library, "level", logging.NOTSET)
    monkeypatch.setattr(logging.getLogger(), "level", logging.DEBUG)

    logging_config.configure_logging()

    for library in libraries:
        assert library.getEffectiveLevel() == logging.WARNING, library.name


WORKER_START = """
import logging
import app.celery_app  # what `celery -A app.celery_app worker` imports
logging.getLogger().setLevel(logging.DEBUG)  # as --loglevel=debug does, afterwards
print(*(logging.getLogger(n).getEffectiveLevel() for n in ("httpx", "httpcore", "urllib3")))
"""


def test_the_worker_quiets_them_too(tmp_path):
    """The worker never imports app.main: app.celery_app is where it starts."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-c", WORKER_START],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", ".."),
            "API_KEY": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        },
        timeout=120,
    )

    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.split() == [str(logging.WARNING)] * 3


# --- a target, named by its host ------------------------------------------------------


@pytest.mark.parametrize(
    "target, host",
    [
        (
            f"https://user:{MARKER}@example.com:8443/reset/{MARKER}?t={MARKER}",
            "example.com:8443",
        ),
        (f"http://example.com/?token={MARKER}", "example.com"),
        (f"http://[2001:db8::1]:8080/{MARKER}", "[2001:db8::1]:8080"),
        ("example.com", "example.com"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        (f"example.com/path?{MARKER}", "example.com"),
        (f"user:{MARKER}@example.com", "example.com"),
        (f"https://{MARKER}", MARKER),  # a host is what the caller says it is
        ("", log_safety.NO_HOST),
        (None, log_safety.NO_HOST),
        ("http://", log_safety.NO_HOST),
    ],
)
def test_host_of_keeps_the_host_and_nothing_else(target, host):
    assert log_safety.host_of(target) == host


def test_an_authorization_is_logged_and_refused_by_host(caplog):
    from app.security.authorization import AuthorizationManager, OperationType

    manager = AuthorizationManager()
    manager.user_permissions[USER] = [OperationType.DESTRUCTIVE_TEST]
    target = f"https://admin:{MARKER}@shop.example.com/login?session={MARKER}"

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(PermissionError) as refused:
            manager.require_authorization(
                target=target,
                user_id=USER,
                operation=OperationType.DESTRUCTIVE_TEST,
                tool_name="sql_injection_scanner",
            )

    assert str(refused.value) == (
        "Target shop.example.com not authorized for destructive_test operations"
    )
    nowhere_in(caplog.records)
    (attempt,) = said(caplog.records, "Authorization attempt")
    assert '"target": "shop.example.com"' in attempt.getMessage()


# --- what Celery is given to show -----------------------------------------------------


def test_a_submission_is_logged_like_a_run(client, caplog):
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            f"/api/tools/{TOOL}/async",
            json={"input_text": MARKER, "hash_types": ["sha256"]},
            headers={"X-Request-ID": "req-755"},
        )

    assert response.status_code == 202, response.text
    nowhere_in(caplog.records)
    (record,) = said(caplog.records, "Async task submitted")
    assert record.tool == TOOL
    assert record.user_id == USER
    assert record.team_id == TEAM
    assert record.request_id == "req-755"
    assert record.input_fields == ["hash_types", "input_text"]
    # The input is in the message all the same: the tool runs with it.
    assert client.sent[0]["kwargs"]["input_data"]["input_text"] == MARKER


def sent_by(monkeypatch, send):
    """The options the task's message is built from, for one ``send``."""
    from celery.app.task import Task

    captured = []

    def record(self, args=None, kwargs=None, **options):
        captured.append({"args": args, "kwargs": kwargs, **options})

    monkeypatch.setattr(Task, "apply_async", record)
    send()
    (options,) = captured
    return options


def test_the_text_celery_shows_for_a_task_leaves_the_input_out(monkeypatch):
    kwargs = {
        "tool_name": TOOL,
        "input_data": {"input_text": MARKER, "salt": MARKER},
        "user_id": USER,
        "timeout": None,
    }

    options = sent_by(
        monkeypatch, lambda: tasks.execute_tool_async.apply_async(kwargs=kwargs)
    )

    assert options["kwargs"] == kwargs  # what the task runs with is untouched
    assert MARKER not in options["kwargsrepr"]
    assert MARKER not in options["argsrepr"]
    assert TOOL in options["kwargsrepr"]
    assert USER in options["kwargsrepr"]
    assert "<2 field(s)>" in options["kwargsrepr"]


def test_positional_arguments_are_not_shown_either(monkeypatch):
    options = sent_by(
        monkeypatch,
        lambda: tasks.execute_tool_async.apply_async(
            args=(TOOL, {"input_text": MARKER})
        ),
    )

    assert options["argsrepr"] == tasks.ARGUMENTS_NOT_SHOWN
    assert MARKER not in options["kwargsrepr"]


def test_the_message_of_a_retry_leaves_the_input_out_too(monkeypatch):
    """Celery builds a retry's message from the request, without the text."""
    from celery.app.task import Context

    task = tasks.execute_tool_async
    kwargs = {"tool_name": TOOL, "input_data": {"input_text": MARKER}, "user_id": USER}
    request = Context(id=str(uuid.uuid4()), args=(), kwargs=kwargs, retries=0)

    options = sent_by(
        monkeypatch,
        lambda: task.signature_from_request(request, (), kwargs).apply_async(),
    )

    assert options["kwargs"] == kwargs
    assert MARKER not in options["kwargsrepr"]
    assert "<1 field(s)>" in options["kwargsrepr"]


def test_the_result_backend_does_not_keep_the_arguments():
    # With result_extended the arguments are stored with every result, for
    # result_expires: the input would outlive the task by an hour.
    assert celery_app.conf.result_extended is False
    assert celery_app.conf.result_expires == 3600


def test_the_broker_address_is_not_logged():
    """REDIS_URL carries the Redis password; the module logged it twice."""
    import inspect

    import app.celery_app as module

    source = inspect.getsource(module)
    logged = [line for line in source.splitlines() if "logger." in line]
    assert logged == ['logger.info("Celery app configured")'], logged


# --- with a real worker and a real Redis ------------------------------------------------


def test_the_queued_message_has_the_input_in_its_body_and_nowhere_else(stack):
    """What Redis holds while a task waits: the arguments, and a text of them."""
    queue = stack.new_queue()
    task_id = str(uuid.uuid4())
    kwargs = {
        "tool_name": "metrics_probe",
        "input_data": {"behaviour": "return", "marker": MARKER},
        "user_id": USER,
    }

    with stack.app.connection_for_write() as connection:
        tasks.execute_tool_async.apply_async(
            kwargs=kwargs, task_id=task_id, queue=queue, connection=connection
        )
    stack.sent.append(task_id)

    (raw,) = stack.redis.lrange(queue, 0, -1)
    message = json.loads(raw)
    body = base64.b64decode(message["body"]).decode()
    # The body is what the worker runs the task with: storage, until the
    # task is acknowledged.
    assert MARKER in body
    # Everything else is for display.
    assert MARKER not in json.dumps(message["headers"])
    assert MARKER not in json.dumps(message["properties"])
    assert "<2 field(s)>" in message["headers"]["kwargsrepr"]

    worker = stack.start_worker(queue)
    try:
        meta = stack.state(
            stack.app.AsyncResult(task_id), {"SUCCESS", "FAILURE", "REVOKED"}
        )
        active = stack.app.control.inspect(destination=[worker.node], timeout=2)

        assert meta["status"] == "SUCCESS", meta
        # The stored result has no argument of the task in it.
        stored = stack.redis.get(f"celery-task-meta-{task_id}")
        assert MARKER not in stored
        assert MARKER not in worker.log_since()
        assert MARKER not in json.dumps(active.active() or {})
        # Acknowledged: the message, and the input with it, is gone.
        assert stack.queued(queue) == 0
        assert MARKER not in json.dumps(stack.redis.hgetall("unacked"))
    finally:
        worker.stop()


def test_a_worker_does_not_log_what_a_tool_raises_over_its_input(stack):
    mark = stack.mark()

    result = stack.send(input_data={"behaviour": "quote", "marker": MARKER})
    meta = stack.state(result, {"SUCCESS", "FAILURE", "REVOKED"})

    assert meta["status"] == "SUCCESS", meta
    assert meta["result"]["status"] == "failed"
    assert meta["result"]["error"] == "Tool execution failed (ValueError)"
    log = stack.logged(mark, "Async tool execution failed")
    assert MARKER not in log
    assert MARKER not in stack.redis.get(f"celery-task-meta-{result.id}")
