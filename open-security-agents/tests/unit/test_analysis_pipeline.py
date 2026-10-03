"""The analysis pipeline, from request to tool call (#582).

These replace tests/test_basic.py, which CI never ran (the Unit Tests job
collects tests/unit only) and which failed when run: it asserted
``client.headers``, an attribute the Wildbox client no longer has. What it
meant to cover that still matters is checked here against the current code:

- the request schemas accept what /v1/analyze documents and refuse the rest;
- /v1/analyze hands the caller's gateway identity to the worker task;
- the worker task makes that identity the one its tool calls send (#175);
- every tool the agent is given reaches an endpoint the client allows, with
  that identity and the gateway secret, and nothing else (#567);
- the client takes the gateway secret from GATEWAY_INTERNAL_SECRET.

Its other checks were dropped: an OpenAI key setting that no longer exists,
and an agent and a Celery app that were only checked for "is not None".
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import main, worker  # noqa: E402
from app.config import Settings  # noqa: E402
from app.schemas import AnalysisTaskRequest, IOCInput, TaskPriority  # noqa: E402
from app.tools import wildbox_client as client_module  # noqa: E402
from app.tools.langchain_tools import ALL_TOOLS  # noqa: E402
from app.tools.wildbox_client import (  # noqa: E402
    CallerIdentityUnavailable,
    WildboxAPIClient,
    _caller_identity,
)
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import ValidationError  # noqa: E402

SECRET = "gateway-secret-for-tests"
# The gateway sends UUIDs, and the shared dependency refuses anything else.
USER_ID = "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77"
TEAM_ID = "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b"
CALLER = {"user_id": USER_ID, "team_id": TEAM_ID, "role": "admin"}


@pytest.fixture(autouse=True)
def no_caller_identity():
    """Each test starts, and leaves, with no caller identity set."""
    _caller_identity.set(None)
    yield
    _caller_identity.set(None)


class FakeRedis:
    """The subset of redis-py the endpoint and the worker call."""

    def __init__(self):
        self.store = {}

    def setex(self, key, ttl, value):
        self.store[key] = value

    def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1

    def delete(self, *keys):
        for key in keys:
            self.store.pop(key, None)

    def pipeline(self):
        return self

    def execute(self):
        return []


class Response:
    status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return {"success": True}


class RecordingClient:
    """Stands in for httpx.AsyncClient and records what would be sent."""

    sent = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, **kwargs):
        RecordingClient.sent.append((url, kwargs.get("headers") or {}))
        return Response()

    async def get(self, url, **kwargs):
        RecordingClient.sent.append((url, kwargs.get("headers") or {}))
        return Response()


@pytest.fixture
def recorded(monkeypatch):
    """Requests the Wildbox client sends, none of them leaving the process."""
    import httpx

    RecordingClient.sent = []
    monkeypatch.setattr(httpx, "AsyncClient", RecordingClient)
    monkeypatch.setattr(client_module.wildbox_client, "gateway_secret", SECRET)
    return RecordingClient.sent


# --- Request schemas -------------------------------------------------------


@pytest.mark.parametrize(
    "ioc_type, value",
    [
        ("ipv4", "192.168.1.1"),
        ("domain", "example.com"),
        ("url", "https://example.com/path"),
        ("md5", "d41d8cd98f00b204e9800998ecf8427e"),
        ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("email", "analyst@example.com"),
    ],
)
def test_a_well_formed_ioc_is_accepted(ioc_type, value):
    ioc = IOCInput(type=ioc_type, value=value)
    assert ioc.type == ioc_type
    assert ioc.value == value


@pytest.mark.parametrize(
    "ioc_type, value",
    [
        ("ipv4", "not-an-ip"),
        ("domain", "no_tld"),
        ("url", "javascript:alert(1)"),
        ("md5", "d41d8cd98f00b204"),
        ("sha256", "XYZ"),
        ("email", "no-at-sign.example.com"),
    ],
)
def test_an_ioc_that_does_not_match_its_type_is_refused(ioc_type, value):
    with pytest.raises(ValidationError, match="Invalid format"):
        IOCInput(type=ioc_type, value=value)


def test_priority_defaults_to_normal_and_takes_only_known_levels():
    ioc = IOCInput(type="ipv4", value="192.168.1.1")
    assert AnalysisTaskRequest(ioc=ioc).priority == TaskPriority.NORMAL
    assert AnalysisTaskRequest(ioc=ioc, priority="high").priority == TaskPriority.HIGH
    with pytest.raises(ValidationError):
        AnalysisTaskRequest(ioc=ioc, priority="urgent")


# --- /v1/analyze -----------------------------------------------------------


@pytest.fixture
def api(monkeypatch):
    """The FastAPI app with Redis and the Celery queue replaced."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(main, "redis_client", FakeRedis())
    main.limiter.reset()

    enqueued = []

    class Enqueued:
        id = "celery-task-1"

    def delay(**kwargs):
        enqueued.append(kwargs)
        return Enqueued()

    monkeypatch.setattr(main.run_threat_enrichment_task, "delay", delay)
    return TestClient(main.app), enqueued


def gateway_headers(caller, secret=SECRET):
    return {
        "X-Wildbox-User-ID": caller["user_id"],
        "X-Wildbox-Team-ID": caller["team_id"],
        "X-Wildbox-Role": caller["role"],
        "X-Gateway-Secret": secret,
    }


def test_analyze_hands_the_callers_identity_to_the_worker(api):
    client, enqueued = api
    response = client.post(
        "/v1/analyze",
        json={"ioc": {"type": "domain", "value": "example.com"}},
        headers=gateway_headers(CALLER),
    )
    assert response.status_code == 202, response.text
    assert len(enqueued) == 1
    assert enqueued[0]["caller"] == CALLER
    assert enqueued[0]["ioc"] == {"type": "domain", "value": "example.com"}


def test_analyze_without_the_gateway_secret_enqueues_nothing(api):
    client, enqueued = api
    response = client.post(
        "/v1/analyze",
        json={"ioc": {"type": "domain", "value": "example.com"}},
        headers=gateway_headers(CALLER, secret="wrong"),
    )
    assert response.status_code in (401, 403), response.text
    assert enqueued == []


# --- Worker task -----------------------------------------------------------


@pytest.fixture
def task(monkeypatch):
    """The worker task with Redis, Celery state and the LLM agent replaced.

    The stand-in agent makes one real tool call through the client, so what
    reaches the wire is what the task set up, not what the test did.
    """

    class Agent:
        async def analyze_ioc(self, ioc):
            await client_module.wildbox_client.whois_lookup(ioc["value"])
            return {"verdict": "Benign"}

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", lambda: Agent())
    monkeypatch.setattr(worker, "redis_client", FakeRedis())
    monkeypatch.setattr(
        worker.run_threat_enrichment_task, "update_state", lambda *a, **k: None
    )
    return worker.run_threat_enrichment_task


def test_the_task_sends_the_callers_identity_on_its_tool_calls(task, recorded):
    result = task(
        task_id="task-1",
        ioc={"type": "domain", "value": "example.com"},
        caller=CALLER,
    )
    assert result["task_id"] == "task-1"
    assert len(recorded) == 1
    url, headers = recorded[0]
    assert url.endswith("/api/tools/whois_lookup")
    assert headers["X-Wildbox-User-ID"] == USER_ID
    assert headers["X-Wildbox-Team-ID"] == TEAM_ID
    assert headers["X-Wildbox-Role"] == "admin"
    assert headers["X-Gateway-Secret"] == SECRET


def test_a_task_without_a_caller_sends_nothing(task, recorded):
    with pytest.raises(CallerIdentityUnavailable):
        task(task_id="task-2", ioc={"type": "domain", "value": "example.com"})
    assert recorded == []


# --- Agent tools -----------------------------------------------------------


SAMPLE_ARGS = {"ip_address": "8.8.8.8", "url": "https://example.com"}


@pytest.mark.parametrize("tool", ALL_TOOLS, ids=lambda t: t.name)
def test_every_agent_tool_reaches_a_service_with_the_callers_identity(tool, recorded):
    """A tool whose name is missing from the client's allowlist answers
    "Unknown tool" without sending anything, so the agent loses it silently.
    """
    _caller_identity.set(dict(CALLER))
    args = {name: SAMPLE_ARGS.get(name, "example.com") for name in tool.args}

    output = asyncio.run(tool.ainvoke(args))

    assert "error" not in output, output
    assert len(recorded) == 1, f"{tool.name} sent {len(recorded)} requests"
    url, headers = recorded[0]
    assert headers["X-Wildbox-User-ID"] == USER_ID
    assert headers["X-Gateway-Secret"] == SECRET
    assert "X-API-Key" not in headers


# --- Configuration ---------------------------------------------------------


def test_the_client_takes_the_gateway_secret_from_the_environment(monkeypatch):
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", "secret-from-env")
    monkeypatch.setattr(client_module, "settings", Settings())
    assert WildboxAPIClient().gateway_secret == "secret-from-env"
