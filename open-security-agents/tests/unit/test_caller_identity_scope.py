"""Each analysis task forwards its own caller's identity, and only for itself.

The caller identity lives in a ContextVar. A Celery worker runs one task after
another in the same thread, so in the same context: before #594 the task set
the identity only when its caller was complete and never reset it, so a task
with no caller, or a partial one, would have sent its tool calls with the
previous task's user and team. Now every task sets the identity from its own
caller or is refused before doing anything, and restores the previous value
when it ends.

The agent's tool calls run in asyncio tasks (several at once through
asyncio.gather) and, for a sync tool, in a thread pool through LangChain's
run_in_executor. Both copy the context they start from; the last tests check
that the identity reaches the wire through each path.
"""

import asyncio
import os
import sys
import threading
import types

import pytest
from fastapi.testclient import TestClient
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import StructuredTool

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import main, worker  # noqa: E402
from app.agents.threat_enrichment_agent import ThreatEnrichmentAgent  # noqa: E402
from app.auth import get_current_user  # noqa: E402
from app.tools import wildbox_client as client_module  # noqa: E402
from app.tools.langchain_tools import ALL_TOOLS  # noqa: E402
from app.tools.wildbox_client import (  # noqa: E402
    CallerIdentityUnavailable,
    _caller_identity,
    caller_identity,
    require_caller_identity,
    reset_caller_identity,
    set_caller_identity,
)

SECRET = "gateway-secret-for-tests"
CALLER_A = {
    "user_id": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "team_id": "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b",
    "role": "admin",
}
CALLER_B = {
    "user_id": "0b3f0e4c-8d1a-4c2e-9f5b-1a2b3c4d5e6f",
    "team_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "role": "member",
}
IOC = {"type": "domain", "value": "example.com"}

INCOMPLETE_CALLERS = [
    pytest.param(None, id="no-caller"),
    pytest.param({}, id="empty"),
    pytest.param({"user_id": CALLER_B["user_id"]}, id="no-team"),
    pytest.param({"team_id": CALLER_B["team_id"]}, id="no-user"),
    pytest.param({"user_id": " ", "team_id": CALLER_B["team_id"]}, id="blank-user"),
    pytest.param({"user_id": CALLER_B["user_id"], "team_id": None}, id="null-team"),
]


@pytest.fixture(autouse=True)
def no_caller_identity():
    """Each test starts with no identity, and must leave none behind."""
    token = _caller_identity.set(None)
    yield
    _caller_identity.reset(token)


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
        RecordingClient.sent.append((url, dict(kwargs.get("headers") or {})))
        return Response()

    async def get(self, url, **kwargs):
        RecordingClient.sent.append((url, dict(kwargs.get("headers") or {})))
        return Response()


@pytest.fixture
def recorded(monkeypatch):
    """Requests the Wildbox client sends, none of them leaving the process."""
    import httpx

    RecordingClient.sent = []
    monkeypatch.setattr(httpx, "AsyncClient", RecordingClient)
    monkeypatch.setattr(client_module.wildbox_client, "gateway_secret", SECRET)
    return RecordingClient.sent


@pytest.fixture
def fake_redis(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(worker, "redis_client", redis)
    monkeypatch.setattr(
        worker.run_threat_enrichment_task, "update_state", lambda *a, **k: None
    )
    return redis


@pytest.fixture
def agent(monkeypatch, fake_redis):
    """A stand-in agent that makes one real tool call through the client."""

    class Agent:
        calls = 0
        error = None

        async def analyze_ioc(self, ioc):
            Agent.calls += 1
            await client_module.wildbox_client.whois_lookup(ioc["value"])
            if Agent.error is not None:
                raise Agent.error
            return {"verdict": "Benign"}

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", lambda: Agent())
    return Agent


def run_task(task_id, caller):
    if caller is None:
        return worker.run_threat_enrichment_task(task_id=task_id, ioc=IOC)
    return worker.run_threat_enrichment_task(task_id=task_id, ioc=IOC, caller=caller)


def sent_user_ids(recorded):
    return [headers.get("X-Wildbox-User-ID") for _, headers in recorded]


# --- One task after another in the same context ----------------------------


@pytest.mark.parametrize("caller_b", INCOMPLETE_CALLERS)
def test_a_task_without_a_complete_caller_never_sends_the_previous_identity(
    agent, fake_redis, recorded, caller_b
):
    """The #594 scenario: task A with a caller, then task B without one."""
    run_task("task-a", CALLER_A)
    assert sent_user_ids(recorded) == [CALLER_A["user_id"]]

    with pytest.raises(CallerIdentityUnavailable):
        run_task("task-b", caller_b)

    # B was refused before any work: its agent never ran, and the only
    # request on the wire is A's.
    assert agent.calls == 1
    assert sent_user_ids(recorded) == [CALLER_A["user_id"]]
    assert fake_redis.store["task:task-b:status"] == "failed"
    assert _caller_identity.get() is None


def test_each_task_sends_its_own_callers_identity(agent, recorded):
    run_task("task-a", CALLER_A)
    run_task("task-b", CALLER_B)
    run_task("task-a2", CALLER_A)

    assert [(h["X-Wildbox-User-ID"], h["X-Wildbox-Team-ID"]) for _, h in recorded] == [
        (CALLER_A["user_id"], CALLER_A["team_id"]),
        (CALLER_B["user_id"], CALLER_B["team_id"]),
        (CALLER_A["user_id"], CALLER_A["team_id"]),
    ]
    assert recorded[1][1]["X-Wildbox-Role"] == "member"
    assert _caller_identity.get() is None


def test_the_identity_is_reset_after_a_task_that_raised(agent, recorded):
    agent.error = RuntimeError("the agent blew up")
    with pytest.raises(RuntimeError, match="blew up"):
        run_task("task-a", CALLER_A)
    assert _caller_identity.get() is None

    agent.error = None
    with pytest.raises(CallerIdentityUnavailable):
        run_task("task-b", None)
    assert sent_user_ids(recorded) == [CALLER_A["user_id"]]


def test_the_identity_is_reset_after_a_task_that_failed_softly(agent, recorded):
    """A handled failure returns an error result; the scope still ends."""
    agent.error = ValueError("bad tool output")
    result = run_task("task-a", CALLER_A)
    assert result["verdict"] == "Informational"
    assert _caller_identity.get() is None


def test_the_task_restores_the_identity_it_found(agent, recorded):
    """The scope restores the previous value rather than blanking it."""
    token = set_caller_identity("outer-user", "outer-team")
    try:
        run_task("task-a", CALLER_A)
        assert _caller_identity.get()["user_id"] == "outer-user"
    finally:
        reset_caller_identity(token)
    assert sent_user_ids(recorded) == [CALLER_A["user_id"]]


# --- The scope helpers ------------------------------------------------------


def test_caller_identity_sets_and_restores():
    with caller_identity(CALLER_A) as identity:
        assert identity == CALLER_A
        assert _caller_identity.get() == CALLER_A
        with caller_identity(CALLER_B):
            assert _caller_identity.get() == CALLER_B
        assert _caller_identity.get() == CALLER_A
    assert _caller_identity.get() is None


def test_caller_identity_restores_after_an_exception():
    with pytest.raises(KeyError):
        with caller_identity(CALLER_A):
            raise KeyError("boom")
    assert _caller_identity.get() is None


@pytest.mark.parametrize("caller", INCOMPLETE_CALLERS)
def test_caller_identity_refuses_an_incomplete_caller_before_the_block(caller):
    ran = []
    with pytest.raises(CallerIdentityUnavailable):
        with caller_identity(caller):
            ran.append(True)
    assert ran == []
    assert _caller_identity.get() is None


def test_role_defaults_to_member():
    caller = {"user_id": "u", "team_id": "t", "role": None}
    assert require_caller_identity(caller)["role"] == "member"


def test_set_caller_identity_returns_a_token_and_refuses_a_blank_id():
    token = set_caller_identity("u", "t", "admin")
    assert _caller_identity.get() == {"user_id": "u", "team_id": "t", "role": "admin"}
    reset_caller_identity(token)
    assert _caller_identity.get() is None

    with pytest.raises(CallerIdentityUnavailable, match="team_id"):
        set_caller_identity("u", "")
    assert _caller_identity.get() is None


def test_the_client_refuses_a_partial_identity_set_directly(recorded):
    """Defence in depth: even a value written around the helpers is checked."""
    token = _caller_identity.set({"user_id": "u", "team_id": "", "role": "member"})
    try:
        with pytest.raises(CallerIdentityUnavailable, match="no caller identity"):
            client_module.wildbox_client._request_headers()
    finally:
        _caller_identity.reset(token)
    assert recorded == []


# --- Where the tool calls run -----------------------------------------------


class ToolCallingFakeModel(FakeMessagesListChatModel):
    """A scripted chat model the tool-calling agent can bind tools to."""

    def bind_tools(self, tools, **kwargs):
        return self


def test_the_identity_reaches_every_tool_call_through_the_real_agent(
    fake_redis, recorded, monkeypatch
):
    """The production AgentExecutor runs both tool calls of one turn
    concurrently, each in its own asyncio task. Each copies the task's context,
    so each request carries the task's caller, and the next task's do not.
    """
    turn = AIMessage(
        content="",
        tool_calls=[
            {"name": "whois_lookup_tool", "args": {"target": "example.com"}, "id": "1"},
            {"name": "dns_lookup_tool", "args": {"domain": "example.com"}, "id": "2"},
        ],
    )
    done = AIMessage(content="Benign.")

    def build_agent():
        agent = ThreatEnrichmentAgent.__new__(ThreatEnrichmentAgent)
        agent.llm = ToolCallingFakeModel(responses=[turn, done])
        agent.tools = ALL_TOOLS
        agent.agent_executor = agent._create_agent()
        return agent

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", build_agent)

    result = run_task("task-a", CALLER_A)
    assert sorted(result["tools_used"]) == ["dns_lookup_tool", "whois_lookup_tool"]
    assert sorted(url.rsplit("/", 1)[-1] for url, _ in recorded) == [
        "dns_enumerator",
        "whois_lookup",
    ]
    assert sent_user_ids(recorded) == [CALLER_A["user_id"]] * 2

    run_task("task-b", CALLER_B)
    assert sent_user_ids(recorded)[2:] == [CALLER_B["user_id"]] * 2

    with pytest.raises(CallerIdentityUnavailable):
        run_task("task-c", None)
    assert len(recorded) == 4


def test_the_identity_reaches_a_sync_tool_run_in_a_thread_pool(recorded):
    """LangChain runs a sync-only tool in a thread pool (run_in_executor),
    under a copy of the calling context: the identity crosses the thread.
    """
    seen = []

    def sync_lookup(target: str) -> str:
        """Look a target up from a worker thread."""
        headers = client_module.wildbox_client._request_headers()
        seen.append((threading.get_ident(), headers["X-Wildbox-User-ID"]))
        return "ok"

    tool = StructuredTool.from_function(func=sync_lookup)

    with caller_identity(CALLER_A):
        asyncio.run(tool.ainvoke({"target": "example.com"}))
    with caller_identity(CALLER_B):
        asyncio.run(tool.ainvoke({"target": "example.com"}))

    assert [user for _, user in seen] == [CALLER_A["user_id"], CALLER_B["user_id"]]
    assert all(ident != threading.get_ident() for ident, _ in seen)


# --- /v1/analyze ------------------------------------------------------------


@pytest.fixture
def api(monkeypatch):
    """The FastAPI app with Redis, the queue and the rate limit replaced."""
    redis = FakeRedis()
    monkeypatch.setattr(main, "redis_client", redis)
    monkeypatch.setattr(main.limiter, "enabled", False)

    enqueued = []

    class Enqueued:
        id = "celery-task-1"

    def delay(**kwargs):
        enqueued.append(kwargs)
        return Enqueued()

    monkeypatch.setattr(main.run_threat_enrichment_task, "delay", delay)
    yield TestClient(main.app), enqueued, redis
    main.app.dependency_overrides.pop(get_current_user, None)


def as_user(**fields):
    user = types.SimpleNamespace(**fields)
    main.app.dependency_overrides[get_current_user] = lambda: user


def test_analyze_refuses_a_user_without_a_team_before_any_work(api):
    client, enqueued, redis = api
    as_user(user_id=CALLER_A["user_id"], team_id=None, role="member")

    response = client.post("/v1/analyze", json={"ioc": IOC})

    assert response.status_code == 403
    assert enqueued == []
    assert redis.store == {}


def test_analyze_enqueues_the_complete_caller(api):
    client, enqueued, _ = api
    as_user(**CALLER_A)

    response = client.post("/v1/analyze", json={"ioc": IOC})

    assert response.status_code == 202, response.text
    assert enqueued[0]["caller"] == CALLER_A
