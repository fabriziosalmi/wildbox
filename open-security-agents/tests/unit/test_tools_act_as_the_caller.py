"""The threat-intelligence and vulnerability tools answer for the caller (#652).

Both tools now reach a real route, so what they return matters: the data
service and Guardian hold every team's rows, and the tools must hand the
model the rows of the user who submitted the analysis and nobody else's.
They do it the way the gateway would: each request carries that user's
identity and the gateway secret, and the service scopes its answer.

The services here are stand-ins (tests/unit/wildbox_services.py) seeded with
the rows of two teams. No test calls the Anthropic API: the tools are called
directly, and once through the production AgentExecutor with a scripted
model.
"""

import asyncio
import json
import os
import sys

import httpx
import pytest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import wildbox_services as services_module  # noqa: E402
from app import worker  # noqa: E402
from app.agents.threat_enrichment_agent import ThreatEnrichmentAgent  # noqa: E402
from app.config import settings  # noqa: E402
from app.tools import wildbox_client as client_module  # noqa: E402
from app.tools.langchain_tools import (  # noqa: E402
    ALL_TOOLS,
    threat_intel_query_tool,
    vulnerability_search_tool,
)
from app.tools.wildbox_client import (  # noqa: E402
    CallerIdentityUnavailable,
    _caller_identity,
    caller_identity,
)

pytestmark = pytest.mark.skipif(
    not services_module.sources_available(),
    reason="the other services' sources are not here",
)

TEAM_A = "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b"
TEAM_B = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
ALICE = {
    "user_id": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "team_id": TEAM_A,
    "role": "owner",
}
ANNA = {
    "user_id": "5e2d1c0b-9a8f-4e7d-8c6b-5a4f3e2d1c0b",
    "team_id": TEAM_A,
    "role": "member",
}
BOB = {
    "user_id": "0b3f0e4c-8d1a-4c2e-9f5b-1a2b3c4d5e6f",
    "team_id": TEAM_B,
    "role": "owner",
}

IOC = "203.0.113.10"
INDICATORS = [
    {
        "team_id": None,
        "indicator_type": "ip_address",
        "value": IOC,
        "description": "shared feed",
    },
    {
        "team_id": TEAM_A,
        "indicator_type": "ip_address",
        "value": IOC,
        "description": "seen by team A",
    },
    {
        "team_id": TEAM_B,
        "indicator_type": "ip_address",
        "value": IOC,
        "description": "seen by team B",
    },
    {
        "team_id": TEAM_A,
        "indicator_type": "url",
        "value": f"http://{IOC}/gate.php",
        "description": "A's url",
    },
]
VULNERABILITIES = [
    {
        "team_id": TEAM_A,
        "created_by": ALICE["user_id"],
        "title": "OpenSSH regreSSHion on web-1",
        "cve_id": "CVE-2024-6387",
        "asset_name": "web-1",
    },
    {
        "team_id": TEAM_A,
        "created_by": ANNA["user_id"],
        "title": "OpenSSH regreSSHion on db-1",
        "cve_id": "CVE-2024-6387",
        "asset_name": "db-1",
    },
    {
        "team_id": TEAM_B,
        "created_by": BOB["user_id"],
        "title": "OpenSSH regreSSHion on team B's bastion",
        "cve_id": "CVE-2024-6387",
        "asset_name": "bastion-b",
    },
]


@pytest.fixture(autouse=True)
def no_caller_identity():
    """Each test starts, and leaves, with no caller identity set."""
    _caller_identity.set(None)
    yield
    _caller_identity.set(None)


@pytest.fixture
def services(monkeypatch):
    return services_module.install(
        monkeypatch,
        client_module,
        services_module.Services(settings, INDICATORS, VULNERABILITIES),
    )


def call(tool, caller, **args):
    with caller_identity(caller):
        return json.loads(asyncio.run(tool.ainvoke(args)))


def descriptions(output):
    return sorted(i["description"] for i in output["indicators"])


def titles(output):
    return sorted(v["title"] for v in output["vulnerabilities"])


# --- Threat intelligence: the caller's team and the shared feeds ------------


def test_threat_intel_answers_with_the_callers_team_and_the_shared_feeds(services):
    output = call(threat_intel_query_tool, ALICE, ioc_value=IOC)

    assert output["success"] is True
    assert descriptions(output) == ["A's url", "seen by team A", "shared feed"]
    assert output["total"] == output["returned"] == 3


def test_threat_intel_never_shows_another_teams_indicators(services):
    a = call(threat_intel_query_tool, ALICE, ioc_value=IOC)
    b = call(threat_intel_query_tool, BOB, ioc_value=IOC)

    assert "seen by team B" not in descriptions(a)
    assert descriptions(b) == ["seen by team B", "shared feed"]


def test_threat_intel_sends_the_callers_identity_and_nothing_else(services):
    call(threat_intel_query_tool, ALICE, ioc_value=IOC)
    call(threat_intel_query_tool, BOB, ioc_value=IOC)

    sent = [
        (
            r.headers["X-Wildbox-User-ID"],
            r.headers["X-Wildbox-Team-ID"],
            r.headers["X-Wildbox-Role"],
        )
        for r in services.sent_to("data")
    ]
    assert sent == [
        (ALICE["user_id"], TEAM_A, "owner"),
        (BOB["user_id"], TEAM_B, "owner"),
    ]
    for request in services.requests:
        assert request.headers["X-Gateway-Secret"] == services_module.SECRET
        assert "X-API-Key" not in request.headers
        assert "Authorization" not in request.headers


def test_threat_intel_marks_the_exact_match_apart_from_related_indicators(services):
    output = call(threat_intel_query_tool, ALICE, ioc_value=IOC)

    exact = {i["description"]: i["exact_match"] for i in output["indicators"]}
    assert exact == {"shared feed": True, "seen by team A": True, "A's url": False}


def test_threat_intel_filters_by_the_type_given(services):
    output = call(threat_intel_query_tool, ALICE, ioc_value=IOC, ioc_type="url")

    assert descriptions(output) == ["A's url"]
    assert output["indicator_type"] == "url"


def test_threat_intel_with_nothing_recorded_says_so_and_invents_nothing(services):
    output = call(threat_intel_query_tool, ALICE, ioc_value="198.51.100.77")

    assert output["success"] is True
    assert output["total"] == 0 and output["indicators"] == []


def test_a_search_result_carries_no_internal_field(services):
    """Row ids, source ids and metadata blobs are of no use to the model."""
    output = call(threat_intel_query_tool, ALICE, ioc_value=IOC)

    for indicator in output["indicators"]:
        assert not {"id", "source_id", "indicator_metadata", "team_id"} & set(indicator)
    assert services_module.no_address(
        json.dumps({**output, "indicators": []}), settings
    )


# --- Vulnerabilities: Guardian's answer for the caller ----------------------


def test_vulnerabilities_are_those_of_the_callers_team(services):
    a = call(vulnerability_search_tool, ALICE, query="CVE-2024-6387")
    b = call(vulnerability_search_tool, BOB, query="CVE-2024-6387")

    assert titles(a) == ["OpenSSH regreSSHion on db-1", "OpenSSH regreSSHion on web-1"]
    assert titles(b) == ["OpenSSH regreSSHion on team B's bastion"]
    assert a["total"] == 2 and b["total"] == 1


def test_a_member_sees_what_guardian_shows_a_member(services):
    """The caller's role goes with the request: no service identity sees more."""
    output = call(vulnerability_search_tool, ANNA, query="CVE-2024-6387")

    assert titles(output) == ["OpenSSH regreSSHion on db-1"]
    [request] = services.sent_to("guardian")
    assert request.headers["X-Wildbox-Role"] == "member"
    assert request.headers["X-Wildbox-User-ID"] == ANNA["user_id"]


def test_vulnerabilities_are_searched_by_asset_name(services):
    output = call(vulnerability_search_tool, ALICE, query="web-1")

    assert titles(output) == ["OpenSSH regreSSHion on web-1"]


def test_a_vulnerability_result_has_no_link_and_no_row_id(services):
    output = call(vulnerability_search_tool, ALICE, query="CVE-2024-6387")

    assert "next" not in output and "previous" not in output
    for vulnerability in output["vulnerabilities"]:
        assert "id" not in vulnerability
    assert services_module.no_address(json.dumps(output), settings)


# --- Without an identity nothing is sent ------------------------------------


@pytest.mark.parametrize(
    "tool, args",
    [
        (threat_intel_query_tool, {"ioc_value": IOC}),
        (vulnerability_search_tool, {"query": "CVE-2024-6387"}),
    ],
    ids=["threat_intel", "vulnerabilities"],
)
def test_without_a_caller_the_tool_sends_nothing(services, tool, args):
    with pytest.raises(CallerIdentityUnavailable):
        asyncio.run(tool.ainvoke(args))
    assert services.requests == []


@pytest.mark.parametrize(
    "tool, args",
    [
        (threat_intel_query_tool, {"ioc_value": IOC}),
        (vulnerability_search_tool, {"query": "CVE-2024-6387"}),
    ],
    ids=["threat_intel", "vulnerabilities"],
)
def test_without_the_gateway_secret_the_tool_sends_nothing(
    services, monkeypatch, tool, args
):
    monkeypatch.setattr(client_module.wildbox_client, "gateway_secret", "")
    with pytest.raises(CallerIdentityUnavailable):
        with caller_identity(ALICE):
            asyncio.run(tool.ainvoke(args))
    assert services.requests == []


# --- A failure is an error result, never data -------------------------------


FAILING = [
    (threat_intel_query_tool, {"ioc_value": IOC}, "data", "data service"),
    (
        vulnerability_search_tool,
        {"query": "CVE-2024-6387"},
        "guardian",
        "guardian service",
    ),
]


@pytest.mark.parametrize(
    "tool, args, service, name", FAILING, ids=["threat_intel", "vulnerabilities"]
)
def test_an_unreachable_service_is_an_error_result(services, tool, args, service, name):
    """httpx.ConnectError is not a builtin ConnectionError: the vulnerability
    tool caught only builtins, so this raised into the agent."""
    services.down.add(service)

    output = call(tool, ALICE, **args)

    assert output["success"] is False
    assert name in output["error"] and "could not be reached" in output["error"]
    assert "indicators" not in output and "vulnerabilities" not in output
    assert services_module.no_address(json.dumps(output), settings)


@pytest.mark.parametrize(
    "tool, args, service, name", FAILING, ids=["threat_intel", "vulnerabilities"]
)
@pytest.mark.parametrize("status", [401, 403, 404, 500, 503])
def test_a_refusal_is_reported_with_the_services_status(
    services, tool, args, service, name, status
):
    services.answers[service] = (status, {"error": {"code": status, "message": "No."}})

    output = call(tool, ALICE, **args)

    assert output["success"] is False
    assert output["status_code"] == status
    assert f"The {name} answered {status}: No." == output["error"]
    assert len(services.requests) == 1, "a failed call is not retried"
    assert services_module.no_address(json.dumps(output), settings)


@pytest.mark.parametrize(
    "tool, args, service, name", FAILING, ids=["threat_intel", "vulnerabilities"]
)
@pytest.mark.parametrize(
    "body",
    [
        "<html>gateway timeout</html>",
        [1, 2],
        {"success": True},
        {"indicators": "many", "total": 1},
    ],
    ids=["not-json", "a-list", "another-object", "wrong-types"],
)
def test_an_answer_of_another_shape_is_an_error_not_an_empty_result(
    services, tool, args, service, name, body
):
    """ "Nothing found" is a statement about the service's data; an answer
    the tool cannot read supports no statement at all."""
    services.answers[service] = (200, body)

    output = call(tool, ALICE, **args)

    assert output["success"] is False
    assert name in output["error"]
    assert "total" not in output


def test_a_redirect_is_not_followed(services):
    """Guardian redirects (to https://, or to a path with its trailing
    slash); the tool reports the answer and goes nowhere else, least of all
    with the caller's identity and the gateway secret in its headers."""
    elsewhere = f"{settings.wildbox_data_url}/api/v1/indicators/search?q=x"
    services.answers["guardian"] = httpx.Response(301, headers={"Location": elsewhere})

    output = call(vulnerability_search_tool, ALICE, query="CVE-2024-6387")

    assert output["success"] is False and output["status_code"] == 301
    assert len(services.requests) == 1
    assert services.sent_to("data") == []


def test_a_wrong_secret_gets_the_services_refusal_not_data(services, monkeypatch):
    monkeypatch.setattr(
        client_module.wildbox_client, "gateway_secret", "not-the-secret"
    )

    for tool, args in (
        (threat_intel_query_tool, {"ioc_value": IOC}),
        (vulnerability_search_tool, {"query": "CVE"}),
    ):
        output = call(tool, ALICE, **args)
        assert output["success"] is False and output["status_code"] == 403


def test_a_tools_service_error_does_not_carry_its_address(services):
    """str() of an httpx error has the full internal URL; the result is read
    by the model, which can quote it in the report."""
    services.down.add("tools")
    with caller_identity(ALICE):
        unreachable = asyncio.run(
            client_module.wildbox_client.whois_lookup("example.com")
        )
    services.down.clear()
    services.answers["tools"] = (
        400,
        {"error": {"code": 400, "message": "Target refused"}},
    )
    with caller_identity(ALICE):
        refused = asyncio.run(client_module.wildbox_client.whois_lookup("example.com"))

    assert unreachable == {
        "success": False,
        "error": "The tools service could not be reached (ConnectError)",
    }
    assert refused == {
        "success": False,
        "error": "The tools service answered 400: Target refused",
        "status_code": 400,
    }


def test_a_refused_input_tells_the_model_which_field_and_why(services):
    """The tools service names the fields it refused (#585); the model needs
    them to correct its call."""
    services.answers["tools"] = (
        422,
        {
            "error": {
                "code": 422,
                "message": "Input validation failed",
                "details": {
                    "errors": [
                        {"loc": ["domain"], "msg": "Field required", "type": "missing"}
                    ]
                },
            }
        },
    )
    with caller_identity(ALICE):
        output = asyncio.run(client_module.wildbox_client.whois_lookup("example.com"))

    assert output["status_code"] == 422
    assert "Input validation failed" in output["error"]
    assert "domain" in output["error"] and "Field required" in output["error"]


def test_a_rate_limited_tool_is_retried_then_reported(services, monkeypatch):
    slept = []

    async def sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(client_module.asyncio, "sleep", sleep)
    services.answers["tools"] = (429, {"error": {"code": 429, "message": "Slow down"}})

    with caller_identity(ALICE):
        output = asyncio.run(client_module.wildbox_client.whois_lookup("example.com"))

    assert output["success"] is False and output["status_code"] == 429
    assert slept == [1.0, 2.0, 4.0]
    assert len(services.sent_to("tools")) == 4


# --- Through the production agent, with a scripted model ---------------------


class ToolCallingFakeModel(FakeMessagesListChatModel):
    """A scripted chat model the tool-calling agent can bind tools to."""

    def bind_tools(self, tools, **kwargs):
        return self


class FakeRedis:
    def __init__(self):
        self.store = {}

    def setex(self, key, ttl, value):
        self.store[key] = value

    def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1

    def expire(self, key, ttl):
        return True

    def pipeline(self):
        return self

    def execute(self):
        return []


def test_the_agents_own_tool_calls_reach_the_services_as_the_tasks_caller(
    services, monkeypatch
):
    """The whole path but the model: the worker task sets the caller, the
    production AgentExecutor runs both tools of one turn, and each request
    arrives as that caller. The next task's arrive as its own."""
    monkeypatch.setattr(worker, "redis_client", FakeRedis())
    monkeypatch.setattr(
        worker.run_threat_enrichment_task, "update_state", lambda *a, **k: None
    )

    def build_agent():
        turn = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "threat_intel_query_tool",
                    "args": {"ioc_value": IOC, "ioc_type": "ipv4"},
                    "id": "1",
                },
                {
                    "name": "vulnerability_search_tool",
                    "args": {"query": "CVE-2024-6387"},
                    "id": "2",
                },
            ],
        )
        agent = ThreatEnrichmentAgent.__new__(ThreatEnrichmentAgent)
        agent.llm = ToolCallingFakeModel(
            responses=[turn, AIMessage(content="Suspicious.")]
        )
        agent.tools = ALL_TOOLS
        agent.agent_executor = agent._create_agent()
        return agent

    monkeypatch.setattr(worker, "get_threat_enrichment_agent", build_agent)
    ioc = {"type": "ipv4", "value": IOC}

    result_a = worker.run_threat_enrichment_task(task_id="task-a", ioc=ioc, caller=ANNA)
    result_b = worker.run_threat_enrichment_task(task_id="task-b", ioc=ioc, caller=BOB)

    assert sorted(result_a["tools_used"]) == [
        "threat_intel_query_tool",
        "vulnerability_search_tool",
    ]
    by_service = {s: services.sent_to(s) for s in ("data", "guardian")}
    for service, requests in by_service.items():
        assert [
            (r.headers["X-Wildbox-User-ID"], r.headers["X-Wildbox-Team-ID"])
            for r in requests
        ] == [
            (ANNA["user_id"], TEAM_A),
            (BOB["user_id"], TEAM_B),
        ], service

    # What the model was handed for each task is that caller's data.
    seen_a = json.dumps(result_a["raw_data"])
    seen_b = json.dumps(result_b["raw_data"])
    assert "seen by team A" in seen_a and "seen by team B" not in seen_a
    assert "db-1" in seen_a and "web-1" not in seen_a and "bastion-b" not in seen_a
    assert "seen by team B" in seen_b and "seen by team A" not in seen_b
    assert "bastion-b" in seen_b and "db-1" not in seen_b
    assert _caller_identity.get() is None


def test_the_stand_in_refuses_what_the_real_services_refuse(services):
    """The premise of this file: a request to a route the service does not
    serve is answered 404 by the stand-in, as #652's routes were."""

    async def get(url, **extra):
        async with client_module.httpx.AsyncClient() as client:
            return await client.get(
                url, headers={"X-Gateway-Secret": services_module.SECRET, **extra}
            )

    guardian_url = f"{settings.wildbox_guardian_url}/api/v1/vulnerabilities/search"
    for url in (f"{settings.wildbox_data_url}/api/v1/threat-intel/query", guardian_url):
        # Guardian redirects plain HTTP unless the caller says the request
        # arrived over TLS (#707); the client always says so.
        response = asyncio.run(get(url, **{"X-Forwarded-Proto": "https"}))
        assert response.status_code == 404, url
    # Without that header the stand-in redirects, as Guardian does.
    assert asyncio.run(get(guardian_url)).status_code == 301
    assert isinstance(httpx.ConnectError("x"), httpx.HTTPError)
    assert not isinstance(httpx.ConnectError("x"), ConnectionError)
