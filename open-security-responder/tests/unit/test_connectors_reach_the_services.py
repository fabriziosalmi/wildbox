"""Each HTTP connector action calls a route its service serves, as the caller.

Until #616 none of them could reach the service it named: the tools route
and body were wrong, the agents request had the wrong shape, the data
service has no blacklist, and no request carried the identity the services
authenticate. These tests call every action the api, wildbox and data
connectors offer and check the request each one sends:

- the route is one the target service declares, read from its source;
- the body or query is made of the fields that service validates, read from
  its schemas, serializers and filters;
- it carries the gateway identity of the run's caller and the gateway secret,
  and nothing is sent without them;
- a failure is reported with the service's status, after a single attempt.
"""

import contextvars
import os
import sys
import threading
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

import service_contracts as contracts  # noqa: E402
from app.caller import CallerIdentityUnavailable, run_as  # noqa: E402
from app.config import settings  # noqa: E402
from app.connectors import connector_registry  # noqa: E402
from app.connectors.base import ConnectorError  # noqa: E402

pytestmark = pytest.mark.skipif(
    not contracts.sources_available(),
    reason="the other services' sources are not here",
)

CALLER = {
    "user_id": "3c9d6e2a-8b1f-4a7c-9d0e-5f2a1b3c4d5e",
    "team_id": "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b",
    "role": "admin",
}
TASK_ID = "1f2e3d4c-5b6a-4978-8a9b-0c1d2e3f4a5b"
ASSET_ID = "7a3e9c1b-5d2f-4b8a-9e6c-1f0d2b4a6c83"


class Recorder:
    """A transport that records each request and answers as the service would.

    A request the real service would refuse (unknown route, no identity, a
    wrong secret) gets the refusal; otherwise ``status`` and ``body``.
    """

    def __init__(self, status=None, body=None):
        self.status = status
        self.body = body
        self.requests = []

    def service(self, request):
        for name, url in (
            ("tools", settings.wildbox_api_url),
            ("data", settings.wildbox_data_url),
            ("guardian", settings.wildbox_guardian_url),
            ("agents", settings.wildbox_agents_url),
        ):
            if str(request.url).startswith(url.rstrip("/") + "/"):
                return name
        raise AssertionError(f"request to an unknown service: {request.url}")

    def __call__(self, request):
        self.requests.append(request)
        refused = contracts.refusal(
            self.service(request), request, settings.gateway_internal_secret
        )
        if refused:
            return httpx.Response(refused[0], json={"detail": refused[1]})
        if self.status is not None:
            return httpx.Response(self.status, json=self.body)
        return default_answer(request)


def default_answer(request):
    path = request.url.path
    if path == "/api/v1/assets/assets/":
        return httpx.Response(
            200,
            json={
                "count": 1,
                "results": [
                    {"id": ASSET_ID, "name": "web-1", "ip_address": "203.0.113.7"}
                ],
            },
        )
    if request.method == "POST" and path == "/api/v1/vulnerabilities/":
        return httpx.Response(201, json={"id": "v-1"})
    if path.endswith("/async") or path == "/v1/analyze":
        return httpx.Response(202, json={"task_id": TASK_ID})
    if path == "/api/tools":
        return httpx.Response(200, json=[{"name": "port_scanner"}])
    return httpx.Response(200, json={"ok": True})


@pytest.fixture
def recorder(monkeypatch):
    recorder = Recorder()
    for name in ("api", "wildbox", "data"):
        connector = connector_registry.get_connector(name)
        monkeypatch.setattr(
            connector, "client", httpx.Client(transport=httpx.MockTransport(recorder))
        )
    return recorder


def call(connector, action, **params):
    with run_as(CALLER):
        return connector_registry.execute_action(connector, action, params)


# Every action of every HTTP connector, called the way a playbook calls it,
# and the service it must reach. A test below checks that this table lists
# all of them, so an action added later cannot go unchecked.
ACTIONS = {
    ("api", "run_tool"): (
        "tools",
        {"tool_name": "port_scanner", "params": {"target": "203.0.113.7"}},
    ),
    ("api", "list_tools"): ("tools", {}),
    ("api", "get_tool_info"): ("tools", {"tool_name": "port_scanner"}),
    ("api", "cancel_execution"): ("tools", {"execution_id": TASK_ID}),
    ("api", "get_execution_status"): ("tools", {"execution_id": TASK_ID}),
    ("wildbox", "run_tool"): (
        "tools",
        {"tool_name": "port_scanner", "params": {"target": "203.0.113.7"}},
    ),
    ("wildbox", "query_threat_intel"): (
        "data",
        {"query": "203.0.113.7", "indicator_type": "ip_address"},
    ),
    ("wildbox", "get_vulnerabilities"): (
        "guardian",
        {"asset_id": ASSET_ID, "severity": "high"},
    ),
    ("wildbox", "create_vulnerability"): (
        "guardian",
        {
            "title": "Exposed telnet",
            "description": "telnet answers on 23",
            "severity": "high",
            "asset_name": "203.0.113.7",
        },
    ),
    ("wildbox", "analyze_ioc"): (
        "agents",
        {"ioc_type": "ipv4", "ioc_value": "203.0.113.7"},
    ),
    ("wildbox", "get_asset_info"): ("guardian", {"asset_id": ASSET_ID}),
    ("data", "search_indicators"): (
        "data",
        {"query": "evil.example", "indicator_type": "domain", "confidence": "high"},
    ),
    ("data", "lookup_indicators"): (
        "data",
        {"indicators": [{"indicator_type": "ip_address", "value": "203.0.113.7"}]},
    ),
}


def test_the_table_lists_every_action():
    offered = {
        (name, action)
        for name in ("api", "wildbox", "data")
        for action in connector_registry.get_connector(name).get_available_actions()
    }
    assert offered == set(ACTIONS)


@pytest.mark.parametrize("key", sorted(ACTIONS), ids="{0[0]}.{0[1]}".format)
def test_each_action_calls_a_route_its_service_serves_as_the_caller(recorder, key):
    service, params = ACTIONS[key]
    call(*key, **params)
    assert recorder.requests, f"{key} sent nothing"
    for request in recorder.requests:
        assert recorder.service(request) == service
        assert contracts.route_for(
            contracts.routes_of(service), request.method, request.url.path
        ), f"{service} serves no {request.method} {request.url.path}"
        assert request.headers["X-Wildbox-User-ID"] == CALLER["user_id"]
        assert request.headers["X-Wildbox-Team-ID"] == CALLER["team_id"]
        assert request.headers["X-Wildbox-Role"] == CALLER["role"]
        assert request.headers["X-Gateway-Secret"] == settings.gateway_internal_secret


# --- The bodies and queries are the services' own ---------------------------


def body(request):
    import json

    return json.loads(request.content)


def test_run_tool_sends_the_tool_input_itself(recorder):
    params = {"target": "203.0.113.7", "ports": [22], "scan_type": "tcp"}
    call("api", "run_tool", tool_name="port_scanner", params=params)
    [request] = recorder.requests
    assert (request.method, request.url.path) == ("POST", "/api/tools/port_scanner")
    # Not wrapped in {"params": ...}: the body is validated as the input schema.
    assert body(request) == params
    tool_input = contracts.REPO_ROOT / "open-security-tools/app/tools/port_scanner"
    assert not contracts.model_problems(
        params, tool_input / "schemas.py", "PortScannerInput"
    )


def test_run_tool_can_queue_the_tool(recorder):
    result = call(
        "api",
        "run_tool",
        tool_name="hash_generator",
        params={"input_text": "x"},
        async_execution=True,
    )
    [request] = recorder.requests
    assert request.url.path == "/api/tools/hash_generator/async"
    assert body(request) == {"input_text": "x"}
    assert result == {"task_id": TASK_ID}


def test_list_tools_answers_a_mapping(recorder):
    """A step's output is a mapping; the tools service answers a list."""
    assert call("api", "list_tools") == {"tools": [{"name": "port_scanner"}]}


@pytest.mark.parametrize("name", ["../identity", "port_scanner/async", "", 7])
def test_a_tool_name_cannot_steer_the_route(recorder, name):
    with pytest.raises(ConnectorError, match="Invalid tool name"):
        call("api", "run_tool", tool_name=name, params={})
    assert recorder.requests == []


def test_a_task_id_cannot_steer_the_route(recorder):
    with pytest.raises(ConnectorError, match="Invalid task id"):
        call("api", "get_execution_status", execution_id="../../tools")
    assert recorder.requests == []


def test_analyze_ioc_sends_an_analysis_task_request(recorder):
    task = call("wildbox", "analyze_ioc", ioc_type="ipv4", ioc_value="203.0.113.7")
    [request] = recorder.requests
    sent = body(request)
    assert sent == {
        "ioc": {"type": "ipv4", "value": "203.0.113.7"},
        "priority": "normal",
    }
    assert not contracts.model_problems(
        sent, contracts.AGENTS_SCHEMAS, "AnalysisTaskRequest"
    )
    assert not contracts.model_problems(
        sent["ioc"], contracts.AGENTS_SCHEMAS, "IOCInput"
    )
    # A task, not a verdict.
    assert task == {"task_id": TASK_ID}


def test_the_ioc_types_and_priorities_are_the_agents_service_ones():
    from app.connectors import wildbox_connector

    assert set(wildbox_connector.AGENTS_IOC_TYPES) == contracts.enum_values(
        contracts.AGENTS_SCHEMAS, "IOCType"
    )
    assert set(wildbox_connector.AGENTS_PRIORITIES) == contracts.enum_values(
        contracts.AGENTS_SCHEMAS, "TaskPriority"
    )


def test_create_vulnerability_sends_what_guardian_validates(recorder):
    result = call(
        "wildbox",
        "create_vulnerability",
        title="Exposed telnet",
        description="telnet answers on 23",
        severity="critical",
        asset_name="203.0.113.7",
        cve_id="CVE-2026-0001",
    )
    lookup, create = recorder.requests
    assert lookup.url.params["search"] == "203.0.113.7"
    sent = body(create)
    fields = contracts.serializer_fields(
        contracts.GUARDIAN_VULN_SERIALIZERS, "VulnerabilityCreateSerializer"
    )
    required = contracts.django_required_fields(
        contracts.GUARDIAN_VULN_MODELS, "Vulnerability"
    )
    assert set(sent) <= fields, f"Guardian ignores {sorted(set(sent) - fields)}"
    assert required <= set(sent), f"Guardian requires {sorted(required - set(sent))}"
    assert sent["asset"] == ASSET_ID
    assert sent["priority"] == "p1"
    assert sent["cve_id"] == "CVE-2026-0001"
    assert result == {"id": "v-1"}


def test_create_vulnerability_needs_exactly_one_known_asset(recorder):
    recorder.status, recorder.body = 200, {"count": 0, "results": []}
    with pytest.raises(ConnectorError, match="no asset named or addressed"):
        call(
            "wildbox",
            "create_vulnerability",
            title="t",
            description="d",
            severity="low",
            asset_name="198.51.100.1",
        )
    # Only the lookup was sent.
    assert [r.method for r in recorder.requests] == ["GET"]


def test_create_vulnerability_refuses_an_ambiguous_asset(recorder):
    twins = [
        {"id": ASSET_ID, "name": "web", "ip_address": "203.0.113.7"},
        {"id": TASK_ID, "name": "203.0.113.7", "ip_address": "198.51.100.9"},
    ]
    recorder.status, recorder.body = 200, {"count": 2, "results": twins}
    with pytest.raises(ConnectorError, match="2 Guardian assets"):
        call(
            "wildbox",
            "create_vulnerability",
            title="t",
            description="d",
            severity="low",
            asset_name="203.0.113.7",
        )
    assert [r.method for r in recorder.requests] == ["GET"]


def test_get_vulnerabilities_filters_are_guardian_ones(recorder):
    call("wildbox", "get_vulnerabilities", asset_id=ASSET_ID, severity="high")
    [request] = recorder.requests
    names = contracts.filterset_names(
        contracts.GUARDIAN_VULN_FILTERS, "VulnerabilityFilter"
    )
    assert set(request.url.params) <= names


@pytest.mark.parametrize(
    "connector, action, params",
    [
        ("wildbox", "query_threat_intel", {"query": "x", "indicator_type": "url"}),
        (
            "data",
            "search_indicators",
            {"query": "x", "indicator_type": "url", "confidence": "high"},
        ),
    ],
)
def test_indicator_searches_send_the_data_service_query(
    recorder, connector, action, params
):
    call(connector, action, **params)
    [request] = recorder.requests
    accepted = contracts.function_parameters(contracts.DATA_MAIN, "search_indicators")
    assert set(request.url.params) <= accepted
    assert request.url.params["q"] == "x"


def test_lookup_indicators_sends_a_bulk_lookup_request(recorder):
    items = [
        {"indicator_type": "ip_address", "value": "203.0.113.7"},
        {"indicator_type": "file_hash", "value": "a" * 64},
    ]
    call("data", "lookup_indicators", indicators=items)
    [request] = recorder.requests
    sent = body(request)
    assert sent == {"indicators": items}
    assert not contracts.model_problems(
        sent, contracts.DATA_SCHEMAS, "BulkLookupRequest"
    )
    for item in sent["indicators"]:
        assert not contracts.model_problems(
            item, contracts.DATA_SCHEMAS, "BulkLookupItem"
        )


def test_the_indicator_types_are_the_data_service_ones():
    from app.connectors import data_connector

    assert set(data_connector.INDICATOR_TYPES) == contracts.enum_values(
        contracts.DATA_MODELS, "IndicatorType"
    )


def test_the_removed_actions_are_gone():
    """No action pretends to reach a route no service serves (#616)."""
    removed = {
        "wildbox": {"add_to_blacklist", "isolate_endpoint", "create_ticket"},
        "data": {
            "add_to_blacklist",
            "remove_from_blacklist",
            "check_blacklist",
            "query_iocs",
            "add_ioc",
            "get_threat_feed",
            "update_reputation",
            "get_asset_inventory",
        },
    }
    for name, actions in removed.items():
        offered = connector_registry.get_connector(name).get_available_actions()
        assert not actions & set(offered)
        with pytest.raises(ConnectorError, match="not found"):
            connector_registry.execute_action(name, sorted(actions)[0], {})


# --- Identity ---------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(ACTIONS), ids="{0[0]}.{0[1]}".format)
def test_nothing_is_sent_without_a_caller(recorder, key):
    _, params = ACTIONS[key]
    with pytest.raises(ConnectorError, match="no caller identity"):
        connector_registry.execute_action(*key, params)
    assert recorder.requests == []


def test_nothing_is_sent_without_the_gateway_secret(recorder, monkeypatch):
    monkeypatch.setattr(settings, "gateway_internal_secret", None)
    with pytest.raises(ConnectorError, match="GATEWAY_INTERNAL_SECRET is not set"):
        call("api", "list_tools")
    assert recorder.requests == []


@pytest.mark.parametrize(
    "caller",
    [
        None,
        {},
        {"user_id": " ", "team_id": "t"},
        {"user_id": "u"},
        {"user_id": "u", "team_id": "t", "role": "root"},
    ],
)
def test_an_incomplete_caller_is_refused_before_it_is_set(caller):
    from app.caller import current_caller

    with pytest.raises(CallerIdentityUnavailable):
        with run_as(caller):
            pass  # pragma: no cover
    assert current_caller() is None


def test_the_caller_is_reset_after_its_block_even_on_error():
    from app.caller import current_caller

    with pytest.raises(RuntimeError):
        with run_as(CALLER):
            assert current_caller()["user_id"] == CALLER["user_id"]
            raise RuntimeError("step failed")
    assert current_caller() is None


def test_the_caller_follows_a_copied_context_into_a_thread(recorder):
    """A step handed to a thread keeps its caller only with copy_context()."""
    outcomes = {}

    def list_tools(label):
        try:
            connector_registry.execute_action("api", "list_tools", {})
            outcomes[label] = "sent"
        except ConnectorError as e:
            outcomes[label] = str(e)

    with run_as(CALLER):
        context = contextvars.copy_context()
        copied = threading.Thread(target=context.run, args=(list_tools, "copied"))
        plain = threading.Thread(target=list_tools, args=("plain",))
        copied.start(), plain.start()
        copied.join(), plain.join()

    assert outcomes["copied"] == "sent"
    assert "no caller identity" in outcomes["plain"]
    [request] = recorder.requests
    assert request.headers["X-Wildbox-User-ID"] == CALLER["user_id"]


# --- Failures ---------------------------------------------------------------


def test_a_refusal_is_reported_with_its_status_and_not_retried(recorder):
    recorder.status, recorder.body = 503, {
        "detail": "Task queue temporarily unavailable"
    }
    with pytest.raises(ConnectorError) as error:
        call("wildbox", "analyze_ioc", ioc_type="ipv4", ioc_value="203.0.113.7")
    assert "answered 503: Task queue temporarily unavailable" in str(error.value)
    assert len(recorder.requests) == 1


def test_an_unreachable_service_is_reported_once(monkeypatch):
    attempts = []

    def down(request):
        attempts.append(request)
        raise httpx.ConnectError("connection refused", request=request)

    connector = connector_registry.get_connector("api")
    monkeypatch.setattr(
        connector, "client", httpx.Client(transport=httpx.MockTransport(down))
    )
    with pytest.raises(ConnectorError, match="ConnectError"):
        call("api", "list_tools")
    assert len(attempts) == 1


def test_a_wrong_route_fails_the_step(recorder, monkeypatch):
    """The stub answers 404 for a route the tools service does not declare."""
    connector = connector_registry.get_connector("api")
    monkeypatch.setitem(connector.config, "api_url", settings.wildbox_api_url + "/v1")
    with pytest.raises(ConnectorError, match="answered 404"):
        call("api", "list_tools")
