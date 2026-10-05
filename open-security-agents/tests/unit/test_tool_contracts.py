"""Every tool the agent is given calls something its service serves (#652).

The model was offered nine tools, and six could only fail:

- ``threat_intel_query_tool`` called ``GET /api/v1/threat-intel/query`` on
  the data service and ``vulnerability_search_tool``
  ``GET /api/v1/vulnerabilities/search`` on Guardian. Neither route exists,
  and both URLs defaulted to localhost inside the agents container;
- ``reputation_check_tool``, ``dns_lookup_tool``, ``url_analysis_tool`` and
  ``hash_lookup_tool`` reached a real tool of the tools service with fields
  its input model does not have (``ioc_value``, ``domain``, ``url``,
  ``hash``) and without the ones it requires, so each was answered 422.

These tests call every tool in ``ALL_TOOLS`` and check the one request it
sends against the target service's source: the route, the query parameters
or the body's fields, and the values of the fields that take a choice. The
stand-in (tests/unit/wildbox_services.py) answers 404 and 422 as the real
services would, so a tool that drifts from its service fails here.
"""

import asyncio
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import wildbox_services as services_module  # noqa: E402
from app.config import settings  # noqa: E402
from app.tools import wildbox_client as client_module  # noqa: E402
from app.tools.langchain_tools import ALL_TOOLS  # noqa: E402
from app.tools.wildbox_client import (  # noqa: E402
    DATA_INDICATOR_TYPES,
    DNS_RECORD_TYPES,
    REPUTATION_INDICATOR_TYPES,
    WildboxAPIClient,
    _caller_identity,
)
from wildbox_services import contracts  # noqa: E402

pytestmark = pytest.mark.skipif(
    not services_module.sources_available(),
    reason="the other services' sources are not here",
)

CALLER = {
    "user_id": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "team_id": "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b",
    "role": "member",
}

# Every tool, called the way the model calls it, and what it must reach:
# (service, method, route template, tools-service tool name or None).
TOOLS = {
    "port_scan_tool": (
        {"ip_address": "203.0.113.10"},
        ("tools", "POST", "/api/tools/{tool_name}", "network_port_scanner"),
    ),
    "whois_lookup_tool": (
        {"target": "example.com"},
        ("tools", "POST", "/api/tools/{tool_name}", "whois_lookup"),
    ),
    "reputation_check_tool": (
        {"ioc_value": "203.0.113.10", "ioc_type": "ip"},
        ("tools", "POST", "/api/tools/{tool_name}", "threat_intelligence_aggregator"),
    ),
    "dns_lookup_tool": (
        {"domain": "example.com", "record_type": "MX"},
        ("tools", "POST", "/api/tools/{tool_name}", "dns_enumerator"),
    ),
    "url_analysis_tool": (
        {"url": "https://example.com/login"},
        ("tools", "POST", "/api/tools/{tool_name}", "url_analyzer"),
    ),
    "hash_lookup_tool": (
        {"hash_value": "d41d8cd98f00b204e9800998ecf8427e"},
        ("tools", "POST", "/api/tools/{tool_name}", "malware_hash_checker"),
    ),
    "geolocation_lookup_tool": (
        {"ip_address": "203.0.113.10"},
        ("tools", "POST", "/api/tools/{tool_name}", "ip_geolocation"),
    ),
    "threat_intel_query_tool": (
        {"ioc_value": "203.0.113.10", "ioc_type": "ip"},
        ("data", "GET", "/api/v1/indicators/search", None),
    ),
    "vulnerability_search_tool": (
        {"query": "CVE-2024-3094"},
        ("guardian", "GET", "/api/v1/vulnerabilities/", None),
    ),
}


@pytest.fixture
def services(monkeypatch):
    token = _caller_identity.set(dict(CALLER))
    yield services_module.install(
        monkeypatch, client_module, services_module.Services(settings)
    )
    _caller_identity.reset(token)


def invoke(name, args):
    tool = next(tool for tool in ALL_TOOLS if tool.name == name)
    return json.loads(asyncio.run(tool.ainvoke(args)))


def test_the_table_lists_every_tool_the_agent_is_given():
    """So a tool added to ALL_TOOLS later cannot go unchecked."""
    assert sorted(TOOLS) == sorted(tool.name for tool in ALL_TOOLS)


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_the_tool_calls_a_route_its_service_serves(services, name):
    args, (service, method, template, tool_name) = TOOLS[name]

    output = invoke(name, args)

    assert output.get("success") is True, output
    assert "error" not in output, output
    [request] = services.requests
    assert services.service(request) == service
    assert request.method == method
    # The service declares this route, and the request is a request for it.
    # (Not contracts.route_for: /api/v1/indicators/{indicator_id} would match
    # the search path as well.)
    assert (method, template) in contracts.routes_of(
        service
    ), f"{service} serves no {method} {template}"
    pattern = re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(template))
    assert re.fullmatch(pattern, request.url.path), request.url.path
    if tool_name:
        assert request.url.path == f"/api/tools/{tool_name}"
        assert (services_module.TOOLS_DIR / tool_name / "schemas.py").is_file()


@pytest.mark.parametrize(
    "name", sorted(n for n, (_, target) in TOOLS.items() if target[3])
)
def test_the_tool_sends_the_input_its_tools_service_tool_validates(services, name):
    args, (_, _, _, tool_name) = TOOLS[name]

    invoke(name, args)

    [request] = services.requests
    body = json.loads(request.content)
    assert services_module.tool_input_problems(tool_name, body) == []
    # The argument the model gave is in the body, under a field of the model.
    given = next(iter(args.values()))
    assert given in body.values()


def test_the_data_search_sends_the_parameters_the_route_takes(services):
    invoke("threat_intel_query_tool", {"ioc_value": "203.0.113.10", "ioc_type": "ip"})

    [request] = services.requests
    accepted = contracts.function_parameters(contracts.DATA_MAIN, "search_indicators")
    assert set(request.url.params) <= accepted
    assert request.url.params["q"] == "203.0.113.10"
    assert request.url.params["indicator_type"] == "ip_address"
    assert 1 <= int(request.url.params["limit"]) <= 10000


def test_the_vulnerability_search_sends_the_parameter_guardian_searches_by(services):
    """``search`` is the list's text search, and a CVE is one of its fields.

    guardian's filter set had a ``search`` of its own beside DRF's
    ``SearchFilter`` until #724; the parameter is the viewset's now.
    """
    invoke("vulnerability_search_tool", {"query": "CVE-2024-3094"})

    [request] = services.requests
    filters = contracts.filterset_names(
        contracts.GUARDIAN_VULN_FILTERS, "VulnerabilityFilter"
    )
    searched = contracts.search_fields(
        contracts.GUARDIAN_VULN_VIEWS, "VulnerabilityViewSet"
    )
    # A CVE is found by the search; the filter set has no second "search".
    assert "cve_id" in searched
    assert "search" not in filters
    assert set(request.url.params) <= filters | {"search"}
    assert request.url.params["search"] == "CVE-2024-3094"
    # The list route, with its trailing slash: without it Guardian redirects.
    assert request.url.path.endswith("/vulnerabilities/")


def test_guardian_is_addressed_by_a_name_it_accepts(services):
    """Django answers 400 to a Host that is not in ALLOWED_HOSTS."""
    invoke("vulnerability_search_tool", {"query": "CVE-2024-3094"})

    [request] = services.requests
    host = request.headers["Host"].rsplit(":", 1)[0]
    assert host in services_module.guardian_allowed_hosts()


def test_guardian_is_told_the_request_came_over_https(services):
    """Guardian redirects plain HTTP to https:// on its own port unless the
    request says the client used HTTPS, as the gateway's does. Found on the
    running stack: every call was answered 301."""
    output = invoke("vulnerability_search_tool", {"query": "CVE-2024-3094"})

    [request] = services.requests
    assert request.headers["X-Forwarded-Proto"] == "https"
    assert output["success"] is True
    # The setting this answers to, in Guardian's own source.
    guardian_settings = (contracts.GUARDIAN / "guardian" / "settings.py").read_text()
    assert "SECURE_SSL_REDIRECT = True" in guardian_settings
    assert (
        'SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")'
        in guardian_settings
    )


# --- The names the client translates ----------------------------------------


def test_the_data_indicator_types_are_the_data_services():
    served = contracts.enum_values(contracts.DATA_MODELS, "IndicatorType")
    assert set(DATA_INDICATOR_TYPES.values()) <= served


def test_the_reputation_types_are_the_aggregators():
    allowed = services_module.tool_input_values("threat_intelligence_aggregator")
    assert set(REPUTATION_INDICATOR_TYPES.values()) <= allowed["indicator_type"]


def test_the_dns_record_types_are_the_enumerators():
    allowed = services_module.tool_input_values("dns_enumerator")
    assert set(DNS_RECORD_TYPES) == allowed["record_types"]


def test_every_ioc_type_of_an_analysis_has_a_service_type():
    """An analysis is submitted with one of these (app/schemas.py IOCType)."""
    ioc_types = contracts.enum_values(contracts.AGENTS_SCHEMAS, "IOCType")
    assert ioc_types <= set(DATA_INDICATOR_TYPES)
    assert ioc_types <= set(REPUTATION_INDICATOR_TYPES)


@pytest.mark.parametrize(
    "internal, tool_name", sorted(WildboxAPIClient.TOOL_ENDPOINT_MAP.items())
)
def test_every_allowlisted_tool_exists_in_the_tools_service(internal, tool_name):
    assert (services_module.TOOLS_DIR / tool_name / "main.py").is_file(), internal
    assert services_module.tool_input_class(tool_name)


# --- Arguments a service would refuse are refused before they are sent ------


@pytest.mark.parametrize(
    "name, args",
    [
        (
            "threat_intel_query_tool",
            {"ioc_value": "203.0.113.10", "ioc_type": "banana"},
        ),
        ("threat_intel_query_tool", {"ioc_value": "  "}),
        ("reputation_check_tool", {"ioc_value": "203.0.113.10", "ioc_type": "banana"}),
        ("dns_lookup_tool", {"domain": "example.com", "record_type": "ANY"}),
        ("vulnerability_search_tool", {"query": ""}),
    ],
)
def test_an_argument_the_service_does_not_take_sends_nothing(services, name, args):
    output = invoke(name, args)

    assert output["success"] is False
    assert output["error"]
    assert services.requests == []


def test_an_unknown_ioc_type_names_the_accepted_ones(services):
    output = invoke(
        "reputation_check_tool", {"ioc_value": "203.0.113.10", "ioc_type": "banana"}
    )
    assert "banana" in output["error"]
    for accepted in ("ip", "domain", "url", "hash", "email"):
        assert accepted in output["error"]


@pytest.mark.parametrize(
    "ioc_type", ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"]
)
def test_the_ioc_type_of_the_analysis_is_accepted_as_is(services, ioc_type):
    """The model is told the IOC's type in those words; it may pass it on."""
    assert invoke(
        "threat_intel_query_tool", {"ioc_value": "x.example", "ioc_type": ioc_type}
    )["success"]
    assert invoke(
        "reputation_check_tool", {"ioc_value": "x.example", "ioc_type": ioc_type}
    )["success"]
    assert len(services.requests) == 2
