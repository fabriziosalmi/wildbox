"""`/api/v1/tools/health` is not a health route, and nothing treats it as one (#721).

The gateway maps `/api/v1/tools/<x>` to `/api/tools/<x>` on the tools
service, where `<x>` is a tool's name: `/api/v1/tools/health` is "the tool
called health", which does not exist, and the service answers 404. An
integration test listed that path among "health endpoints" and passed
because it accepted any answer but 502.

The decision is to have no such route, not to add one. Data and identity
have a health location on the gateway because something reads them (the
dashboard's System Health card, the session tests); nothing reads a tools
one, and under `/api/v1/tools/` a fixed name would take a name away from the
tools, which is why the task routes got a prefix of their own
(`/api/v1/tasks/`, see the comment in wildbox_gateway.conf). The service's
health is its container's health check, on the service port.

These tests keep the pieces of that decision together. If a tools health
route through the gateway is wanted one day, they say what else has to
change: a location with authentication, a pin in route_scope_tests.sh, the
endpoint reference, and the integration test that pins the 404.
"""

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "open-security-gateway"
PRODUCTION_CONF = GATEWAY / "nginx" / "conf.d" / "wildbox_gateway.conf"
HARNESS = GATEWAY / "test" / "route_scope_tests.sh"
TOOLS = ROOT / "open-security-tools" / "app" / "tools"
ENDPOINTS = ROOT / "docs" / "api" / "tools" / "endpoints.md"
INTEGRATION = ROOT / "tests" / "integration"

spec = importlib.util.spec_from_file_location(
    "authenticated_locations", GATEWAY / "test" / "authenticated_locations.py"
)
al = importlib.util.module_from_spec(spec)
sys.modules.setdefault(spec.name, al)
spec.loader.exec_module(al)

PATH = "/api/v1/tools/health"


def test_the_gateway_has_no_location_of_its_own_for_the_path():
    conf = PRODUCTION_CONF.read_text(encoding="utf-8")
    locations = re.findall(r"^\s*location\s+([^{]+?)\s*\{", conf, re.M)

    assert locations, "no location read from the gateway configuration"
    assert [spec for spec in locations if "tools/health" in spec] == []
    # It is served by the tools location, like any other tool name, and that
    # location authenticates.
    assert "~ ^/api/v1/tools/(.*)$" in al.authenticated_locations(conf)
    assert "proxy_pass http://api_service/api/tools/$1$is_args$args;" in conf


def test_data_and_identity_are_the_services_with_a_health_location():
    """The convention the decision was taken against, as it stands."""
    conf = PRODUCTION_CONF.read_text(encoding="utf-8")

    health = sorted(
        spec for spec in al.authenticated_locations(conf) if spec.endswith("/health")
    )

    assert health == ["= /api/v1/data/health", "= /api/v1/identity/health"]


def test_no_tool_is_called_health():
    # With one, GET /api/v1/tools/health/info and POST /api/v1/tools/health
    # would be that tool's routes, and "health" could not mean anything else.
    tools = {path.name for path in TOOLS.iterdir() if (path / "main.py").is_file()}

    assert len(tools) > 10
    assert "health" not in tools


def test_the_endpoint_reference_says_the_path_is_not_the_health_endpoint():
    text = " ".join(ENDPOINTS.read_text(encoding="utf-8").split())

    assert (
        "The gateway does not route them (`/api/v1/tools/health` reaches "
        "`/api/tools/health` on the service, the run path of a tool named "
        "`health`, not this endpoint)"
    ) in text


def test_only_the_test_that_pins_the_404_asks_for_the_path():
    asking = sorted(
        path.name
        for path in INTEGRATION.glob("*.py")
        if PATH in path.read_text(encoding="utf-8")
    )

    assert asking == ["test_gateway_security.py"]
    source = (INTEGRATION / "test_gateway_security.py").read_text(encoding="utf-8")
    # Asked with a credential and expected to be the service's 404; no test
    # passes on "anything but 502" any more.
    assert "should be the tools service's 404" in source
    assert "!= 502" not in source
    # What it asks the backends for are routes they serve.
    assert re.findall(r'\("(\w+)", "(/api/v1/[^"]+)"\)', source) == [
        ("tools", "/api/v1/tools"),
        ("data", "/api/v1/data/health"),
        ("agents", "/api/v1/agents/stats"),
    ]
