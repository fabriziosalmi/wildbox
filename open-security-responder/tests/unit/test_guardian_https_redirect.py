"""Guardian redirects plain HTTP, and its internal callers must not be (#707).

Guardian runs with DEBUG off, so Django's SecurityMiddleware answers 301 to
https:// for any request that is not secure, and a request is secure only
when it carries ``X-Forwarded-Proto: https``. TLS ends at the gateway, which
sends that header; the responder's connectors call Guardian directly, over
plain HTTP, and did not. Every Guardian action of every playbook was answered
301 on the running stack.

No unit test failed, because the stand-in the connector tests call
(service_contracts.refusal) answered 404 and 403 as Guardian does but knew
nothing of the redirect. It now reads the redirect from Guardian's settings
and answers it, first, as the middleware does. These tests pin both halves:
the stand-in redirects what Guardian redirects, and every internal caller of
Guardian in this repository is either told apart by the header or exempt.
"""

import inspect
import os
import re
import sys
from pathlib import Path

import httpx
import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
sys.path.insert(0, str(SERVICE_ROOT))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

import service_contracts as contracts  # noqa: E402
from app.caller import FORWARDED_PROTO, gateway_headers, run_as  # noqa: E402
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
ASSET_ID = "7a3e9c1b-5d2f-4b8a-9e6c-1f0d2b4a6c83"
GUARDIAN = settings.wildbox_guardian_url
VULNERABILITIES = f"{GUARDIAN}/api/v1/vulnerabilities/"


def as_caller():
    """What a connector sends for CALLER, but for X-Forwarded-Proto.

    Taken from the connectors' own helper, not written out here: whatever
    else the services come to require of an internal call (#637 adds the
    credential's type) is then in these requests too, and the tests below
    stay tests of the one header.
    """
    with run_as(CALLER):
        headers = gateway_headers()
    del headers["X-Forwarded-Proto"]
    return headers


# --- What Guardian does, read from its settings ------------------------------


def test_guardian_redirects_plain_http_and_trusts_the_forwarded_proto_header():
    enabled, header, exempt = contracts.guardian_https_redirect()

    assert enabled is True
    assert header == ("X-FORWARDED-PROTO", "https")
    # Health, for the container's own probe; nothing under /api/.
    assert any(re.search(pattern, "health/") for pattern in exempt)
    assert not any(re.search(pattern, "api/v1/vulnerabilities/") for pattern in exempt)


def test_compose_runs_guardian_with_the_redirect_on():
    """The redirect is set when DEBUG is off, which is the compose default."""
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    guardian = compose.split("\n  guardian:\n", 1)[1].split(
        "\n  guardian-worker:\n", 1
    )[0]
    assert "- DEBUG=${DEBUG:-false}" in guardian
    source = contracts.GUARDIAN_SETTINGS.read_text()
    block = source.split("if not DEBUG:", 1)[1]
    assert "SECURE_SSL_REDIRECT = True" in block.split("\nelse:", 1)[0]


# --- The stand-in answers as Guardian does ----------------------------------


def test_the_stand_in_redirects_a_guardian_request_without_the_header():
    request = httpx.Request("GET", VULNERABILITIES, headers=as_caller())

    status, reason = contracts.refusal(
        "guardian", request, settings.gateway_internal_secret
    )

    assert status == 301
    assert reason.endswith(VULNERABILITIES.replace("http://", "https://", 1))


def test_the_redirect_comes_before_the_route_and_the_identity_are_looked_at():
    """SecurityMiddleware runs first: an anonymous request to no route at
    all is redirected too, not answered 403 or 404."""
    request = httpx.Request("GET", f"{GUARDIAN}/api/v1/no-such-route")

    status, _ = contracts.refusal("guardian", request, settings.gateway_internal_secret)

    assert status == 301


@pytest.mark.parametrize("value", ["http", "HTTPS", "", "https, http"])
def test_only_the_exact_header_value_counts(value):
    headers = {**as_caller(), "X-Forwarded-Proto": value}
    request = httpx.Request("GET", VULNERABILITIES, headers=headers)

    assert (
        contracts.refusal("guardian", request, settings.gateway_internal_secret)[0]
        == 301
    )


def test_the_stand_in_serves_a_guardian_request_with_the_header():
    headers = {**as_caller(), "X-Forwarded-Proto": "https"}
    request = httpx.Request("GET", VULNERABILITIES, headers=headers)

    assert (
        contracts.refusal("guardian", request, settings.gateway_internal_secret) is None
    )
    # And still refuses it for the reasons it did before.
    del headers["X-Gateway-Secret"]
    request = httpx.Request("GET", VULNERABILITIES, headers=headers)
    assert contracts.refusal("guardian", request, settings.gateway_internal_secret) == (
        403,
        "GATEWAY_SECRET_REQUIRED",
    )


@pytest.mark.parametrize(
    "service, url",
    [
        ("tools", f"{settings.wildbox_api_url}/api/tools"),
        ("data", f"{settings.wildbox_data_url}/api/v1/indicators/search"),
        ("agents", f"{settings.wildbox_agents_url}/v1/analyze"),
    ],
)
def test_no_other_service_redirects(service, url):
    assert contracts.https_redirect(service, httpx.Request("GET", url)) is None


def test_no_other_service_has_an_https_redirect_to_model():
    """The FastAPI services install none; only Guardian is Django. If one
    gains a redirect, the stand-in must learn it."""
    installs = re.compile(
        r"add_middleware\(\s*HTTPSRedirectMiddleware|^\s*SECURE_SSL_REDIRECT\s*=",
        re.MULTILINE,
    )
    for service in ("tools", "data", "agents", "identity", "cspm", "responder"):
        for source in (REPO_ROOT / f"open-security-{service}" / "app").rglob("*.py"):
            assert not installs.search(source.read_text()), source


# --- Every internal caller of Guardian ---------------------------------------


def test_the_responders_connector_calls_say_the_run_came_over_https():
    with run_as(CALLER):
        headers = gateway_headers()

    assert FORWARDED_PROTO == "https"
    assert headers["X-Forwarded-Proto"] == "https"
    request = httpx.Request("GET", VULNERABILITIES, headers=headers)
    assert (
        contracts.refusal("guardian", request, settings.gateway_internal_secret) is None
    )


@pytest.fixture
def guardian(monkeypatch):
    """The wildbox connector, its requests answered as Guardian answers."""
    requests = []

    def handle(request):
        requests.append(request)
        refused = contracts.refusal(
            "guardian", request, settings.gateway_internal_secret
        )
        if refused:
            return httpx.Response(refused[0], json={"detail": refused[1]})
        if request.method == "POST":
            return httpx.Response(201, json={"id": "v-1"})
        if request.url.path == "/api/v1/assets/assets/":
            asset = {"id": ASSET_ID, "name": "web-1", "ip_address": "203.0.113.7"}
            return httpx.Response(200, json={"count": 1, "results": [asset]})
        return httpx.Response(200, json={"count": 0, "results": [], "id": ASSET_ID})

    connector = connector_registry.get_connector("wildbox")
    monkeypatch.setattr(
        connector, "client", httpx.Client(transport=httpx.MockTransport(handle))
    )
    return requests


GUARDIAN_ACTIONS = {
    "get_vulnerabilities": {},
    "get_asset_info": {"asset_id": ASSET_ID},
    "create_vulnerability": {
        "title": "t",
        "description": "d",
        "severity": "high",
        "asset_name": "web-1",
    },
}


def test_the_table_lists_every_guardian_action_of_the_connector():
    """So a Guardian action added later cannot go unchecked. An action calls
    Guardian when its code, or a helper it calls, names guardian_url."""
    connector = connector_registry.get_connector("wildbox")

    def source(name):
        return inspect.getsource(getattr(connector, name))

    def calls_guardian(name):
        text = source(name)
        helpers = re.findall(r"self\.(_\w+)\(", text)
        return "guardian_url" in text + "".join(source(h) for h in helpers)

    calling_guardian = {
        name for name in connector.get_available_actions() if calls_guardian(name)
    }
    assert calling_guardian == set(GUARDIAN_ACTIONS)
    # And no other connector calls Guardian.
    for other in ("api", "data", "system"):
        module = inspect.getsource(type(connector_registry.get_connector(other)))
        assert "guardian" not in module.lower(), other


@pytest.mark.parametrize("action", sorted(GUARDIAN_ACTIONS))
def test_each_guardian_action_is_served_not_redirected(guardian, action):
    with run_as(CALLER):
        result = connector_registry.execute_action(
            "wildbox", action, GUARDIAN_ACTIONS[action]
        )

    assert result
    assert guardian, "no request was sent"
    for request in guardian:
        assert request.headers["X-Forwarded-Proto"] == "https"


@pytest.mark.parametrize("action", sorted(GUARDIAN_ACTIONS))
def test_a_guardian_action_without_the_header_fails_with_the_redirect(
    guardian, monkeypatch, action
):
    """What the running stack answered before the fix, reproduced: the step
    fails with Guardian's 301, after one request, which is not followed."""
    import app.caller as caller_module

    monkeypatch.setattr(caller_module, "FORWARDED_PROTO", "http")
    with run_as(CALLER):
        with pytest.raises(ConnectorError, match="answered 301"):
            connector_registry.execute_action(
                "wildbox", action, GUARDIAN_ACTIONS[action]
            )

    assert len(guardian) == 1


def test_identitys_membership_notice_goes_to_a_route_guardian_exempts():
    """identity calls Guardian over plain HTTP too, with the secret alone
    (#676). Its route is exempt from the redirect; if either side moves, the
    notice would be answered 301 and lost."""
    source = (
        REPO_ROOT / "open-security-identity" / "app" / "guardian_memberships.py"
    ).read_text()
    url = re.search(r'^DEFAULT_URL = "([^"]+)"', source, re.MULTILINE).group(1)
    compose = (REPO_ROOT / "docker-compose.yml").read_text()

    assert url.startswith("http://")
    assert f"GUARDIAN_INTERNAL_URL=${{GUARDIAN_INTERNAL_URL-{url}}}" in compose
    assert contracts.https_redirect("guardian", httpx.Request("POST", url)) is None
    # A neighbouring path is not exempt: the exemption is this one route.
    other = url.replace("/revoke/", "/list/")
    assert contracts.https_redirect("guardian", httpx.Request("POST", other))


def test_the_gateway_tells_guardian_the_scheme_and_proxies_from_https_only():
    """The other caller: nginx sends X-Forwarded-Proto $scheme, and only its
    TLS listener has the guardian location."""
    nginx = REPO_ROOT / "open-security-gateway" / "nginx"
    params = (nginx / "includes" / "proxy_params.conf").read_text()
    conf = (nginx / "conf.d" / "wildbox_gateway.conf").read_text()

    assert "proxy_set_header X-Forwarded-Proto $scheme;" in params
    servers = re.split(r"(?m)^server \{", conf)
    with_guardian = [s for s in servers if "location /api/v1/guardian/" in s]
    assert len(with_guardian) == 1
    assert re.search(r"(?m)^\s*listen 443 ssl;", with_guardian[0])
    assert "include /etc/nginx/includes/proxy_params.conf;" in with_guardian[0]
