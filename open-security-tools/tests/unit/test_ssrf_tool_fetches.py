"""Tools that build or follow a URL the generic SSRF guard never sees (#610).

The guard on tool inputs checks values that already look like http(s) URLs.
These tools fetch something else: a bare host name they turn into a URL, a
specification URL detected by prefix, a WHOIS referral taken from a
response, or the input of another tool run as a workflow step. Each must go
through the shared guard (public host, every resolved address public, fail
closed when the name does not resolve) before anything is sent.

No test touches the network: ``socket.getaddrinfo`` and the HTTP clients
are replaced with fakes that record what would have been sent.
"""

import asyncio
import os
import socket
import sys

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.tools.api_security_tester import main as api_tester  # noqa: E402
from app.tools.email_harvester import main as harvester  # noqa: E402
from app.tools.email_harvester.schemas import EmailHarvesterInput  # noqa: E402
from app.tools.header_analyzer import main as header_analyzer  # noqa: E402
from app.tools.http_security_scanner import main as http_scanner  # noqa: E402
from app.tools.http_security_scanner.schemas import (  # noqa: E402
    HttpSecurityScannerInput,
)
from app.tools.security_automation_orchestrator import main as orch  # noqa: E402
from app.tools.security_automation_orchestrator.schemas import (  # noqa: E402
    AutomationWorkflowInput,
)
from app.tools.sql_injection_scanner import main as sqli_scanner  # noqa: E402
from app.tools.sql_injection_scanner.schemas import (  # noqa: E402
    SQLInjectionScannerInput,
)
from app.tools.url_security_scanner import main as url_scanner  # noqa: E402
from app.tools.whois_lookup import main as whois  # noqa: E402
from app.tools.whois_lookup.schemas import WHOISLookupInput  # noqa: E402

PUBLIC_IP = "93.184.215.14"
PUBLIC_IP_2 = "93.184.215.15"


@pytest.fixture
def dns(monkeypatch):
    """Fake resolver: name -> list of addresses; unknown names do not resolve."""
    table = {
        "example.com": [PUBLIC_IP],
        "public.example": [PUBLIC_IP],
        "whois.public.example": [PUBLIC_IP],
        "internal.example": ["10.0.0.5"],
        "rebind.example": [PUBLIC_IP, "127.0.0.1"],
        "metadata.example": ["169.254.169.254"],
    }
    lookups = []

    def fake_getaddrinfo(host, *args, **kwargs):
        lookups.append(host)
        if host not in table:
            raise socket.gaierror(f"cannot resolve {host}")
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (ip, 43),
            )
            for ip in table[host]
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return table


class Recorder:
    """A fake HTTP session (requests or aiohttp shaped) that records URLs."""

    def __init__(self):
        self.urls = []
        self.headers = {}

    def _record(self, url, *args, **kwargs):
        self.urls.append(str(url))
        return FakeResponse()

    get = post = head = _record

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def close(self):
        pass


class FakeResponse:
    status = status_code = 200
    text = "<html>ok</html>"
    headers = {}
    url = "https://example.com/"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


INTERNAL_HOSTS = [
    "169.254.169.254",
    "127.0.0.1",
    "10.0.0.1",
    "[::1]",
    "localhost",
    "internal.example",  # resolves to 10.0.0.5
    "rebind.example",  # one public, one loopback answer
    "unknown.example",  # does not resolve: fail closed
]


# --- http_security_scanner: scheme-less url ----------------------------------


@pytest.mark.parametrize("host", INTERNAL_HOSTS)
def test_http_scanner_validates_the_url_it_builds(dns, host):
    scanner = http_scanner.HttpSecurityScanner()
    with pytest.raises(ValueError):
        scanner.normalize_url(host)


def test_http_scanner_adds_https_to_a_public_host(dns):
    assert (
        http_scanner.HttpSecurityScanner().normalize_url("example.com")
        == "https://example.com"
    )


def test_http_scanner_scheme_check_is_case_insensitive(dns):
    scanner = http_scanner.HttpSecurityScanner()
    assert scanner.normalize_url("HTTPS://example.com/") == "HTTPS://example.com/"
    with pytest.raises(ValueError):
        scanner.normalize_url("HTTP://169.254.169.254/")


def test_http_scanner_fetches_nothing_for_a_refused_host(dns, monkeypatch):
    fetched = []

    async def fake_fetch(self, url, follow_redirects=True):
        fetched.append(url)
        return {}, 200, url

    monkeypatch.setattr(http_scanner.HttpSecurityScanner, "fetch_headers", fake_fetch)
    out = asyncio.run(
        http_scanner.execute_tool(HttpSecurityScannerInput(url="169.254.169.254"))
    )
    assert out.success is False
    assert fetched == []


# --- email_harvester: bare domain --------------------------------------------


@pytest.fixture
def harvester_http(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(harvester, "guarded_requests_session", lambda: recorder)
    return recorder


@pytest.mark.parametrize(
    "host", INTERNAL_HOSTS + ["example.com/path", "user@example.com"]
)
def test_email_harvester_refuses_internal_domains(dns, harvester_http, host):
    with pytest.raises(ValueError):
        harvester.DirectDomainSearch().search(host)
    assert harvester_http.urls == []


def test_email_harvester_fetches_a_public_domain(dns, harvester_http):
    harvester.DirectDomainSearch().search("example.com")
    assert harvester_http.urls[0] == "https://example.com"
    assert "https://example.com/contact" in harvester_http.urls


def test_email_harvester_tool_skips_a_refused_domain(dns, harvester_http):
    out = harvester.execute_tool(
        EmailHarvesterInput(domain="169.254.169.254", search_engines=[])
    )
    assert "Direct Domain" not in out.sources_searched
    assert harvester_http.urls == []


# --- api_security_tester: specification URL ----------------------------------


@pytest.fixture
def api_http(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(api_tester, "_session", lambda: recorder)
    return recorder


@pytest.mark.parametrize(
    "spec",
    [
        "http://169.254.169.254/openapi.json",
        "HTTP://169.254.169.254/openapi.json",
        " https://internal.example/x",
    ],
)
def test_api_tester_refuses_internal_specification_urls(dns, api_http, spec):
    assert (
        asyncio.run(api_tester.parse_api_specification(spec, "https://example.com"))
        == []
    )
    assert api_http.urls == []


def test_api_tester_detects_spec_urls_case_insensitively():
    assert api_tester._is_spec_url("HTTPS://example.com/openapi.json")
    assert api_tester._is_spec_url("  http://example.com/openapi.json")
    assert not api_tester._is_spec_url('{"openapi": "3.0.0"}')


def test_api_tester_fetches_a_public_specification_url(dns, api_http):
    asyncio.run(
        api_tester.parse_api_specification(
            "HTTPS://example.com/openapi.json", "https://example.com"
        )
    )
    assert api_http.urls == ["HTTPS://example.com/openapi.json"]


# --- header_analyzer: the shared guard replaces its own check ----------------


@pytest.mark.parametrize(
    "url",
    [
        "http://rebind.example/",  # old check looked at the first answer only
        "http://unknown.example/",  # old check let unresolvable names through
        "http://224.0.0.1/",  # old check ignored multicast
        "http://0.0.0.0/",  # ... and the unspecified address
        "http://100.64.0.1/",  # ... and shared address space
    ],
)
def test_header_analyzer_refuses_what_its_old_check_let_through(dns, monkeypatch, url):
    opened = []
    monkeypatch.setattr(
        header_analyzer, "guarded_session", lambda **kw: opened.append(kw) or Recorder()
    )
    with pytest.raises(Exception, match="SSRF|resolve|blocked"):
        asyncio.run(header_analyzer.HeaderSecurityAnalyzer().analyze_headers(url))
    assert opened == []


def test_header_analyzer_has_no_private_check_of_its_own():
    assert not hasattr(header_analyzer.HeaderSecurityAnalyzer, "_is_private_ip")


# --- url_security_scanner: fail closed ---------------------------------------


@pytest.mark.parametrize(
    "url", ["http://unknown.example/", "http://rebind.example/", "http://224.0.0.1/"]
)
def test_url_scanner_redirect_analysis_fails_closed(dns, monkeypatch, url):
    opened = []
    monkeypatch.setattr(
        url_scanner, "guarded_session", lambda **kw: opened.append(kw) or Recorder()
    )
    result = asyncio.run(url_scanner.URLSecurityScanner().analyze_redirects(url, 5, 5))
    assert result.redirect_count == 0
    assert result.redirect_security_issues[0].startswith("Blocked:")
    assert opened == []


# --- sql_injection_scanner: DNS resolution, fail closed ----------------------


@pytest.mark.parametrize(
    "host",
    ["internal.example", "rebind.example", "metadata.example", "unknown.example"],
)
def test_sqli_scanner_resolves_the_target(dns, monkeypatch, host):
    recorder = Recorder()
    monkeypatch.setattr(sqli_scanner, "guarded_requests_session", lambda: recorder)
    with pytest.raises(ValueError):
        sqli_scanner.execute_tool(
            SQLInjectionScannerInput(target_url=f"http://{host}/?id=1"),
            user_id="user-1",
        )
    assert recorder.urls == []


# --- whois_lookup: referral server -------------------------------------------


@pytest.mark.parametrize(
    "server",
    [
        "10.0.0.1",
        "169.254.169.254",
        "localhost",
        "internal.example",
        "rebind.example",
        "unknown.example",
        "whois.public.example:4343",
        "whois://whois.public.example",
        "x@whois.public.example",
        "whois.public.example/path",
        "[::1]",
    ],
)
def test_whois_referral_is_checked(dns, server):
    with pytest.raises(ValueError):
        whois.resolve_referral_server(server)


def test_whois_referral_returns_the_checked_address(dns):
    family, sockaddr = whois.resolve_referral_server("whois.public.example")
    assert family == socket.AF_INET
    assert sockaddr == (PUBLIC_IP, 43)


@pytest.fixture
def whois_server(monkeypatch):
    calls = []

    def fake_query(domain, server, timeout, address=None):
        calls.append((server, address))
        return f"Domain Name: {domain}\nWhois Server: {fake_query.referral}\n"

    fake_query.referral = ""
    monkeypatch.setattr(whois, "query_whois_server", fake_query)
    return calls, fake_query


@pytest.mark.parametrize("referral", ["10.0.0.1", "internal.example", "localhost"])
def test_whois_does_not_follow_an_internal_referral(dns, whois_server, referral):
    calls, fake_query = whois_server
    fake_query.referral = referral
    out = whois.execute_tool(WHOISLookupInput(domain="example.com"))
    assert out.success is True
    assert [server for server, _ in calls] == ["whois.verisign-grs.com"]


def test_whois_follows_a_public_referral_to_the_checked_address(dns, whois_server):
    calls, fake_query = whois_server
    fake_query.referral = "whois.public.example"
    whois.execute_tool(WHOISLookupInput(domain="example.com"))
    assert calls[1] == ("whois.public.example", (socket.AF_INET, (PUBLIC_IP, 43)))


# --- security_automation_orchestrator: steps run through the guard -----------


def _workflow(*steps):
    return AutomationWorkflowInput(
        workflow_name="wf",
        trigger_type="manual",
        workflow_steps=list(steps),
        execution_mode="sequential",
    )


@pytest.fixture
def spy_tools(monkeypatch):
    """Replace the step tools' execute_tool with spies; return their calls."""
    calls = []

    async def header_spy(params):
        calls.append(("header_analyzer", params))
        return {"success": True}

    async def cookie_spy(input_data):
        calls.append(("cookie_scanner", input_data))
        return {"success": True}

    def sqli_spy(input_data, user_id=None):
        calls.append(("sql_injection_scanner", input_data))
        return {"success": True}

    from app.tools.cookie_scanner import main as cookie_main

    monkeypatch.setattr(header_analyzer, "execute_tool", header_spy)
    monkeypatch.setattr(cookie_main, "execute_tool", cookie_spy)
    monkeypatch.setattr(sqli_scanner, "execute_tool", sqli_spy)
    return calls


@pytest.mark.parametrize(
    "step",
    [
        {
            "tool": "header_analyzer",
            "parameters": {"url": "http://169.254.169.254/latest/meta-data/"},
        },
        {"tool": "header_analyzer", "parameters": {"url": "http://internal.example/"}},
        {"tool": "cookie_scanner", "parameters": {"target_url": "http://10.0.0.1/"}},
        {"tool": "cookie_scanner", "parameters": {"target_url": "HTTP://127.0.0.1/"}},
    ],
)
def test_orchestrated_step_aimed_at_an_internal_target_is_refused(dns, spy_tools, step):
    out = asyncio.run(orch.execute_tool(_workflow(step)))
    result = out.workflow_execution.step_results[0]
    assert result.status == "failed"
    assert "Blocked target" in result.error_message
    assert "SSRF" in result.error_message
    assert spy_tools == []


def test_orchestrated_tool_acting_for_a_caller_is_refused(dns, spy_tools, monkeypatch):
    """Even if listed, a tool that declares user_id cannot run as a step."""
    monkeypatch.setattr(
        orch.SecurityAutomationOrchestrator,
        "__init__",
        _with_extra_tool("sql_injection_scanner"),
    )
    step = {
        "tool": "sql_injection_scanner",
        "parameters": {"target_url": "http://public.example/?id=1"},
    }
    out = asyncio.run(orch.execute_tool(_workflow(step)))
    result = out.workflow_execution.step_results[0]
    assert result.status == "failed"
    assert "acts on behalf of a caller" in result.error_message
    assert spy_tools == []


def _with_extra_tool(name):
    original = orch.SecurityAutomationOrchestrator.__init__

    def init(self):
        original(self)
        self.available_tools.append(name)

    return init


def test_orchestrated_step_gets_the_tools_own_validated_input(dns, spy_tools):
    step = {"tool": "header_analyzer", "parameters": {"url": "https://example.com/"}}
    out = asyncio.run(orch.execute_tool(_workflow(step)))
    assert out.workflow_execution.step_results[0].status == "completed"
    ((tool, params),) = spy_tools
    assert tool == "header_analyzer"
    assert type(params).__name__ == "HeaderAnalyzerInput"


def test_orchestrated_step_with_invalid_parameters_fails_the_step(dns, spy_tools):
    step = {"tool": "header_analyzer", "parameters": {"url": "not a url"}}
    out = asyncio.run(orch.execute_tool(_workflow(step)))
    result = out.workflow_execution.step_results[0]
    assert result.status == "failed"
    assert "Invalid parameters" in result.error_message
    assert spy_tools == []
