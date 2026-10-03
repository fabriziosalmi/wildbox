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
