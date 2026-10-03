"""The guarded HTTP clients in app.safe_http (#610).

The SSRF guard on tool inputs checks the URL a caller sends; these clients
check every connection a tool then makes, so a redirect cannot take a tool
to an internal address and a host name is checked on the answer that is
actually dialed.

The aiohttp tests run a real HTTP server on 127.0.0.1 and a fake resolver,
so no real DNS is used. 127.0.0.1 is accepted only where a test asks for it
(``allow_loopback_targets``) and stands in for a public host there; every
other private, local or metadata address is still refused. The requests
tests use a fake transport adapter and a fake ``socket.getaddrinfo``.
"""

import asyncio
import io
import os
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import aiohttp
import pytest
import requests
from aiohttp.abc import AbstractResolver

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import safe_http  # noqa: E402
from app.safe_http import (  # noqa: E402
    MAX_REDIRECTS,
    GuardedResolver,
    UnsafeTargetError,
    guarded_requests_session,
    guarded_session,
)

PUBLIC_IP = "93.184.215.14"
TOOLS_DIR = Path(__file__).resolve().parents[2] / "app" / "tools"


# --- a local server whose paths redirect ---------------------------------


class _Redirector(BaseHTTPRequestHandler):
    hits = []
    port = 0

    def do_GET(self):  # noqa: N802 - http.server API
        type(self).hits.append((self.headers.get("Host"), self.path))
        path = self.path
        if path == "/ok":
            return self._reply(200)
        if path == "/to-metadata":
            return self._reply(302, "http://169.254.169.254/latest/meta-data/")
        if path == "/to-private-ip":
            return self._reply(302, "http://10.0.0.5/")
        if path == "/to-internal-name":
            return self._reply(302, f"http://internal.example:{self.port}/ok")
        if path == "/to-localhost":
            return self._reply(302, f"http://localhost:{self.port}/ok")
        if path == "/to-public-name":
            return self._reply(302, f"http://public.example:{self.port}/ok")
        if path == "/loop":
            return self._reply(302, "/loop")
        if path.startswith("/chain/"):
            left = int(path.rsplit("/", 1)[1])
            return (
                self._reply(200)
                if left == 0
                else self._reply(302, f"/chain/{left - 1}")
            )
        return self._reply(404)

    def _reply(self, status, location=None):
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", "2")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b"ok")

    do_HEAD = do_GET  # noqa: N815 - http.server API

    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture
def server():
    handler = type("Handler", (_Redirector,), {"hits": []})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    handler.port = httpd.server_address[1]
    thread = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    yield handler
    httpd.shutdown()
    httpd.server_close()


class FakeResolver(AbstractResolver):
    """Answers from a fixed table; a name not in it does not resolve."""

    def __init__(self, table):
        self.table = table
        self.asked = []

    async def resolve(self, host, port=0, family=socket.AF_INET):
        self.asked.append(host)
        if host not in self.table:
            raise OSError(f"cannot resolve {host}")
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": socket.AF_INET6 if ":" in ip else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for ip in self.table[host]
        ]

    async def close(self):
        pass


RESOLVER_TABLE = {
    "public.example": ["127.0.0.1"],  # the loopback stand-in for a public host
    "internal.example": ["10.0.0.5"],
    "mixed.example": ["127.0.0.1", "10.0.0.5"],
}


def _get(url, table=RESOLVER_TABLE):
    """GET ``url`` through a guarded session; return (status, final url)."""

    async def run():
        async with guarded_session(resolver=FakeResolver(table)) as session:
            async with session.get(url) as response:
                return response.status, str(response.url)

    return asyncio.run(run())


# --- direct targets ----------------------------------------------------------


def test_loopback_target_is_refused_without_connecting(server):
    with pytest.raises(UnsafeTargetError):
        _get(f"http://127.0.0.1:{server.port}/ok")
    assert server.hits == []


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fd00::c2b6:a9ff:fe52:2ea5]/",
        "http://224.0.0.1/",
        "http://0.0.0.0/",
        "http://localhost/",
        "http://metadata.google.internal/",
    ],
)
def test_private_local_and_metadata_targets_are_refused(url):
    with pytest.raises(UnsafeTargetError):
        _get(url)


def test_name_resolving_to_a_private_address_is_refused(allow_loopback_targets, server):
    with pytest.raises(UnsafeTargetError):
        _get(f"http://internal.example:{server.port}/ok")
    assert server.hits == []


def test_name_with_any_private_address_is_refused(allow_loopback_targets, server):
    """One private answer refuses the name, even next to a public one."""
    with pytest.raises(UnsafeTargetError):
        _get(f"http://mixed.example:{server.port}/ok")
    assert server.hits == []


def test_name_that_does_not_resolve_fails(allow_loopback_targets):
    with pytest.raises(aiohttp.ClientError):
        _get("http://unknown.example/ok")


def test_public_name_connects_to_the_checked_address(allow_loopback_targets, server):
    """The connection goes to the address the guard checked (no re-resolution)."""
    status, _ = _get(f"http://public.example:{server.port}/ok")
    assert status == 200
    assert server.hits == [(f"public.example:{server.port}", "/ok")]


# --- redirects ---------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/to-metadata", "/to-private-ip", "/to-internal-name", "/to-localhost"],
)
def test_redirect_to_an_internal_target_is_refused(
    allow_loopback_targets, server, path
):
    with pytest.raises(UnsafeTargetError):
        _get(f"http://public.example:{server.port}{path}")
    # The first request reached the server; the redirect was not followed.
    assert server.hits == [(f"public.example:{server.port}", path)]


def test_redirect_to_a_public_target_is_followed(allow_loopback_targets, server):
    status, final = _get(f"http://public.example:{server.port}/to-public-name")
    assert status == 200
    assert final == f"http://public.example:{server.port}/ok"
    assert [path for _, path in server.hits] == ["/to-public-name", "/ok"]


def test_redirects_are_followed_up_to_the_limit(allow_loopback_targets, server):
    status, _ = _get(f"http://public.example:{server.port}/chain/{MAX_REDIRECTS}")
    assert status == 200
    assert len(server.hits) == MAX_REDIRECTS + 1


def test_one_redirect_past_the_limit_is_refused(allow_loopback_targets, server):
    with pytest.raises(UnsafeTargetError, match="Too many redirects"):
        _get(f"http://public.example:{server.port}/chain/{MAX_REDIRECTS + 1}")
    assert len(server.hits) == MAX_REDIRECTS + 1


def test_redirect_loop_is_refused(allow_loopback_targets, server):
    with pytest.raises(UnsafeTargetError, match="Too many redirects"):
        _get(f"http://public.example:{server.port}/loop")
    assert len(server.hits) == MAX_REDIRECTS + 1


def test_redirect_hop_is_checked_with_redirects_off_too(allow_loopback_targets, server):
    """Tools that follow redirects themselves (url_analyzer) hit the same check."""

    async def run():
        async with guarded_session(resolver=FakeResolver(RESOLVER_TABLE)) as session:
            async with session.get(
                f"http://public.example:{server.port}/to-metadata",
                allow_redirects=False,
            ) as response:
                location = response.headers["Location"]
            async with session.get(location):
                pass

    with pytest.raises(UnsafeTargetError):
        asyncio.run(run())


# --- the session factory -----------------------------------------------------


def test_guarded_session_refuses_a_caller_supplied_connector():
    async def run():
        guarded_session(connector=aiohttp.TCPConnector())

    with pytest.raises(TypeError):
        asyncio.run(run())


def test_guarded_session_refuses_proxies_from_the_environment():
    async def run():
        guarded_session(trust_env=True)

    with pytest.raises(TypeError):
        asyncio.run(run())


@pytest.mark.parametrize(
    "name", ["localhost", "db.localhost", "metadata.google.internal"]
)
def test_guarded_resolver_refuses_local_names_before_asking_dns(name):
    inner = FakeResolver({name: [PUBLIC_IP]})
    with pytest.raises(UnsafeTargetError):
        asyncio.run(GuardedResolver(inner).resolve(name, 80))
    assert inner.asked == []


def test_guarded_resolver_checks_every_answer():
    resolver = GuardedResolver(FakeResolver({"a.example": [PUBLIC_IP, "192.168.0.1"]}))
    with pytest.raises(UnsafeTargetError):
        asyncio.run(resolver.resolve("a.example", 80))


# --- requests ----------------------------------------------------------------


class FakeAdapter(requests.adapters.BaseAdapter):
    """A transport that answers from a table of URL -> (status, Location)."""

    def __init__(self, routes):
        super().__init__()
        self.routes = routes
        self.sent = []

    def send(self, request, **kwargs):
        self.sent.append(request.url)
        status, location = self.routes.get(request.url, (200, None))
        response = requests.Response()
        response.status_code = status
        response.url = request.url
        response.request = request
        response.raw = io.BytesIO(b"")
        response._content = b""
        if location:
            response.headers["Location"] = location
        return response

    def close(self):
        pass


@pytest.fixture
def dns(monkeypatch):
    table = {"public.example": PUBLIC_IP, "internal.example": "10.0.0.5"}

    def fake_getaddrinfo(host, *args, **kwargs):
        if host not in table:
            raise socket.gaierror(f"cannot resolve {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table[host], 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return table


def _requests_session(routes):
    session = guarded_requests_session()
    adapter = FakeAdapter(routes)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session, adapter


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "http://internal.example/",
        "http://localhost/",
        "http://unknown.example/",
    ],
)
def test_requests_session_refuses_internal_targets(dns, url):
    session, adapter = _requests_session({})
    with pytest.raises(UnsafeTargetError):
        session.get(url)
    assert adapter.sent == []


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://internal.example/",
        "http://[::1]/",
    ],
)
def test_requests_session_refuses_redirect_to_internal_target(dns, location):
    session, adapter = _requests_session({"http://public.example/": (302, location)})
    with pytest.raises(UnsafeTargetError):
        session.get("http://public.example/")
    assert adapter.sent == ["http://public.example/"]


def test_requests_session_follows_public_redirects_up_to_the_limit(dns):
    routes = {
        f"http://public.example/{n}": (302, f"http://public.example/{n - 1}")
        for n in range(1, 10)
    }
    session, adapter = _requests_session(routes)
    assert session.get(f"http://public.example/{MAX_REDIRECTS}").status_code == 200
    assert len(adapter.sent) == MAX_REDIRECTS + 1

    session, adapter = _requests_session(routes)
    with pytest.raises(requests.TooManyRedirects):
        session.get(f"http://public.example/{MAX_REDIRECTS + 1}")


def test_requests_session_refuses_a_redirect_loop(dns):
    session, _ = _requests_session({"http://public.example/loop": (302, "/loop")})
    with pytest.raises(requests.TooManyRedirects):
        session.get("http://public.example/loop")


def test_policy_is_the_input_sanitizer_policy():
    """One policy: safe_http defers to InputSanitizer for blocked addresses."""
    import ipaddress

    assert safe_http.is_blocked_address(ipaddress.ip_address("100.64.0.1"))
    assert not safe_http.is_blocked_address(ipaddress.ip_address(PUBLIC_IP))


# --- tools, end to end -------------------------------------------------------


def test_cookie_scanner_does_not_follow_a_redirect_to_metadata(
    allow_loopback_targets, server
):
    from app.tools.cookie_scanner.main import CookieSecurityScanner

    url = f"http://127.0.0.1:{server.port}/to-metadata"
    result = asyncio.run(CookieSecurityScanner().scan_cookies(url))
    assert "SSRF" in result["error"]
    assert [path for _, path in server.hits] == ["/to-metadata"]


def test_url_analyzer_records_the_chain_but_refuses_the_internal_hop(
    allow_loopback_targets, server
):
    from app.tools.url_analyzer.main import URLShortenerAnalyzer

    url = f"http://127.0.0.1:{server.port}/to-private-ip"
    with pytest.raises(Exception, match="SSRF"):
        asyncio.run(URLShortenerAnalyzer().analyze_url(url))
    assert [path for _, path in server.hits] == ["/to-private-ip"]


# Tools that fetch a URL the caller supplies (or one built from caller
# input). They must open HTTP connections only through app.safe_http.
FETCHING_TOOLS = [
    "api_security_analyzer",
    "api_security_tester",
    "cookie_scanner",
    "directory_bruteforcer",
    "email_harvester",
    "file_upload_scanner",
    "header_analyzer",
    "http_security_scanner",
    "metadata_extractor",
    "mobile_security_analyzer",
    "sql_injection_scanner",
    "static_malware_analyzer",
    "url_analyzer",
    "url_security_scanner",
    "web_application_firewall_bypass",
    "web_vuln_scanner",
    "xss_scanner",
]

UNGUARDED_CLIENTS = re.compile(
    r"aiohttp\.ClientSession\(|aiohttp\.TCPConnector\(|requests\.(get|post|put|head|"
    r"delete|patch|request|Session)\(|httpx\.|urlopen\("
)


@pytest.mark.parametrize("tool", FETCHING_TOOLS)
def test_fetching_tools_use_only_guarded_clients(tool):
    source = (TOOLS_DIR / tool / "main.py").read_text()
    assert not UNGUARDED_CLIENTS.search(
        source
    ), f"{tool} opens an unguarded HTTP client"
