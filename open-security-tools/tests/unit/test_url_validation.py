"""URL validation shared by both validators, and its use by the tools (#561).

``InputSanitizer.validate_url`` (url_analyzer, static_malware_analyzer, the
``UrlField`` schema type) and ``SecurityValidator.validate_url``
(sql_injection_scanner, security_integration) parse URLs with the same
function. No test here touches the network: name resolution and HTTP are
replaced with fakes.
"""

import os
import socket
import sys

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.input_validation import InputSanitizer  # noqa: E402
from app.tools.sql_injection_scanner import main as sqli_scanner  # noqa: E402
from app.tools.sql_injection_scanner.schemas import (  # noqa: E402
    SQLInjectionScannerInput,
)

PUBLIC_IP = "93.184.215.14"


@pytest.fixture
def resolver(monkeypatch):
    """Resolve every name to PUBLIC_IP unless mapped otherwise; record lookups."""
    answers = {}
    lookups = []

    def fake_getaddrinfo(host, *args, **kwargs):
        lookups.append(host)
        ip = answers.get(host, PUBLIC_IP)
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return answers, lookups


# --- InputSanitizer.validate_url -------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "https://shop.example.com/",
        "https://example.com/item?id=1",
        "https://example.com/a&b",
        "http://example.com/page?id=1&name=x",
        "https://bücher.example/",
    ],
)
def test_sanitizer_accepts_ordinary_urls(resolver, url):
    assert InputSanitizer.validate_url(url) == url


def test_sanitizer_strips_surrounding_whitespace(resolver):
    assert (
        InputSanitizer.validate_url("  https://example.com/ \n")
        == "https://example.com/"
    )


def test_sanitizer_resolves_the_normalized_host(resolver):
    _, lookups = resolver
    InputSanitizer.validate_url("https://Example.COM./x")
    assert lookups == ["example.com"]


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@example.com/",
        "https://example.com@127.0.0.1/",
        "https://example.com/\r\nX-Injected: 1",
        "https://example.com/a\tb",
        "https://example.com:0/",
        "https://example.com:65536/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://017700000001/",
        "http://127.1/",
        "http://localhost./",
        "http://LOCALHOST/",
        "http://foo.localhost/",
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "http://100.64.0.1/",  # shared address space, missed before
        "http://169.254.169.254/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://metadata.google.internal/",
        "ftp://example.com/",
        "http://exa\\mple.com/",
    ],
)
def test_sanitizer_refuses(resolver, url):
    with pytest.raises(ValueError):
        InputSanitizer.validate_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://127.1/",
        "http://user@example.com/",
    ],
)
def test_sanitizer_refuses_before_resolving(resolver, url):
    # Structural refusals do not depend on what the resolver answers.
    _, lookups = resolver
    with pytest.raises(ValueError):
        InputSanitizer.validate_url(url)
    assert lookups == []


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "100.64.0.1", "::1"])
def test_sanitizer_refuses_names_resolving_to_private_addresses(resolver, address):
    answers, _ = resolver
    answers["internal.example.com"] = address
    with pytest.raises(ValueError, match="blocked"):
        InputSanitizer.validate_url("https://internal.example.com/")


def test_url_field_schema_uses_the_shared_parser(resolver):
    from app.input_validation import UrlField
    from pydantic import BaseModel, ValidationError

    class Model(BaseModel):
        url: UrlField

    assert Model(url="http://example.com/?id=1").url == "http://example.com/?id=1"
    with pytest.raises(ValidationError):
        Model(url="http://user@example.com/")


# --- sql_injection_scanner input path --------------------------------------


def test_sql_injection_scanner_accepts_http_target_with_query(monkeypatch):
    """An http:// target with a query string reaches the scan (#561).

    Before the fix the validator refused it ("dangerous content"), so the
    scanner could not test the parameters it exists to test. The tool is
    called directly, with the caller the execution path would pass;
    authorization happens in that path (#563, test_tool_authorization.py).
    """
    requested = []

    class FakeResponse:
        text = "<html>ok</html>"

    def fake_get(url, headers=None, timeout=None):
        requested.append(url)
        return FakeResponse()

    monkeypatch.setattr(sqli_scanner.requests, "get", fake_get)

    target = "http://shop.example.com/page?id=1"
    result = sqli_scanner.execute_tool(
        SQLInjectionScannerInput(target_url=target), user_id="user-1"
    )

    assert result.target_url == target
    assert result.total_tests == len(sqli_scanner.SAFE_SQL_PAYLOADS)
    assert {r.parameter for r in result.results} == {"id"}
    assert requested and all(
        u.startswith("http://shop.example.com/page?id=") for u in requested
    )


def test_sql_injection_scanner_refuses_private_target(monkeypatch):
    def fail(*args, **kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("no request may be sent")

    monkeypatch.setattr(sqli_scanner.requests, "get", fail)
    with pytest.raises(ValueError):
        sqli_scanner.execute_tool(
            SQLInjectionScannerInput(target_url="http://127.1/page?id=1"),
            user_id="user-1",
        )
