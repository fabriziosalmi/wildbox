"""Unit tests for the WAF Bypass Tester.

The tool sends real HTTP requests to a target; these tests stub aiohttp so
they run offline. The suite locks in that bypass verdicts come from the real
response (status + WAF signatures), not from hash(payload) % 100 as the
previous _simulate_request did, and that the tool refuses unauthorised
targets.
"""
import asyncio
import os
import socket
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

SERVICE_ROOT = Path(__file__).resolve().parents[2]
APP_DIR = SERVICE_ROOT / "app"
TOOL_DIR = APP_DIR / "tools" / "web_application_firewall_bypass"

# The service root, not APP_DIR: `import app.tools...` needs the directory that
# *contains* the app package on sys.path. Inserting APP_DIR itself worked only
# under `python -m pytest`, which puts the working directory on sys.path too;
# CI runs plain `pytest`, where it failed with
# ModuleNotFoundError: No module named 'app'.
sys.path.insert(0, str(SERVICE_ROOT))


# Tools are real packages, so a plain import is all that is needed. This
# file used to carry its own copy of the loader's sys.modules injection,
# because every tool had a bare top-level `schemas` module that collided
# across test files (WILDBO-ARCH-03/ARCH-06).
from app.tools.web_application_firewall_bypass import main as _tool_main  # noqa: E402
from app.tools.web_application_firewall_bypass import schemas as _tool_schemas  # noqa: E402
from app import standardized_schemas as _std_schemas  # noqa: E402

_std = _std_schemas
_schemas = _tool_schemas
waf = _tool_main


class FakeResponse:
    def __init__(self, status, headers=None, body=""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    async def text(self, errors="replace"):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """Maps a substring of the request URL to a FakeResponse."""

    def __init__(self, responder):
        self._responder = responder

    def get(self, url, **kwargs):
        return self._responder(url)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


PUBLIC_IP = "93.184.215.14"


@pytest.fixture(autouse=True)
def resolver(monkeypatch):
    """Resolve every name to PUBLIC_IP unless mapped otherwise; no real DNS."""
    answers = {}

    def fake_getaddrinfo(host, *args, **kwargs):
        ip = answers.get(host, PUBLIC_IP)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return answers


@pytest.fixture
def request_factory():
    def _make(url="https://app.example.com/app", **overrides):
        params = dict(
            target_url=url,
            payload_types=["xss"],
            encoding_techniques=["none"],
            obfuscation_methods=["none"],
        )
        params.update(overrides)
        return _schemas.WAFBypassRequest(**params)

    return _make


def _patch_session(monkeypatch, responder):
    """Make every guarded session the tool opens a FakeSession."""
    monkeypatch.setattr(waf, "guarded_session", lambda *a, **k: FakeSession(responder))
    monkeypatch.setattr(waf.aiohttp, "ClientTimeout", lambda *a, **k: None)


class TestAuthorization:
    def test_unauthorised_target_is_refused_without_any_request(self, request_factory, monkeypatch):
        called = {"n": 0}

        def responder(url):
            called["n"] += 1
            return FakeResponse(200)

        _patch_session(monkeypatch, responder)
        out = asyncio.run(waf.execute_tool(request_factory(url="https://not-mine.example/")))
        assert out.success is False
        assert out.total_payloads_tested == 0
        assert called["n"] == 0                       # never touched the target
        assert "not authorised" in out.summary.lower()

    def test_env_allowlist_authorises_a_target(self, request_factory, monkeypatch):
        monkeypatch.setattr(waf, "_ENV_AUTHORIZED", ["mytarget.example"])
        _patch_session(monkeypatch, lambda url: FakeResponse(200, body="ok"))
        out = asyncio.run(waf.execute_tool(request_factory(url="https://mytarget.example/x")))
        assert out.success is True
        assert out.total_payloads_tested > 0


    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/app",
            "http://127.0.0.1/app",
            "http://app.local/app",
            "http://app.test/app",
            "http://169.254.169.254/latest/meta-data/",
        ],
    )
    def test_local_targets_are_not_authorised(self, request_factory, monkeypatch, url):
        """The tool's own list no longer allows local hosts (#610)."""
        called = []
        _patch_session(monkeypatch, lambda u: called.append(u) or FakeResponse(200))
        out = asyncio.run(waf.execute_tool(request_factory(url=url)))
        assert out.success is False
        assert called == []

    def test_local_targets_stay_refused_when_allowlisted(self, request_factory, monkeypatch, resolver):
        """The operator allowlist cannot override the SSRF guard."""
        resolver["app.local"] = "192.168.1.20"  # what mDNS would answer
        monkeypatch.setattr(waf, "_ENV_AUTHORIZED", ["localhost", "127.0.0.1", "app.local"])
        called = []
        _patch_session(monkeypatch, lambda u: called.append(u) or FakeResponse(200))
        for url in ("http://localhost/", "http://127.0.0.1/", "http://app.local/"):
            out = asyncio.run(waf.execute_tool(request_factory(url=url)))
            assert out.success is False
        assert called == []

    def test_user_info_cannot_borrow_an_authorised_name(self, request_factory, monkeypatch):
        """'example.com@evil.example' used to match the allowlist by its user info."""
        called = []
        _patch_session(monkeypatch, lambda u: called.append(u) or FakeResponse(200))
        for url in ("https://example.com@evil.example/", "https://x@app.example.com/"):
            out = asyncio.run(waf.execute_tool(request_factory(url=url)))
            assert out.success is False
        assert called == []

    def test_authorised_name_resolving_to_a_private_address_is_refused(
        self, request_factory, monkeypatch, resolver
    ):
        resolver["app.example.com"] = "10.0.0.7"
        called = []
        _patch_session(monkeypatch, lambda u: called.append(u) or FakeResponse(200))
        out = asyncio.run(waf.execute_tool(request_factory()))
        assert out.success is False
        assert called == []


class TestBypassVerdicts:
    def test_a_real_200_with_no_waf_signature_is_a_bypass(self, request_factory, monkeypatch):
        _patch_session(monkeypatch, lambda url: FakeResponse(200, body="welcome"))
        out = asyncio.run(waf.execute_tool(request_factory()))
        assert out.successful_bypasses == out.total_payloads_tested
        assert all(p.bypass_success for p in out.payload_results)

    def test_a_403_is_never_a_bypass(self, request_factory, monkeypatch):
        _patch_session(monkeypatch, lambda url: FakeResponse(403, body="blocked"))
        out = asyncio.run(waf.execute_tool(request_factory()))
        assert out.successful_bypasses == 0
        assert all(p.waf_triggered or not p.bypass_success for p in out.payload_results)

    def test_a_200_carrying_a_waf_signature_is_not_a_bypass(self, request_factory, monkeypatch):
        # 200 status but a Cloudflare block signature in the body.
        _patch_session(
            monkeypatch,
            lambda url: FakeResponse(200, headers={"cf-ray": "abc-SJC"}, body="access denied"),
        )
        out = asyncio.run(waf.execute_tool(request_factory()))
        assert out.successful_bypasses == 0
        assert all(p.waf_triggered for p in out.payload_results)
        assert any("cloudflare" in sig for p in out.payload_results for sig in p.detection_signatures)

    def test_a_failed_request_is_not_counted_as_a_bypass(self, request_factory, monkeypatch):
        def responder(url):
            raise waf.aiohttp.ClientError("connection reset")

        _patch_session(monkeypatch, responder)
        out = asyncio.run(waf.execute_tool(request_factory()))
        assert out.successful_bypasses == 0
        assert all(p.response_code == 0 and not p.bypass_success for p in out.payload_results)


class TestPayloadTransformationsAreReal:
    def test_the_payload_actually_sent_is_encoded(self, request_factory, monkeypatch):
        seen = []

        def responder(url):
            seen.append(url)
            return FakeResponse(200, body="ok")

        _patch_session(monkeypatch, responder)
        asyncio.run(
            waf.execute_tool(
                request_factory(
                    payload_types=["xss"],
                    encoding_techniques=["base64"],
                    obfuscation_methods=["none"],
                )
            )
        )
        # Base64 of "<img src=x>" is "PGltZyBzcmM9eD4=" -> url-encoded in the query.
        assert seen and any("PGltZy" in url for url in seen)


class TestRequestCap:
    def test_the_request_grid_is_capped(self, request_factory, monkeypatch):
        sent = {"n": 0}

        def responder(url):
            sent["n"] += 1
            return FakeResponse(200, body="ok")

        monkeypatch.setattr(waf, "_MAX_REQUESTS", 3)
        _patch_session(monkeypatch, responder)
        out = asyncio.run(
            waf.execute_tool(
                request_factory(
                    payload_types=["xss", "sql_injection"],
                    encoding_techniques=["none", "url_encoding", "base64"],
                    obfuscation_methods=["none", "case_variation"],
                )
            )
        )
        # The grid is far larger than 3; the baseline request is separate.
        assert out.total_payloads_tested == 3
