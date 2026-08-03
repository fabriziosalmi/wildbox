"""Unit tests for the WAF Bypass Tester.

The tool sends real HTTP requests to a target; these tests stub aiohttp so
they run offline. The suite locks in that bypass verdicts come from the real
response (status + WAF signatures), not from hash(payload) % 100 as the
previous _simulate_request did, and that the tool refuses unauthorised
targets.
"""
import asyncio
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

APP_DIR = Path(__file__).resolve().parents[2] / "app"
TOOL_DIR = APP_DIR / "tools" / "web_application_firewall_bypass"

sys.path.insert(0, str(APP_DIR))


def _load(name, path, extra_modules=None):
    """Load a tool module under a unique name (see test_ct_log_scanner)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    injected = list((extra_modules or {}).items())
    for key, value in injected:
        sys.modules[key] = value
    try:
        spec.loader.exec_module(module)
    finally:
        for key, _ in injected:
            sys.modules.pop(key, None)
    return module


_std = _load("waf_standardized_schemas", APP_DIR / "standardized_schemas.py")
_schemas = _load("waf_schemas", TOOL_DIR / "schemas.py", {"standardized_schemas": _std})
waf = _load("waf_main", TOOL_DIR / "main.py", {"schemas": _schemas})


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


@pytest.fixture
def request_factory():
    def _make(url="https://test.local/app", **overrides):
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
    """Make every aiohttp.ClientSession the tool opens a FakeSession."""
    monkeypatch.setattr(
        waf.aiohttp, "ClientSession", lambda *a, **k: FakeSession(responder)
    )
    monkeypatch.setattr(waf.aiohttp, "TCPConnector", lambda *a, **k: None)
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

        monkeypatch.setattr(waf, "_ENV_AUTHORIZED", ["test.local"])
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
