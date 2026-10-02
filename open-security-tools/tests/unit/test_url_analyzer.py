"""TLS certificate verification in the URL analyzer (#495).

The SSRF guard refuses loopback targets, so it is bypassed here to reach the
local test server; the guard has its own tests in test_ssrf_guard.py.
"""

import asyncio
import re

import pytest
from app.tools.url_analyzer import main as analyzer
from app.tools.url_analyzer.schemas import URLShortenerInput

SELF_SIGNED = re.compile(r"self[- ]signed", re.IGNORECASE)


@pytest.fixture(autouse=True)
def allow_loopback_target(monkeypatch):
    monkeypatch.setattr(
        analyzer.InputSanitizer, "validate_url", staticmethod(lambda url: url)
    )


def _analyze(url, **options):
    return asyncio.run(
        analyzer.execute_tool(URLShortenerInput(shortened_url=url, **options))
    )


def test_verify_ssl_is_on_by_default_in_the_schema():
    schema = URLShortenerInput.model_json_schema()["properties"]["verify_ssl"]
    assert schema["default"] is True


def test_untrusted_certificate_is_reported_not_bypassed(https_server):
    result = _analyze(https_server.url)

    assert result.success is False
    assert "TLS certificate could not be verified" in result.error
    assert SELF_SIGNED.search(result.error)
    assert result.redirect_chain == []


def test_trusted_certificate_passes_default_verification(
    https_server, trust_server_certificate
):
    result = _analyze(https_server.url)

    assert result.success is True
    assert [hop.status_code for hop in result.redirect_chain] == [200]


def test_explicit_opt_out_analyzes_untrusted_target(https_server):
    result = _analyze(https_server.url, verify_ssl=False)

    assert result.success is True
    assert [hop.status_code for hop in result.redirect_chain] == [200]
