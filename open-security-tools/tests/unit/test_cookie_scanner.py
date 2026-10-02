"""TLS certificate verification in the cookie scanner (#495)."""

import asyncio
import re

from app.tools.cookie_scanner import main as scanner
from app.tools.cookie_scanner.schemas import CookieScannerInput

SELF_SIGNED = re.compile(r"self[- ]signed", re.IGNORECASE)


def _scan(url, **options):
    return asyncio.run(
        scanner.execute_tool(CookieScannerInput(target_url=url, **options))
    )


def test_verify_ssl_is_on_by_default_in_the_schema():
    schema = CookieScannerInput.model_json_schema()["properties"]["verify_ssl"]
    assert schema["default"] is True


def test_untrusted_certificate_is_reported_not_bypassed(https_server):
    result = _scan(https_server.url)

    assert result.success is False
    assert "TLS certificate could not be verified" in result.error
    assert SELF_SIGNED.search(result.error)
    assert result.error_message == result.error
    assert result.total_cookies == 0


def test_trusted_certificate_passes_default_verification(
    https_server, trust_server_certificate
):
    result = _scan(https_server.url)

    assert result.success is True
    assert result.total_cookies == 1


def test_explicit_opt_out_scans_untrusted_target(https_server):
    result = _scan(https_server.url, verify_ssl=False)

    assert result.success is True
    assert result.total_cookies == 1
    assert result.insecure_cookies == 1
