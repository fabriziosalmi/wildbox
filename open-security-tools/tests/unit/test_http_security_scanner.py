"""TLS certificate verification in the HTTP security headers scanner (#495)."""

import asyncio
import re

from app.tools.http_security_scanner import main as scanner
from app.tools.http_security_scanner.schemas import HttpSecurityScannerInput

SELF_SIGNED = re.compile(r"self[- ]signed", re.IGNORECASE)


def _scan(url, **options):
    return asyncio.run(
        scanner.execute_tool(HttpSecurityScannerInput(url=url, **options))
    )


def test_verify_ssl_is_on_by_default_in_the_schema():
    schema = HttpSecurityScannerInput.model_json_schema()["properties"]["verify_ssl"]
    assert schema["default"] is True


def test_untrusted_certificate_is_reported_not_bypassed(https_server):
    result = _scan(https_server.url)

    assert result.success is False
    assert result.status == "tls_verification_failed"
    assert "TLS certificate could not be verified" in result.error_message
    assert SELF_SIGNED.search(result.error_message)
    assert result.http_status is None
    assert result.security_headers == []


def test_trusted_certificate_passes_default_verification(
    https_server, trust_server_certificate
):
    result = _scan(https_server.url)

    assert result.success is True
    assert result.http_status == 200
    assert "certificate_verification" not in result.findings


def test_explicit_opt_out_scans_untrusted_target(https_server):
    result = _scan(https_server.url, verify_ssl=False)

    assert result.success is True
    assert result.http_status == 200
    assert result.findings["certificate_verification"].startswith("disabled")
