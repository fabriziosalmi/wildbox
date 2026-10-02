"""TLS certificate verification in the web vulnerability scanner (#495).

The scanner used to build its connector with ``ssl=False``, so it accepted
any certificate and reported results that could have come from an
intercepted connection. Verification is now on by default and a failure is
reported to the caller; ``verify_ssl=False`` is an explicit per-scan opt-out.
"""

import asyncio
import re

from app.tools.web_vuln_scanner import main as scanner
from app.tools.web_vuln_scanner.schemas import WebVulnScannerInput

SELF_SIGNED = re.compile(r"self[- ]signed", re.IGNORECASE)


def _scan(url, **options):
    return asyncio.run(
        scanner.execute_tool(WebVulnScannerInput(target_url=url, **options))
    )


def test_verify_ssl_is_on_by_default_in_the_schema():
    schema = WebVulnScannerInput.model_json_schema()["properties"]["verify_ssl"]
    assert schema["default"] is True
    assert WebVulnScannerInput(target_url="https://example.com").verify_ssl is True


def test_untrusted_certificate_is_reported_not_bypassed(https_server):
    result = _scan(https_server.url)

    assert result.success is False
    assert result.status == "tls_verification_failed"
    assert "TLS certificate could not be verified" in result.error_message
    assert SELF_SIGNED.search(result.error_message)
    # Nothing was scanned over the unverified connection.
    assert result.pages_scanned == 0
    assert result.security_headers == []
    assert result.vulnerabilities == []


def test_trusted_certificate_passes_default_verification(
    https_server, trust_server_certificate
):
    result = _scan(https_server.url)

    assert result.success is True
    assert result.status == "completed"
    assert result.ssl_info["verified"] is True
    frame = next(h for h in result.security_headers if h.header == "X-Frame-Options")
    assert frame.present and frame.value == "DENY"


def test_explicit_opt_out_scans_untrusted_target(https_server):
    result = _scan(https_server.url, verify_ssl=False)

    assert result.success is True
    assert result.status == "completed"
    assert result.ssl_info["verified"] is False
    frame = next(h for h in result.security_headers if h.header == "X-Frame-Options")
    assert frame.present
