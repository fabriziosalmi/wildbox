"""Unit tests for the Certificate Transparency Log Scanner.

The tool queries crt.sh over the network; these tests exercise the parsing
and analysis logic against captured crt.sh response shapes, so they need no
network access. The point of the suite is to lock in that every reported
value is derived from the log entry — the previous version of this tool
fabricated issuers, key sizes and fingerprints with `random`.
"""
import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

APP_DIR = Path(__file__).resolve().parents[2] / "app"
TOOL_DIR = APP_DIR / "tools" / "ct_log_scanner"

sys.path.insert(0, str(APP_DIR))


def _load(name, path, extra_modules=None):
    """Load a tool module under a unique name.

    Every tool package has a module literally called `schemas`, and the tool
    code imports it as a bare top-level `from schemas import ...`. Registering
    that name globally (sys.path.insert of the tool dir) makes the FIRST test
    module to import win for all the others — which is why this loader
    registers `schemas` only for the duration of the tool import and removes
    it afterwards.
    """
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


_std = _load("ct_standardized_schemas", APP_DIR / "standardized_schemas.py")
_schemas = _load(
    "ct_log_scanner_schemas",
    TOOL_DIR / "schemas.py",
    {"standardized_schemas": _std},
)
ct_main = _load("ct_log_scanner_main", TOOL_DIR / "main.py", {"schemas": _schemas})
CTLogScannerInput = _schemas.CTLogScannerInput

NOW = datetime(2026, 8, 3, tzinfo=timezone.utc)

# Shape taken from a real crt.sh ?output=json response.
ENTRY = {
    "issuer_ca_id": 295815,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
    "common_name": "example.com",
    "name_value": "example.com\n*.example.com",
    "id": 1234567890,
    "entry_timestamp": "2026-01-15T10:00:00.123",
    "not_before": "2026-01-15T09:00:00",
    "not_after": "2027-04-15T09:00:00",
    "serial_number": "03a1b2c3",
}


def _entry(**overrides):
    return {**ENTRY, **overrides}


class TestEntryParsing:
    def test_maps_real_fields_from_the_log_entry(self):
        cert = ct_main.to_certificate_info(ENTRY, NOW)
        assert cert.issuer == "Let's Encrypt"          # O= extracted from the DN
        assert cert.subject == "example.com"
        assert cert.subject_alt_names == ["*.example.com", "example.com"]
        assert cert.serial_number == "03a1b2c3"
        assert cert.ct_log_entry_id == "1234567890"
        assert cert.not_after.startswith("2027-04-15")

    def test_unavailable_fields_are_unknown_not_invented(self):
        """crt.sh does not carry these; they must not be guessed."""
        cert = ct_main.to_certificate_info(ENTRY, NOW)
        assert cert.key_algorithm == "unknown"
        assert cert.signature_algorithm == "unknown"
        assert cert.fingerprint_sha256 == "unknown"
        assert cert.key_size is None

    def test_expiry_is_computed_from_not_after(self):
        assert ct_main.to_certificate_info(ENTRY, NOW).is_expired is False
        expired = _entry(not_after="2026-01-20T09:00:00")
        assert ct_main.to_certificate_info(expired, NOW).is_expired is True

    def test_entry_without_expiry_is_dropped(self):
        assert ct_main.to_certificate_info(_entry(not_after=None), NOW) is None

    def test_timestamp_accepts_both_crtsh_formats(self):
        assert ct_main._parse_ct_timestamp("2026-01-15T09:00:00") is not None
        assert ct_main._parse_ct_timestamp("2026-01-15T09:00:00.123") is not None
        assert ct_main._parse_ct_timestamp("not a date") is None

    def test_issuer_falls_back_to_the_raw_dn(self):
        cert = ct_main.to_certificate_info(_entry(issuer_name="CN=Some CA"), NOW)
        assert cert.issuer == "CN=Some CA"


class TestAnalysis:
    def test_subdomain_analysis_counts_only_in_scope_hostnames(self):
        cert = ct_main.to_certificate_info(
            _entry(name_value="a.example.com\n*.example.com\nunrelated.tld"), NOW
        )
        result = ct_main.analyze_subdomains([cert], "example.com")
        assert result["unique_hostnames"] == 2      # unrelated.tld excluded
        assert result["wildcard_certificates"] == 1
        assert result["subdomains"] == ["a.example.com"]

    def test_issuer_analysis_counts_per_ca(self):
        certs = [
            ct_main.to_certificate_info(ENTRY, NOW),
            ct_main.to_certificate_info(ENTRY, NOW),
            ct_main.to_certificate_info(_entry(issuer_name="C=US, O=Amazon"), NOW),
        ]
        result = ct_main.analyze_issuers(certs)
        assert result["distinct_issuers"] == 2
        assert result["primary_issuer"] == "Let's Encrypt"
        assert result["certificates_per_issuer"]["Let's Encrypt"] == 2

    def test_timeline_flags_certificates_expiring_within_30_days(self):
        soon = ct_main.to_certificate_info(_entry(not_after="2026-08-20T09:00:00"), NOW)
        far = ct_main.to_certificate_info(ENTRY, NOW)
        result = ct_main.analyze_timeline([soon, far], NOW)
        assert result["expiring_within_30_days"] == ["example.com"]
        assert result["active_certificates"] == 2

    def test_lookalike_hostname_is_flagged(self):
        cert = ct_main.to_certificate_info(
            _entry(name_value="example.com.phishing.tld"), NOW
        )
        findings = ct_main.detect_suspicious_patterns([cert], "example.com", NOW)
        assert findings and "phishing.tld" in findings[0]

    def test_legitimate_subdomain_is_not_flagged(self):
        cert = ct_main.to_certificate_info(_entry(name_value="mail.example.com"), NOW)
        assert ct_main.detect_suspicious_patterns([cert], "example.com", NOW) == []

    def test_recommendations_are_derived_from_the_data(self):
        subs = {"unique_hostnames": 2, "wildcard_certificates": 1}
        timeline = {"expiring_within_30_days": ["example.com"]}
        recs = ct_main.generate_recommendations(subs, timeline, [])
        assert any("expire" in r for r in recs)
        assert any("Wildcard" in r for r in recs)


class TestExecuteTool:
    def test_rejects_a_malformed_domain_without_calling_the_network(self):
        out = asyncio.run(ct_main.execute_tool(CTLogScannerInput(domain="not a domain")))
        assert out.success is False
        assert "valid domain" in out.message

    def test_reports_lookup_failure_instead_of_fabricating_results(self, monkeypatch):
        async def boom(domain, include_subdomains):
            raise ct_main.CTLogLookupError("crt.sh returned HTTP 503")

        monkeypatch.setattr(ct_main, "fetch_ct_entries", boom)
        out = asyncio.run(ct_main.execute_tool(CTLogScannerInput(domain="example.com")))
        assert out.success is False
        assert out.certificates_found == []
        assert out.total_certificates == 0
        assert "503" in out.message

    def test_applies_filters_and_reports_truncation(self, monkeypatch):
        entries = [
            _entry(not_after=f"2027-0{i}-15T09:00:00", common_name=f"h{i}.example.com")
            for i in range(1, 6)
        ]
        entries.append(_entry(not_after="2026-01-01T09:00:00", common_name="old.example.com"))

        async def fake_fetch(domain, include_subdomains):
            return entries

        monkeypatch.setattr(ct_main, "fetch_ct_entries", fake_fetch)
        out = asyncio.run(
            ct_main.execute_tool(
                CTLogScannerInput(domain="example.com", max_results=2, include_expired=False)
            )
        )
        assert out.success is True
        assert out.total_certificates == 5           # the expired one is filtered out
        assert len(out.certificates_found) == 2      # capped by max_results
        assert out.security_insights["truncated"] is True
        # Newest first, so truncation keeps the relevant end.
        assert out.certificates_found[0].not_after > out.certificates_found[1].not_after
