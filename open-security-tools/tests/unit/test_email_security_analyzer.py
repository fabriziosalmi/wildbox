"""Unit tests for the Email Security Analyzer.

The tool performs real DNS lookups (SPF/DMARC/DKIM records, DNS blocklists);
these tests stub the resolver so they run offline. The suite exists to lock in
that the verdicts come from the records — the previous version produced SPF
results, DMARC policies, DKIM validity, reputation and domain age with
`random`, on top of genuine header parsing, which made the fabricated half
look trustworthy.
"""
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

APP_DIR = Path(__file__).resolve().parents[2] / "app"
TOOL_DIR = APP_DIR / "tools" / "email_security_analyzer"

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


_std = _load("email_standardized_schemas", APP_DIR / "standardized_schemas.py")
_schemas = _load(
    "email_security_schemas", TOOL_DIR / "schemas.py", {"standardized_schemas": _std}
)
esa = _load("email_security_main", TOOL_DIR / "main.py", {"schemas": _schemas})


@pytest.fixture
def analyzer():
    return esa.EmailSecurityAnalyzer()


@pytest.fixture
def txt(monkeypatch):
    """Stub the TXT resolver with a name -> records mapping."""

    def _install(records):
        monkeypatch.setattr(esa, "query_txt", lambda name: records.get(name, []))

    return _install


class TestSPF:
    def test_reports_the_published_record(self, analyzer, txt):
        txt({"example.com": ["v=spf1 include:_spf.example.com -all"]})
        result = analyzer.analyze_spf("example.com", None)
        assert result.spf_record_found is True
        assert result.spf_record == "v=spf1 include:_spf.example.com -all"
        assert "fail-closed" in result.spf_result
        assert result.authorized_senders == ["include:_spf.example.com"]

    def test_missing_record_is_reported_not_guessed(self, analyzer, txt):
        txt({})
        result = analyzer.analyze_spf("example.com", None)
        assert result.spf_record_found is False
        assert result.spf_result == "none"
        assert "No SPF record published" in result.spf_issues[0]

    def test_plus_all_is_flagged_as_equivalent_to_no_spf(self, analyzer, txt):
        txt({"example.com": ["v=spf1 +all"]})
        result = analyzer.analyze_spf("example.com", None)
        assert any("+all" in issue for issue in result.spf_issues)

    def test_multiple_records_are_a_permerror(self, analyzer, txt):
        txt({"example.com": ["v=spf1 -all", "v=spf1 ~all"]})
        result = analyzer.analyze_spf("example.com", None)
        assert result.spf_result == "permerror"

    def test_dns_lookup_limit_is_enforced(self, analyzer, txt):
        record = "v=spf1 " + " ".join(f"include:h{i}.example.com" for i in range(11)) + " -all"
        txt({"example.com": [record]})
        result = analyzer.analyze_spf("example.com", None)
        assert result.spf_result == "permerror"
        assert any("limit of 10" in issue for issue in result.spf_issues)

    def test_resolver_failure_is_temperror_not_absence(self, analyzer, monkeypatch):
        def boom(name):
            raise RuntimeError("resolver unreachable")

        monkeypatch.setattr(esa, "query_txt", boom)
        result = analyzer.analyze_spf("example.com", None)
        assert result.spf_result == "temperror"
        assert result.spf_record_found is False


class TestDMARC:
    def test_parses_the_real_policy(self, analyzer, txt):
        txt({"_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]})
        result = analyzer.analyze_dmarc("example.com", "pass", True)
        assert result.dmarc_record_found is True
        assert result.dmarc_policy == "reject"
        assert result.dmarc_compliance is True

    def test_policy_none_is_flagged(self, analyzer, txt):
        txt({"_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:d@example.com"]})
        result = analyzer.analyze_dmarc("example.com", "none", False)
        assert result.dmarc_policy == "none"
        assert any("monitoring only" in issue for issue in result.dmarc_issues)

    def test_partial_pct_and_weak_subdomain_policy_are_flagged(self, analyzer, txt):
        txt({"_dmarc.example.com": ["v=DMARC1; p=reject; pct=20; sp=none; rua=mailto:d@e.com"]})
        result = analyzer.analyze_dmarc("example.com", "pass", False)
        assert any("20%" in issue for issue in result.dmarc_issues)
        assert any("sp=none" in issue for issue in result.dmarc_issues)

    def test_missing_record_is_reported(self, analyzer, txt):
        txt({})
        result = analyzer.analyze_dmarc("example.com", "none", False)
        assert result.dmarc_record_found is False
        assert result.dmarc_policy is None
        assert result.dmarc_compliance is False


class TestDKIM:
    HEADERS = {
        "headers": {"DKIM-Signature": "v=1; a=rsa-sha256; d=example.com; s=sel1; b=abc"},
        "from": "a@example.com",
    }

    def test_missing_public_key_is_reported(self, analyzer, txt):
        txt({})
        result = analyzer.analyze_dkim(self.HEADERS)
        assert result.dkim_valid is False
        assert any("No DKIM public key" in issue for issue in result.dkim_issues)

    def test_revoked_key_is_detected(self, analyzer, txt):
        txt({"sel1._domainkey.example.com": ["v=DKIM1; k=rsa; p="]})
        result = analyzer.analyze_dkim(self.HEADERS)
        assert any("revoked" in issue for issue in result.dkim_issues)

    def test_published_key_does_not_claim_a_crypto_verdict(self, analyzer, txt):
        txt({"sel1._domainkey.example.com": ["v=DKIM1; k=rsa; p=" + "A" * 400]})
        result = analyzer.analyze_dkim(self.HEADERS)
        # The signature itself is not verified — the tool only sees headers.
        assert any("NOT cryptographically verified" in i for i in result.dkim_issues)


class TestReputation:
    def test_listings_drive_the_verdict(self, analyzer, monkeypatch):
        monkeypatch.setattr(esa, "check_ip_blocklist", lambda ip, zone: True)
        monkeypatch.setattr(esa, "check_domain_blocklist", lambda d, zone: False)
        result = analyzer.analyze_reputation("bad.example", "93.184.216.34")
        assert result.domain_reputation == "malicious"   # 3 IP blocklists hit
        assert result.ip_reputation == "listed"

    def test_clean_host_is_neutral_never_good(self, analyzer, monkeypatch):
        monkeypatch.setattr(esa, "check_ip_blocklist", lambda ip, zone: False)
        monkeypatch.setattr(esa, "check_domain_blocklist", lambda d, zone: False)
        result = analyzer.analyze_reputation("example.com", "93.184.216.34")
        # Absence of a negative signal is not a positive endorsement.
        assert result.domain_reputation == "neutral"
        assert result.ip_reputation == "not listed"

    def test_unavailable_data_is_none_not_invented(self, analyzer, monkeypatch):
        monkeypatch.setattr(esa, "check_ip_blocklist", lambda ip, zone: False)
        monkeypatch.setattr(esa, "check_domain_blocklist", lambda d, zone: False)
        result = analyzer.analyze_reputation("example.com", None)
        assert result.domain_age_days is None    # needs WHOIS/RDAP, not queried
        assert result.whitelist_status == {}     # dashboards behind auth


class TestLinkAndRoutingAnalysis:
    def test_flags_only_genuinely_suspicious_urls(self, analyzer):
        headers = analyzer.parse_email_headers(
            "From: Test <a@example.com>\nSubject: hello\n"
        )
        content = (
            "http://192.168.1.1/login "
            "https://bit.ly/x "
            "https://paypal.evil.tld/ "
            "https://google.com/legitimate"
        )
        result = analyzer.detect_phishing_indicators(headers, content)
        assert len(result.suspicious_links) == 3
        joined = " ".join(result.suspicious_links)
        assert "bare IP address" in joined
        assert "URL shortener" in joined
        assert "brand name in a domain" in joined
        assert "google.com/legitimate" not in joined

    def test_no_content_means_no_link_findings(self, analyzer):
        headers = analyzer.parse_email_headers("From: a@example.com\nSubject: x\n")
        assert analyzer.detect_phishing_indicators(headers, "").suspicious_links == []

    def test_delivery_delay_comes_from_the_received_timestamps(self, analyzer):
        received = [
            "from mx1.example.com; Mon, 1 Jan 2026 10:00:00 +0000",
            "from mx2.example.com; Mon, 1 Jan 2026 09:00:00 +0000",
        ]
        result = analyzer.analyze_email_routing(received)
        assert result.delivery_delay == pytest.approx(1.0)

    def test_unparsable_timestamps_yield_no_delay(self, analyzer):
        result = analyzer.analyze_email_routing(["from mx1.example.com; not a date"])
        assert result.delivery_delay is None


class TestBlocklistQueries:
    def test_private_and_invalid_addresses_are_never_queried(self):
        assert esa.check_ip_blocklist("10.0.0.1", "zen.spamhaus.org") is False
        assert esa.check_ip_blocklist("not-an-ip", "zen.spamhaus.org") is False

    def test_resolver_failure_is_not_a_listing(self, monkeypatch):
        class FailingResolver:
            def resolve(self, *args, **kwargs):
                raise RuntimeError("network down")

        monkeypatch.setattr(esa, "_resolver", lambda: FailingResolver())
        assert esa.check_ip_blocklist("93.184.216.34", "zen.spamhaus.org") is False
        assert esa.check_domain_blocklist("example.com", "multi.surbl.org") is False
