"""Unit tests for the indicator normalization helpers.

Pure-logic, no DB/service needed. Locks in the value-canonicalization rules
that downstream dedup/fingerprinting (create_fingerprint) and tenancy-scoped
querying rely on producing stable, comparable values.
"""
from datetime import datetime, timezone

import pytest

from app.utils.normalizers import (
    create_fingerprint,
    merge_indicators,
    normalize_asn,
    normalize_cve,
    normalize_domain,
    normalize_email,
    normalize_file_hash,
    normalize_indicator,
    normalize_ip_address,
    normalize_timestamp,
    normalize_url,
)


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", "8.8.8.8"),
    (" 1.1.1.1 ", "1.1.1.1"),
    ("::1", "::1"),
])
def test_normalize_ip_address_valid(value, expected):
    assert normalize_ip_address(value) == expected


def test_normalize_ip_address_invalid_passthrough():
    # Not a parseable IP -> returned stripped, not raised
    assert normalize_ip_address(" not-an-ip ") == "not-an-ip"


@pytest.mark.parametrize("value,expected", [
    ("EXAMPLE.com", "example.com"),
    ("https://Example.COM/path", "example.com"),
    ("example.com.", "example.com"),
    ("example.com:8080", "example.com"),
])
def test_normalize_domain(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("example.com/path", "http://example.com/path"),
    ("HTTP://Example.com:80/", "http://example.com/"),
    ("https://Example.com:443/a", "https://example.com/a"),
    ("https://example.com:8443/a", "https://example.com:8443/a"),
])
def test_normalize_url(value, expected):
    assert normalize_url(value) == expected


def test_normalize_file_hash_strips_known_prefix():
    assert normalize_file_hash("SHA256:AABBCC") == "aabbcc"


def test_normalize_file_hash_rejects_non_hex_passthrough():
    original = " not-hex! "
    assert normalize_file_hash(original) == original.strip()


def test_normalize_email_lowercases_and_strips():
    assert normalize_email(" User@Example.COM ") == "user@example.com"


def test_normalize_asn_adds_prefix():
    assert normalize_asn("15169") == "AS15169"
    assert normalize_asn("as15169") == "AS15169"


def test_normalize_cve_uppercases():
    assert normalize_cve("cve-2024-12345") == "CVE-2024-12345"


@pytest.mark.parametrize("raw,expected_year", [
    ("2024-01-15T10:30:00Z", 2024),
    ("2024-01-15 10:30:00", 2024),
    ("2024-01-15", 2024),
])
def test_normalize_timestamp_parses_common_formats(raw, expected_year):
    dt = normalize_timestamp(raw)
    assert dt is not None
    assert dt.year == expected_year
    assert dt.tzinfo is not None


def test_normalize_timestamp_handles_unix_epoch():
    dt = normalize_timestamp("1700000000")
    assert dt is not None
    assert dt.tzinfo is not None


def test_normalize_timestamp_returns_none_for_garbage():
    assert normalize_timestamp("not-a-date") is None
    assert normalize_timestamp("") is None


def test_normalize_timestamp_naive_datetime_gets_utc():
    naive = datetime(2024, 1, 1, 12, 0, 0)
    result = normalize_timestamp(naive)
    assert result.tzinfo == timezone.utc


def test_normalize_indicator_domain_sets_value_and_normalized_value():
    raw = {"indicator_type": "domain", "value": "HTTPS://Example.COM/x"}
    result = normalize_indicator(raw)
    assert result["normalized_value"] == "example.com"
    assert result["value"] == "example.com"


def test_normalize_indicator_ip_keeps_original_value_field():
    # IP normalization only populates normalized_value, not value, per the
    # normalizer dispatch table in normalize_indicator.
    raw = {"indicator_type": "ip_address", "value": "8.8.8.8"}
    result = normalize_indicator(raw)
    assert result["normalized_value"] == "8.8.8.8"
    assert result["value"] == "8.8.8.8"


def test_normalize_indicator_defaults_severity_on_bad_value():
    raw = {"indicator_type": "domain", "value": "example.com", "severity": "not-a-number"}
    result = normalize_indicator(raw)
    assert result["severity"] == 5


def test_normalize_indicator_lowercases_tags_and_threat_types():
    raw = {
        "indicator_type": "domain",
        "value": "example.com",
        "tags": "Malware, C2",
        "threat_types": ["Botnet", "Phishing"],
    }
    result = normalize_indicator(raw)
    assert result["tags"] == ["malware", "c2"]
    assert result["threat_types"] == ["botnet", "phishing"]


def test_create_fingerprint_is_deterministic():
    data = {"indicator_type": "domain", "normalized_value": "example.com", "source_id": "src-1"}
    assert create_fingerprint(data) == create_fingerprint(dict(data))


def test_create_fingerprint_differs_on_value_change():
    base = {"indicator_type": "domain", "normalized_value": "example.com", "source_id": "src-1"}
    other = {**base, "normalized_value": "other.com"}
    assert create_fingerprint(base) != create_fingerprint(other)


def test_merge_indicators_keeps_latest_last_seen_and_earliest_first_seen():
    existing = {
        "first_seen": "2024-01-10",
        "last_seen": "2024-01-10",
        "threat_types": ["botnet"],
        "tags": ["a"],
        "confidence": "low",
        "severity": 3,
    }
    new = {
        "first_seen": "2024-01-01",
        "last_seen": "2024-02-01",
        "threat_types": ["phishing"],
        "tags": ["b"],
        "confidence": "high",
        "severity": 7,
    }
    merged = merge_indicators(existing, new)

    assert merged["first_seen"] == normalize_timestamp("2024-01-01")
    assert merged["last_seen"] == normalize_timestamp("2024-02-01")
    assert set(merged["threat_types"]) == {"botnet", "phishing"}
    assert set(merged["tags"]) == {"a", "b"}
    assert merged["confidence"] == "high"
    assert merged["severity"] == 7


def test_merge_indicators_does_not_downgrade_confidence_or_severity():
    existing = {"confidence": "high", "severity": 8}
    new = {"confidence": "low", "severity": 2}
    merged = merge_indicators(existing, new)

    assert merged["confidence"] == "high"
    assert merged["severity"] == 8
