"""The tools service answers the shared scan target vectors (#748).

What is internal, what an allowlist covers and how a host is parsed are now
decided by ``open_security_shared.target_policy``, which guardian's asset
discovery and port scans use too. ``tests/shared/target_policy_vectors.json``
holds the cases the two services must agree on; guardian's unit tests and
the shared package's run the same file.

Here they go through this service's entry point, ``check_value``, as a
tool's input does: the refusal is a ``TargetRefused`` with this service's
words and its own setting in them. ``test_target_policy.py`` is the suite of
the policy itself and is unchanged by the move.
"""

import ipaddress
import json
import os
import socket
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import target_policy as tp  # noqa: E402
from app import url_guard  # noqa: E402
from app.input_validation import InputSanitizer  # noqa: E402
from app.target_policy import (  # noqa: E402
    TargetKind,
    TargetRefused,
    check_value,
    parse_allowlist,
)
from open_security_shared import target_policy as shared  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS_FILE = REPO_ROOT / "tests" / "shared" / "target_policy_vectors.json"
VECTORS = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
SETTING = "TOOLS_ALLOWED_INTERNAL_TARGETS"


def _id(case):
    key = case.get("address") if "network" not in case else case["network"]
    return f"{key}|{case.get('allow', '')}"


@pytest.fixture
def no_lookups(monkeypatch):
    """No case here is a name: a lookup is a failure."""
    lookups = []

    def fake_getaddrinfo(host, *args, **kwargs):
        lookups.append(host)
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    yield
    assert lookups == []


def test_there_are_vectors():
    assert len(VECTORS["addresses"]) >= 60
    assert len(VECTORS["networks"]) >= 50


@pytest.mark.parametrize("case", VECTORS["addresses"], ids=_id)
@pytest.mark.parametrize(
    "kind", [TargetKind.HOST, TargetKind.IP, TargetKind.IP_OR_CIDR]
)
def test_an_address_is_allowed_or_internal(case, kind, no_lookups):
    allowlist = parse_allowlist(case.get("allow", ""))

    if case["expect"] == "allowed":
        check_value(kind, case["address"], allowlist)
    else:
        with pytest.raises(TargetRefused, match=f"internal.*{SETTING}"):
            check_value(kind, case["address"], allowlist)


@pytest.mark.parametrize("case", VECTORS["embedded"], ids=lambda c: c["address"])
def test_the_ipv4_address_inside_an_ipv6_one(case):
    found = tp._embedded_ipv4(ipaddress.ip_address(case["address"]))

    assert found == (ipaddress.ip_address(case["ipv4"]) if case["ipv4"] else None)


@pytest.mark.parametrize("value", VECTORS["spellings"])
@pytest.mark.parametrize(
    "kind", [TargetKind.HOST, TargetKind.IP, TargetKind.IP_OR_CIDR]
)
def test_another_spelling_of_an_address_is_refused(value, kind, no_lookups):
    with pytest.raises(TargetRefused):
        check_value(kind, value, parse_allowlist(""))


@pytest.mark.parametrize("case", VECTORS["networks"], ids=_id)
@pytest.mark.parametrize("kind", [TargetKind.IP_OR_CIDR, TargetKind.NETWORK])
def test_a_network_is_allowed_or_refused_whole(case, kind):
    allowlist = parse_allowlist(case.get("allow", ""))

    if case["expect"] == "allowed":
        check_value(kind, case["network"], allowlist)
        return
    with pytest.raises(TargetRefused) as refused:
        check_value(kind, case["network"], allowlist)
    message = str(refused.value)
    if case["expect"] == "too_large":
        assert f"at most {shared.MAX_TARGET_ADDRESSES}" in message
    elif case["expect"] == "internal":
        assert f"includes {ipaddress.ip_address(case['address'])}, " in message
        assert SETTING in message
    else:
        assert "must be an IP address" in message


@pytest.mark.parametrize("name", VECTORS["names"]["internal"])
def test_a_name_of_the_deployment_is_refused_without_a_lookup(name, no_lookups):
    with pytest.raises(TargetRefused, match="internal or deployment service name"):
        check_value(TargetKind.HOST, name, parse_allowlist(""))


@pytest.mark.parametrize("name", VECTORS["names"]["not_internal"])
def test_a_public_name_is_not_one_of_the_deployment(name):
    assert not tp.is_internal_name(name)


@pytest.mark.parametrize("case", VECTORS["allowlist"]["valid"], ids=lambda c: c["raw"])
def test_an_allowlist_of_ranges_is_parsed(case):
    allowlist = parse_allowlist(case["raw"])

    assert [str(network) for network in allowlist.networks] == case["networks"]
    assert allowlist.names == frozenset()


@pytest.mark.parametrize("raw", VECTORS["allowlist"]["invalid"])
def test_a_bad_allowlist_entry_names_this_services_setting(raw):
    with pytest.raises(ValueError, match=SETTING):
        parse_allowlist(raw)


@pytest.mark.parametrize("raw", VECTORS["allowlist"]["names"])
def test_this_service_scans_by_name_so_a_name_is_an_entry(raw):
    assert parse_allowlist(raw).names


# --- one implementation --------------------------------------------------------------


def test_the_policy_is_the_shared_one_and_not_a_copy():
    """A second classifier here would drift from guardian's."""
    assert tp.MAX_TARGET_ADDRESSES is shared.MAX_TARGET_ADDRESSES
    assert tp.Allowlist is shared.Allowlist
    assert tp._embedded_ipv4 is shared.embedded_ipv4
    assert tp.is_internal_name is shared.is_internal_name
    assert url_guard.parse_host is shared.parse_host
    assert url_guard.is_local_hostname is shared.is_local_hostname
    assert url_guard.ParsedTarget is shared.ParsedTarget
    assert InputSanitizer.BLOCKED_HOSTNAMES is shared.METADATA_HOSTNAMES
    for module in ("target_policy.py", "url_guard.py", "input_validation.py"):
        source = (REPO_ROOT / "open-security-tools" / "app" / module).read_text()
        for flag in ("is_private", "is_loopback", "is_link_local", "169.254.169.254"):
            assert flag not in source, f"{module} classifies an address itself"


def test_the_one_classifier_name_reaches_the_shared_decision(monkeypatch):
    """InputSanitizer._is_blocked_ip is the name the URL guard, app.safe_http
    and this policy classify through; it is the shared function, and a
    replacement of it (the fixture that lets a test reach a local server)
    reaches this policy too."""
    loopback = ipaddress.ip_address("127.0.0.1")
    assert InputSanitizer._is_blocked_ip(loopback) is True
    assert tp.is_internal_address(loopback) is True

    monkeypatch.setattr(
        InputSanitizer,
        "_is_blocked_ip",
        staticmethod(lambda addr: addr != loopback and shared.is_blocked_address(addr)),
    )

    assert tp.is_internal_address(loopback) is False
    check_value(TargetKind.HOST, "127.0.0.1", parse_allowlist(""))
    with pytest.raises(TargetRefused):
        check_value(TargetKind.HOST, "127.0.0.2", parse_allowlist(""))
