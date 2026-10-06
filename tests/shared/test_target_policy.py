"""The scan target policy both scanning services share (#614, #748).

``open_security_shared.target_policy`` decides which network targets a
service may connect to for a caller. The tools service had it; guardian's
asset discovery and port scans had none, and swept whatever network a team
admin named from a worker inside the stack's networks. The decision moved
here so that there is one.

``tests/shared/target_policy_vectors.json`` is run here against the module,
and by the tools service's and guardian's unit suites against their own
entry points. No test touches the network: name resolution is replaced.
"""

import ipaddress
import json
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from open_security_shared import target_policy as tp
from open_security_shared.target_policy import (
    MAX_TARGET_ADDRESSES,
    Allowlist,
    Reason,
    TargetPolicy,
    parse_allowlist,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads(
    (REPO_ROOT / "tests" / "shared" / "target_policy_vectors.json").read_text(
        encoding="utf-8"
    )
)
SETTING = "EXAMPLE_ALLOWED_INTERNAL_TARGETS"
PUBLIC_IP = "93.184.215.14"
PUBLIC_IP6 = "2001:4860:4860::8888"


def _policy(case):
    return TargetPolicy(parse_allowlist(case.get("allow", ""), SETTING))


def _id(case):
    key = case.get("address") if "network" not in case else case["network"]
    return f"{key}|{case.get('allow', '')}"


@pytest.fixture
def resolver(monkeypatch):
    """Resolve names from a table; unknown names resolve to PUBLIC_IP."""
    table = {}
    lookups = []

    def fake_getaddrinfo(host, *args, **kwargs):
        lookups.append(host)
        answers = table.get(host, [PUBLIC_IP])
        if answers is None:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [
            (
                socket.AF_INET6 if ":" in ip else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (ip, 0, 0, 0) if ":" in ip else (ip, 0),
            )
            for ip in answers
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return table, lookups


# --- the vectors ----------------------------------------------------------------


def test_there_are_vectors():
    """An empty file would pass every parametrized test below."""
    assert len(VECTORS["addresses"]) >= 60
    assert len(VECTORS["networks"]) >= 50
    assert {case["expect"] for case in VECTORS["addresses"]} == {"allowed", "internal"}
    assert {case["expect"] for case in VECTORS["networks"]} == {
        "allowed",
        "internal",
        "too_large",
        "invalid",
    }
    # Refused by default and allowed by a list, both ways round.
    assert any(case.get("allow") for case in VECTORS["addresses"])
    assert any(case.get("allow") for case in VECTORS["networks"])


@pytest.mark.parametrize("case", VECTORS["addresses"], ids=_id)
def test_an_address_is_allowed_or_internal(case):
    address = ipaddress.ip_address(case["address"])

    assert _policy(case).allows(address) is (case["expect"] == "allowed")
    # A range of that one address gets the same answer.
    refusal = _policy(case).refuse_network(ipaddress.ip_network(address))
    if case["expect"] == "allowed":
        assert refusal is None
    else:
        assert refusal.reason is Reason.INTERNAL_ADDRESS
        assert refusal.address == address


@pytest.mark.parametrize("case", VECTORS["addresses"], ids=_id)
def test_the_same_address_as_a_host(case, resolver):
    _, lookups = resolver

    addresses, refusal = _policy(case).check_host(case["address"])

    if case["expect"] == "allowed":
        assert refusal is None
        assert addresses == [ipaddress.ip_address(case["address"])]
    else:
        assert addresses == []
        assert refusal.reason is Reason.INTERNAL_ADDRESS
    assert lookups == [], "an address is never looked up"


@pytest.mark.parametrize("case", VECTORS["embedded"], ids=lambda c: c["address"])
def test_the_ipv4_address_inside_an_ipv6_one(case):
    found = tp.embedded_ipv4(ipaddress.ip_address(case["address"]))

    assert found == (ipaddress.ip_address(case["ipv4"]) if case["ipv4"] else None)


@pytest.mark.parametrize(
    "address", ["::ffff:10.0.0.1", "2002:a9fe:a9fe::1", "64:ff9b::7f00:1"]
)
def test_an_embedded_internal_address_is_refused_whatever_the_ipv6_prefix_is(address):
    """Python versions disagree on which of these prefixes are global."""

    def only_ipv4_is_classified(addr):
        return False if addr.version == 6 else tp.is_blocked_address(addr)

    policy = TargetPolicy(blocked=only_ipv4_is_classified)

    assert not policy.allows(ipaddress.ip_address(address))


@pytest.mark.parametrize("value", VECTORS["spellings"])
def test_another_spelling_of_an_address_is_not_a_host(value, resolver):
    _, lookups = resolver

    addresses, refusal = TargetPolicy().check_host(value)

    assert addresses == []
    assert refusal.reason is Reason.INVALID
    assert refusal.detail
    assert lookups == [], "inet_aton would have read it as an address"


@pytest.mark.parametrize("case", VECTORS["networks"], ids=_id)
def test_a_network_is_allowed_or_refused_whole(case):
    try:
        network = ipaddress.ip_network(case["network"], strict=False)
    except ValueError:
        assert case["expect"] == "invalid"
        return
    assert case["expect"] != "invalid"

    refusal = _policy(case).refuse_network(network)

    if case["expect"] == "allowed":
        assert refusal is None
    elif case["expect"] == "too_large":
        assert refusal.reason is Reason.TOO_LARGE
        assert refusal.count == network.num_addresses > MAX_TARGET_ADDRESSES
    else:
        assert refusal.reason is Reason.INTERNAL_ADDRESS
        assert refusal.address == ipaddress.ip_address(case["address"])


@pytest.mark.parametrize("name", VECTORS["names"]["internal"])
def test_a_name_of_the_deployment_is_refused_without_a_lookup(name, resolver):
    _, lookups = resolver

    assert tp.is_internal_name(name)
    addresses, refusal = TargetPolicy().check_host(name)

    assert addresses == []
    assert refusal.reason is Reason.INTERNAL_NAME
    assert refusal.host == name.lower().rstrip(".")
    assert lookups == []


@pytest.mark.parametrize("name", VECTORS["names"]["not_internal"])
def test_a_public_name_is_resolved_and_checked(name, resolver):
    _, lookups = resolver

    assert not tp.is_internal_name(name)
    addresses, refusal = TargetPolicy().check_host(name)

    assert refusal is None
    assert addresses == [ipaddress.ip_address(PUBLIC_IP)]
    assert lookups == [name]


@pytest.mark.parametrize("case", VECTORS["allowlist"]["valid"], ids=lambda c: c["raw"])
@pytest.mark.parametrize("names", [True, False])
def test_an_allowlist_of_ranges_is_parsed(case, names):
    allowlist = parse_allowlist(case["raw"], SETTING, names=names)

    assert [str(network) for network in allowlist.networks] == case["networks"]
    assert allowlist.names == frozenset()
    assert bool(allowlist) is bool(case["networks"])


@pytest.mark.parametrize("raw", VECTORS["allowlist"]["invalid"])
@pytest.mark.parametrize("names", [True, False])
def test_a_bad_allowlist_entry_is_an_error_that_names_the_setting(raw, names):
    with pytest.raises(ValueError, match=SETTING):
        parse_allowlist(raw, SETTING, names=names)


@pytest.mark.parametrize("raw", VECTORS["allowlist"]["names"])
def test_a_host_name_is_an_entry_only_where_names_are_scanned(raw):
    listed = parse_allowlist(raw, SETTING)

    assert listed.names
    assert all(name == name.lower().rstrip(".") for name in listed.names)
    with pytest.raises(ValueError, match=f"{SETTING}.*is a host name"):
        parse_allowlist(raw, SETTING, names=False)


# --- what the vectors cannot say ----------------------------------------------------


def test_nothing_is_allowed_by_default():
    policy = TargetPolicy()

    assert not policy.allowlist
    assert policy.allowlist == Allowlist()
    assert parse_allowlist(None, SETTING) == Allowlist()
    assert not policy.allows(ipaddress.ip_address("10.0.0.1"))


def test_the_limit_is_a_slash_22():
    assert MAX_TARGET_ADDRESSES == 1024
    assert ipaddress.ip_network("8.8.8.0/22").num_addresses == MAX_TARGET_ADDRESSES
    assert ipaddress.ip_network("2001:db8::/118").num_addresses == MAX_TARGET_ADDRESSES


def test_a_range_beyond_the_limit_is_refused_without_expanding_it():
    # Iterating ::/0 would never end; the answer has to come from its size.
    refusal = TargetPolicy().refuse_network(ipaddress.ip_network("::/0"))

    assert refusal.reason is Reason.TOO_LARGE
    assert refusal.count == 2**128


def test_every_address_of_a_range_is_checked():
    almost = parse_allowlist(
        "10.20.0.0/25,10.20.0.128/26,10.20.0.192/27,10.20.0.224/28,"
        "10.20.0.240/29,10.20.0.248/30,10.20.0.252/31,10.20.0.254",
        SETTING,
    )

    refusal = TargetPolicy(almost).refuse_network(ipaddress.ip_network("10.20.0.0/24"))

    # 255 of its 256 addresses are listed.
    assert refusal.reason is Reason.INTERNAL_ADDRESS
    assert refusal.address == ipaddress.ip_address("10.20.0.255")


@pytest.mark.parametrize(
    "answers",
    [
        ["10.0.0.5"],
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["::1"],
        ["fd12:3456::1"],
        [PUBLIC_IP, "10.0.0.5"],  # one internal answer is enough
        ["10.0.0.5", PUBLIC_IP],
        None,  # does not resolve
        [],
        ["not-an-address"],
    ],
)
def test_a_name_that_resolves_inside_or_not_at_all_gets_one_answer(resolver, answers):
    table, lookups = resolver
    table["scan.example.com"] = answers

    addresses, refusal = TargetPolicy().check_host("scan.example.com")

    assert addresses == []
    # One reason for all of them: two would tell which internal names exist.
    assert refusal == tp.Refusal(Reason.UNRESOLVABLE, host="scan.example.com")
    assert lookups == ["scan.example.com"]


def test_a_public_name_gets_every_address_it_resolves_to(resolver):
    table, _ = resolver
    table["scan.example.com"] = [PUBLIC_IP, PUBLIC_IP6, "fe80::1%eth0"]
    allowed = parse_allowlist("fe80::/10", SETTING)

    addresses, refusal = TargetPolicy(allowed).check_host("SCAN.example.com.")

    assert refusal is None
    # The zone of a link-local answer is dropped: the address is what is checked.
    assert addresses == [
        ipaddress.ip_address(PUBLIC_IP),
        ipaddress.ip_address(PUBLIC_IP6),
        ipaddress.ip_address("fe80::1"),
    ]


def test_a_listed_name_is_allowed_whatever_it_resolves_to_and_covers_only_itself(
    resolver,
):
    table, _ = resolver
    table["lab-dc01"] = ["10.99.0.1"]
    table["x.scanme.lab.example"] = ["192.168.0.2"]
    table["gone.lab.example"] = None
    policy = TargetPolicy(
        parse_allowlist("lab-dc01,scanme.lab.example,gone.lab.example", SETTING)
    )

    assert policy.check_host("lab-dc01") == ([ipaddress.ip_address("10.99.0.1")], None)
    assert policy.check_host("lab-dc02")[1].reason is Reason.INTERNAL_NAME
    assert policy.check_host("x.scanme.lab.example")[1].reason is Reason.UNRESOLVABLE
    # Listed, and still nothing to dial.
    assert policy.check_host("gone.lab.example")[1].reason is Reason.UNRESOLVABLE


@pytest.mark.parametrize(
    "value",
    [
        " example.com",
        "example.com ",
        "exa mple.com",
        "example.com\n",
        "example.com:443",
        "[::1]",
        "fe80::1%eth0",
        "user@example.com",
        "exämple.com",
        "-bad.example.com",
        "a" * 64 + ".example.com",
        "",
        None,
        7,
    ],
)
def test_a_value_that_is_not_a_bare_host_is_refused(resolver, value):
    _, lookups = resolver

    addresses, refusal = TargetPolicy().check_host(value)

    assert addresses == []
    assert refusal.reason is Reason.INVALID
    assert lookups == []


def test_the_module_needs_the_standard_library_only():
    """guardian is Django and installs the package with no extra (#722).

    Loaded by path, with no package around it, in an interpreter that refuses
    to import anything outside the standard library.
    """
    module = REPO_ROOT / "open-security-shared" / "target_policy.py"
    script = textwrap.dedent(f"""
        import importlib.abc, importlib.util, sys

        class StandardLibraryOnly(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path, target=None):
                if name.split(".")[0] not in sys.stdlib_module_names:
                    raise ImportError(f"not in the standard library: {{name}}")
                return None

        sys.meta_path.insert(0, StandardLibraryOnly())
        spec = importlib.util.spec_from_file_location("policy", {str(module)!r})
        policy = importlib.util.module_from_spec(spec)
        sys.modules["policy"] = policy
        spec.loader.exec_module(policy)
        import ipaddress
        print(policy.TargetPolicy().allows(ipaddress.ip_address("10.0.0.1")))
        """)

    out = subprocess.run(
        [sys.executable, "-S", "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )

    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "False"
