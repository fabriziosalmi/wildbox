"""The network target policy for host, IP and CIDR inputs (#614).

Network tools take a host, an address, a range, a DNS server or an image
reference, and the URL guard does not see those. ``app.target_policy``
refuses internal targets unless the operator allows them with
``TOOLS_ALLOWED_INTERNAL_TARGETS``, before any tool runs, on the
synchronous endpoint, in the Celery task and in each orchestrator step.

No test touches the network: name resolution is replaced with a fake, and
the tools behind the endpoint, the task and the workflow are stubs that
record their calls.
"""

import asyncio
import ipaddress
import os
import pkgutil
import re
import socket
import sys
import types
import typing
import uuid
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import app.tools  # noqa: E402
from app import target_policy as tp  # noqa: E402
from app.input_validation import InputSanitizer  # noqa: E402
from app.standardized_schemas import BaseToolInput  # noqa: E402
from app.target_policy import (  # noqa: E402
    MAX_TARGET_ADDRESSES,
    NETWORK_TARGET_FIELDS,
    REVIEWED_NON_TARGET_FIELDS,
    Allowlist,
    TargetKind,
    TargetRefused,
    check_network_targets,
    check_value,
    enforce_target_policy,
    parse_allowlist,
)
from app.tool_loader import find_schema_classes, load_tool_module  # noqa: E402

PUBLIC_IP = "93.184.215.14"
PUBLIC_IP6 = "2001:4860:4860::8888"
NO_ALLOWLIST = Allowlist()
REPO_ROOT = Path(__file__).resolve().parents[3]
TOOLS_DIR = Path(app.tools.__file__).parent


@pytest.fixture
def resolver(monkeypatch):
    """Resolve names from a table; unknown names resolve to PUBLIC_IP.

    A table value of None makes the name unresolvable. Every lookup is
    recorded.
    """
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


@pytest.fixture
def allow(monkeypatch):
    """Set the configured allowlist as the service would read it."""
    from app.config import settings

    def set_allowlist(raw):
        monkeypatch.setattr(settings, "tools_allowed_internal_targets", raw)

    set_allowlist("")
    return set_allowlist


def _host(value, allowlist=NO_ALLOWLIST):
    check_value(TargetKind.HOST, value, allowlist)


# --- the registry of target fields --------------------------------------------


def _tool_names():
    return sorted(
        info.name
        for info in pkgutil.iter_modules([str(TOOLS_DIR)])
        if info.ispkg and info.name != "wordlists"
    )


def _input_class(tool):
    module = load_tool_module(tool)
    assert module is not None, tool
    input_cls, _ = find_schema_classes(getattr(module, "schemas", None))
    assert input_cls is not None, tool
    return input_cls


# Field names that may hold a host, an address, a range, a server or an
# image a tool could connect to.
HOST_LIKE = re.compile(
    r"(host|^ip|_ip|ip_|target|network|server|domain|registry|image|range|"
    r"address|cidr|subnet|connection|dns|^ns)",
    re.IGNORECASE,
)


def _tool_source(tool):
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in (TOOLS_DIR / tool).glob("*.py")
        if path.name != "schemas.py"
    )


def test_every_registered_tool_and_field_exists():
    tools = set(_tool_names())
    for tool, fields in NETWORK_TARGET_FIELDS.items():
        assert tool in tools, f"{tool} is registered but is not a tool"
        model_fields = _input_class(tool).model_fields
        for field, kind in fields.items():
            assert (
                field in model_fields
            ), f"{tool}.{field} is registered but not an input field"
            assert isinstance(kind, TargetKind)


def _suggested_values(field_info):
    """What the schema itself offers for a field: its examples and its default."""
    extra = field_info.json_schema_extra
    values = list(field_info.examples or [])
    if isinstance(extra, dict) and "example" in extra:
        values.append(extra["example"])
    if not field_info.is_required() and field_info.default is not None:
        values.append(field_info.default)
    # A list field (dns_enumerator's dns_servers) suggests each of its items.
    return [
        item
        for value in values
        for item in (value if isinstance(value, list) else [value])
    ]


def test_the_values_a_schema_suggests_pass_the_default_policy(resolver):
    # The dashboard shows a field's example as the input's placeholder.
    # network_scanner suggested 192.168.1.0/24 and port_scanner 127.0.0.1,
    # which the service refuses unless the operator allows them (#646).
    refused = {}
    suggested = 0
    for tool, fields in NETWORK_TARGET_FIELDS.items():
        model_fields = _input_class(tool).model_fields
        for field, kind in fields.items():
            for value in _suggested_values(model_fields[field]):
                suggested += 1
                try:
                    check_value(kind, value, NO_ALLOWLIST)
                except TargetRefused as error:
                    refused[f"{tool}.{field}={value!r}"] = str(error)

    assert refused == {}
    # network_scanner, port_scanner and ssl_analyzer give an example, and
    # dns_enumerator two default servers.
    assert suggested >= 5


def test_every_reviewed_field_exists():
    for (tool, field), reason in REVIEWED_NON_TARGET_FIELDS.items():
        assert reason.strip()
        assert field in _input_class(tool).model_fields, f"{tool}.{field}"
        assert field not in NETWORK_TARGET_FIELDS.get(tool, {}), f"{tool}.{field}"


def _can_hold_text(annotation):
    """True if a value of this type can be a string (str, Optional[str], ...)."""
    if annotation is str:
        return True
    return any(_can_hold_text(arg) for arg in typing.get_args(annotation))


def _unclassified_host_fields():
    missing = []
    for tool in _tool_names():
        input_cls = _input_class(tool)
        registered = NETWORK_TARGET_FIELDS.get(tool, {})
        source = _tool_source(tool)
        for name, field in input_cls.model_fields.items():
            if not HOST_LIKE.search(name) or not _can_hold_text(field.annotation):
                continue
            if name in registered or (tool, name) in REVIEWED_NON_TARGET_FIELDS:
                continue
            if InputSanitizer.is_url_field_name(name):
                continue  # a URL: the URL guard checks it
            inherited = (
                name in BaseToolInput.model_fields
                and field.annotation == BaseToolInput.model_fields[name].annotation
            )
            if inherited and not re.search(rf"\.{name}\b", source):
                continue  # the shared optional field, which this tool never reads
            missing.append(f"{tool}.{name}")
    return missing


def test_every_host_like_input_field_is_classified():
    """A new network tool or field fails here until it is classified.

    Register it in NETWORK_TARGET_FIELDS with its kind, or list it in
    REVIEWED_NON_TARGET_FIELDS with the reason it is not a target.
    """
    assert _unclassified_host_fields() == []


def test_the_classification_check_catches_a_new_field(monkeypatch):
    monkeypatch.setitem(NETWORK_TARGET_FIELDS, "ssl_analyzer", {})
    assert "ssl_analyzer.target" in _unclassified_host_fields()


def test_the_audited_network_tools_are_registered():
    """The tools the #610 audit named, with the fields they connect to."""
    expected = {
        ("ca_analyzer", "target"),
        ("ssl_analyzer", "target"),
        ("pki_certificate_manager", "domain"),
        ("network_port_scanner", "target"),
        ("port_scanner", "target"),
        ("network_vulnerability_scanner", "target"),
        ("iot_security_scanner", "target_ip"),
        ("iot_security_scanner", "ip_range"),
        ("network_scanner", "network"),
        ("database_security_analyzer", "host"),
        ("dns_enumerator", "dns_servers"),
        ("container_security_scanner", "image_name"),
    }
    registered = {(t, f) for t, fields in NETWORK_TARGET_FIELDS.items() for f in fields}
    assert expected <= registered


def test_no_tool_reads_the_shared_proxy_field():
    """BaseToolInput.proxy is not a URL guard field target if nobody uses it."""
    for tool in _tool_names():
        assert not re.search(r"\.proxy\b", _tool_source(tool)), tool


# --- addresses ------------------------------------------------------------------


REFUSED_ADDRESSES = [
    "127.0.0.1",
    "127.255.0.9",
    "10.0.0.1",
    "172.16.5.4",
    "192.168.1.1",
    "169.254.169.254",
    "169.254.0.1",
    "0.0.0.0",
    "100.64.0.1",
    "100.127.255.254",
    "224.0.0.1",
    "239.255.255.250",
    "240.0.0.1",
    "255.255.255.255",
    "192.0.2.10",
    "198.18.0.1",
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "fd00::c2b6:a9ff:fe52:2ea5",
    "ff02::1",
    "2001:db8::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "2002:7f00:1::1",  # 6to4 of 127.0.0.1
    "64:ff9b::a9fe:a9fe",  # NAT64 of 169.254.169.254
]


@pytest.mark.parametrize("address", REFUSED_ADDRESSES)
def test_an_internal_address_is_refused(resolver, address):
    _, lookups = resolver
    with pytest.raises(TargetRefused, match="TOOLS_ALLOWED_INTERNAL_TARGETS"):
        _host(address)
    assert lookups == []


@pytest.mark.parametrize(
    "address", [PUBLIC_IP, "8.8.8.8", PUBLIC_IP6, "2a00:1450:4001:80b::200e"]
)
def test_a_public_address_is_accepted(resolver, address):
    _, lookups = resolver
    _host(address)
    assert lookups == []


@pytest.mark.parametrize(
    "address,embedded",
    [
        ("::ffff:10.0.0.1", "10.0.0.1"),
        ("2002:a9fe:a9fe::1", "169.254.169.254"),
        ("64:ff9b::7f00:1", "127.0.0.1"),
        (PUBLIC_IP6, None),
        ("10.0.0.1", None),
    ],
)
def test_the_ipv4_address_inside_an_ipv6_one(address, embedded):
    found = tp._embedded_ipv4(ipaddress.ip_address(address))
    assert found == (ipaddress.ip_address(embedded) if embedded else None)


@pytest.mark.parametrize(
    "address", ["::ffff:10.0.0.1", "2002:a9fe:a9fe::1", "64:ff9b::7f00:1"]
)
def test_an_embedded_internal_address_is_refused_even_if_the_ipv6_one_looks_public(
    monkeypatch, address
):
    """Python versions disagree on which of these prefixes are global."""
    real = InputSanitizer._is_blocked_ip
    monkeypatch.setattr(
        InputSanitizer,
        "_is_blocked_ip",
        staticmethod(lambda addr: False if addr.version == 6 else real(addr)),
    )
    with pytest.raises(TargetRefused):
        _host(address)


@pytest.mark.parametrize(
    "value",
    ["127.1", "0x7f000001", "2130706433", "017700000001", "0177.0.0.1", "127.0.0.01"],
)
def test_other_spellings_of_an_address_are_refused(resolver, value):
    _, lookups = resolver
    with pytest.raises(TargetRefused):
        _host(value)
    assert lookups == []


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
    ],
)
def test_a_value_that_is_not_a_bare_host_is_refused(resolver, value):
    _, lookups = resolver
    with pytest.raises(TargetRefused):
        _host(value)
    assert lookups == []


# --- names ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "localhost",
        "LOCALHOST.",
        "foo.localhost",
        "wildbox-redis",
        "postgres",
        "gateway",
        "open-security-tools",
        "printer.local",
        "host.docker.internal",
        "metadata.google.internal",
        "nas.localdomain",
        "router.home.arpa",
        "instance-data",
    ],
)
def test_internal_and_service_names_are_refused_without_a_lookup(resolver, name):
    _, lookups = resolver
    with pytest.raises(TargetRefused, match="internal or deployment service name"):
        _host(name)
    assert lookups == []


def _compose_names():
    import yaml

    class Loader(yaml.SafeLoader):
        """Reads the compose merge tags (!override, !reset) as plain values."""

    def plain(loader, suffix, node):
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_scalar(node)

    Loader.add_multi_constructor("!", plain)

    names = set()
    for path in sorted(REPO_ROOT.glob("docker-compose*.yml")):
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=Loader) or {}
        for service, spec in (document.get("services") or {}).items():
            names.add(service)
            spec = spec or {}
            if spec.get("container_name"):
                names.add(spec["container_name"])
            networks = spec.get("networks")
            if isinstance(networks, dict):
                for net in networks.values():
                    for alias in (net or {}).get("aliases", []) or []:
                        names.add(alias)
    return sorted(names)


def test_every_deployment_service_name_is_refused(resolver):
    names = _compose_names()
    if not names:
        pytest.skip("the compose files are not in this checkout")
    assert "wildbox-redis" in names
    for name in names:
        with pytest.raises(TargetRefused):
            _host(name)


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
    ],
)
def test_a_name_resolving_to_an_internal_address_is_refused(resolver, answers):
    table, lookups = resolver
    table["scan.example.com"] = answers
    with pytest.raises(
        TargetRefused, match="does not resolve, or resolves to an internal"
    ):
        _host("scan.example.com")
    assert lookups == ["scan.example.com"]


def test_the_refusal_does_not_say_which_internal_address(resolver):
    table, _ = resolver
    table["scan.example.com"] = ["10.9.8.7"]
    with pytest.raises(TargetRefused) as info:
        _host("scan.example.com")
    assert "10.9.8.7" not in str(info.value)


def test_a_name_that_does_not_resolve_is_refused(resolver):
    table, _ = resolver
    table["nowhere.example.com"] = None
    with pytest.raises(TargetRefused):
        _host("nowhere.example.com")


def test_a_public_name_is_accepted_and_resolved_once(resolver):
    table, lookups = resolver
    table["scan.example.com"] = [PUBLIC_IP, PUBLIC_IP6]
    assert tp.check_host("scan.example.com", NO_ALLOWLIST) == [
        ipaddress.ip_address(PUBLIC_IP),
        ipaddress.ip_address(PUBLIC_IP6),
    ]
    assert lookups == ["scan.example.com"]


def test_a_trailing_dot_is_the_same_name(resolver):
    table, lookups = resolver
    table["scan.example.com"] = ["10.0.0.5"]
    with pytest.raises(TargetRefused):
        _host("scan.example.com.")
    assert lookups == ["scan.example.com"]


# --- ranges ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.0/24",
        "192.168.1.0/30",
        "127.0.0.1",
        "127.0.0.1/32",
        "169.254.169.0/24",
        "100.64.0.0/22",
        "192.0.0.0/22",  # a public /22 with IETF and TEST-NET blocks inside
        "fe80::/120",
        "::1/128",
        "224.0.0.0/30",
    ],
)
def test_a_range_with_an_internal_address_is_refused(value):
    with pytest.raises(TargetRefused, match="internal"):
        check_value(TargetKind.IP_OR_CIDR, value, NO_ALLOWLIST)


def test_the_refusal_keeps_the_first_internal_address_of_a_range_as_data():
    """For the code that catches it. The text has neither the range nor the
    address: it named both until #774."""
    with pytest.raises(TargetRefused, match="range includes a private") as refused:
        check_value(TargetKind.IP_OR_CIDR, "192.0.0.0/22", NO_ALLOWLIST)

    assert refused.value.address == ipaddress.ip_address("192.0.0.0")
    assert "192.0" not in str(refused.value)


@pytest.mark.parametrize(
    "value", ["8.8.8.0/24", "8.8.8.8", "8.8.8.0/22", "2001:4860::/118"]
)
def test_a_public_range_within_the_limit_is_accepted(value):
    check_value(TargetKind.IP_OR_CIDR, value, NO_ALLOWLIST)


@pytest.mark.parametrize(
    "value",
    [
        "8.8.0.0/21",
        "8.0.0.0/8",
        "0.0.0.0/0",
        "2001:4860::/117",
        "2001:4860::/64",
        "::/0",
    ],
)
def test_a_range_beyond_the_limit_is_refused_without_expanding_it(value):
    with pytest.raises(TargetRefused, match=f"at most {MAX_TARGET_ADDRESSES}"):
        check_value(TargetKind.IP_OR_CIDR, value, NO_ALLOWLIST)


def test_the_limit_is_a_slash_22():
    assert MAX_TARGET_ADDRESSES == 1024
    assert ipaddress.ip_network("8.8.8.0/22").num_addresses == MAX_TARGET_ADDRESSES


def test_the_limit_covers_what_network_scanner_sweeps():
    # The comment on MAX_TARGET_ADDRESSES promises that no range a tool would
    # scan is lost to the policy, and used to give network_scanner's limit as
    # 1000 hosts. It is 1024, the same /22 (#646).
    from app.tools.network_scanner import main as network_scanner
    from app.tools.network_scanner import secure_scan

    assert network_scanner.MAX_HOSTS == 1024
    assert network_scanner.MAX_HOSTS <= MAX_TARGET_ADDRESSES
    assert secure_scan.MAX_HOSTS_TO_SCAN <= MAX_TARGET_ADDRESSES


@pytest.mark.parametrize(
    "value", ["example.com", "10.0.0.0/33", "10.0.0.0/24 ", "1.2.3"]
)
def test_a_range_field_takes_addresses_only(value):
    with pytest.raises(TargetRefused):
        check_value(TargetKind.IP_OR_CIDR, value, NO_ALLOWLIST)


@pytest.mark.parametrize(
    "value,refused",
    [
        ("8.8.8.1-20", False),
        ("8.8.8.0/24", False),
        ("8.8.8.8", False),
        ("192.168.1.1-10", True),
        ("10.0.0.0/24", True),
        ("127.0.0.1", True),
        ("8.8.8.250-255", False),
        ("8.8.8.5-1", True),  # end before start
        ("8.8.8.1-256", True),
        ("8.8.1-20", True),
        ("8.8.8.x-2", True),
        ("example.com", True),
        ("8.8.0.0/16", True),  # beyond the limit
    ],
)
def test_network_scanner_syntax(value, refused):
    if refused:
        with pytest.raises(TargetRefused):
            check_value(TargetKind.NETWORK, value, NO_ALLOWLIST)
    else:
        check_value(TargetKind.NETWORK, value, NO_ALLOWLIST)


# --- per-kind parsing -------------------------------------------------------------


@pytest.mark.parametrize(
    "value,host",
    [
        ("example.com", "example.com"),
        ("example.com:8443", "example.com"),
        ("https://example.com/path", "example.com"),
        ("https://example.com:8443/path?x=1", "example.com"),
        ("ssl://127.0.0.1:443", "127.0.0.1"),
    ],
)
def test_pki_domain_host_is_taken_as_the_tool_takes_it(value, host):
    assert tp.host_of_host_port_or_url(value) == host


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "127.0.0.1:443",
        "https://169.254.169.254/latest",
        "localhost:8443",
        "https://wildbox-redis:6379/",
        "user@127.0.0.1",
        "https://user@example.com/",
    ],
)
def test_pki_domain_aimed_inside_is_refused(resolver, value):
    with pytest.raises(TargetRefused):
        check_value(TargetKind.HOST_PORT_OR_URL, value, NO_ALLOWLIST)


@pytest.mark.parametrize(
    "value,registry",
    [
        ("alpine", None),
        ("alpine:3.19", None),
        ("library/alpine:3.19", None),
        ("bitnami/redis@sha256:abc", None),
        ("ghcr.io/org/image:1", "ghcr.io"),
        ("registry.example.com:5000/team/app", "registry.example.com"),
        ("localhost/app", "localhost"),
        ("localhost:5000/app", "localhost"),
        ("wildbox-redis:6379/x", "wildbox-redis"),
        ("10.0.0.5:5000/app", "10.0.0.5"),
    ],
)
def test_the_registry_of_an_image_reference(value, registry):
    assert tp.registry_of_image(value) == registry


@pytest.mark.parametrize(
    "value",
    [
        "localhost:5000/app",
        "wildbox-redis:6379/x",
        "10.0.0.5:5000/app",
        "127.0.0.1/app",
    ],
)
def test_an_image_from_an_internal_registry_is_refused(resolver, value):
    with pytest.raises(TargetRefused):
        check_value(TargetKind.IMAGE_REF, value, NO_ALLOWLIST)


@pytest.mark.parametrize(
    "kind,value",
    [
        (TargetKind.IMAGE_REF, "alpine:3.19 --insecure"),
        (TargetKind.IMAGE_REF, "alpine\t"),
        (TargetKind.HOST, " example.com"),
        (TargetKind.IP, "8.8.8.8\n"),
        (TargetKind.NETWORK, "8.8.8.0/24 "),
        (TargetKind.IP_OR_CIDR, "\x008.8.8.0/24"),
    ],
)
def test_whitespace_and_control_characters_are_refused_in_every_kind(
    resolver, kind, value
):
    with pytest.raises(TargetRefused, match="whitespace or control"):
        check_value(kind, value, NO_ALLOWLIST)


@pytest.mark.parametrize(
    "value", ["alpine:3.19", "library/alpine", "ghcr.io/org/image:1"]
)
def test_an_image_from_a_public_registry_is_accepted(resolver, value):
    check_value(TargetKind.IMAGE_REF, value, NO_ALLOWLIST)


@pytest.mark.parametrize(
    "value", ["dns.google", "10.0.0.53", "127.0.0.11", "08.8.8.8", " 8.8.8.8"]
)
def test_a_dns_server_must_be_a_public_address(resolver, value):
    with pytest.raises(TargetRefused):
        check_value(TargetKind.IP, value, NO_ALLOWLIST)


@pytest.mark.parametrize("value", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_a_public_dns_server_is_accepted(value):
    check_value(TargetKind.IP, value, NO_ALLOWLIST)


# --- the allowlist ---------------------------------------------------------------


def test_the_allowlist_is_parsed():
    allowlist = parse_allowlist(
        " 10.20.0.0/16, 192.168.50.7 ,lab-dc01, scanme.lab.example.,fd00:1::/64,"
    )
    assert allowlist.networks == (
        ipaddress.ip_network("10.20.0.0/16"),
        ipaddress.ip_network("192.168.50.7/32"),
        ipaddress.ip_network("fd00:1::/64"),
    )
    assert allowlist.names == {"lab-dc01", "scanme.lab.example"}


@pytest.mark.parametrize("raw", ["", " ", ",", None])
def test_an_empty_allowlist_allows_nothing(raw):
    assert not parse_allowlist(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "10.0.0.1/8",  # host bits set: a typo, not a range
        "10.0.0.0/33",
        "10.0.0.300",
        "fd00::/129",
        "lab dc01",
        "exämple.lab",
        "http://10.0.0.0/8",
        "10.0.0.0/8;rm",
        "127.1",
    ],
)
def test_a_bad_allowlist_entry_is_an_error_that_names_it(raw):
    with pytest.raises(ValueError, match="TOOLS_ALLOWED_INTERNAL_TARGETS"):
        parse_allowlist(raw)


def test_a_bad_allowlist_stops_the_service_at_start_up(monkeypatch):
    from app.config import Settings
    from pydantic import ValidationError

    monkeypatch.setenv("TOOLS_ALLOWED_INTERNAL_TARGETS", "10.0.0.0/8,not a host")
    with pytest.raises(ValidationError, match="not a host"):
        Settings()


def test_the_allowlist_is_read_from_the_environment(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("TOOLS_ALLOWED_INTERNAL_TARGETS", "10.20.0.0/16,lab-dc01")
    assert Settings().tools_allowed_internal_targets == "10.20.0.0/16,lab-dc01"
    monkeypatch.delenv("TOOLS_ALLOWED_INTERNAL_TARGETS")
    assert Settings().tools_allowed_internal_targets == ""


LAB = parse_allowlist("10.20.0.0/16,fd00:1::/64,lab-dc01,scanme.lab.example")


@pytest.mark.parametrize(
    "value", ["10.20.3.4", "fd00:1::10", "lab-dc01", "scanme.lab.example"]
)
def test_an_allow_listed_target_is_accepted(resolver, value):
    table, _ = resolver
    table["lab-dc01"] = ["10.99.0.1"]  # allowed by name, whatever it resolves to
    table["scanme.lab.example"] = ["192.168.0.1"]
    _host(value, LAB)


@pytest.mark.parametrize(
    "value",
    [
        "10.21.0.1",
        "127.0.0.1",
        "fd00:2::1",
        "wildbox-redis",
        "lab-dc02",
        "x.scanme.lab.example",
    ],
)
def test_a_target_outside_the_allowlist_is_still_refused(resolver, value):
    table, _ = resolver
    # A listed name covers itself, not the names under it.
    table["x.scanme.lab.example"] = ["192.168.0.2"]
    with pytest.raises(TargetRefused):
        _host(value, LAB)


def test_a_name_resolving_inside_the_allowlist_is_accepted(resolver):
    table, _ = resolver
    table["db.lab.example"] = ["10.20.0.5", PUBLIC_IP]
    _host("db.lab.example", LAB)


def test_a_name_resolving_partly_outside_the_allowlist_is_refused(resolver):
    table, _ = resolver
    table["db.lab.example"] = ["10.20.0.5", "10.21.0.5"]
    with pytest.raises(TargetRefused):
        _host("db.lab.example", LAB)


@pytest.mark.parametrize(
    "value,allowed",
    [
        ("10.20.0.0/22", True),
        ("10.20.255.0/24", True),
        # 10.19.254.0-10.19.255.255: it ends where the allowed /16 begins and
        # has no address in it. (No range within the limit can lie half in a
        # /16: the next test has a list that a range does straddle.)
        ("10.19.255.0/23", False),
        ("10.20.0.1-200", True),
    ],
)
def test_a_range_must_be_covered_by_the_allowlist(value, allowed):
    kind = TargetKind.NETWORK
    if allowed:
        check_value(kind, value, LAB)
    else:
        with pytest.raises(TargetRefused) as refused:
            check_value(kind, value, LAB)
        assert refused.value.address == ipaddress.ip_address("10.19.254.0")


def test_every_address_of_a_range_is_checked():
    narrow = parse_allowlist("10.20.0.0/24")
    # The first address is allowed, the second half of the range is not.
    with pytest.raises(TargetRefused) as refused:
        check_value(TargetKind.IP_OR_CIDR, "10.20.0.0/23", narrow)
    assert refused.value.address == ipaddress.ip_address("10.20.1.0")
    # The last address of a short range is the only one outside.
    almost = parse_allowlist(
        "10.20.0.0/25,10.20.0.128/26,10.20.0.192/27,10.20.0.224/28"
    )
    check_value(TargetKind.NETWORK, "10.20.0.230-239", almost)
    with pytest.raises(TargetRefused) as refused:
        check_value(TargetKind.NETWORK, "10.20.0.230-240", almost)
    assert refused.value.address == ipaddress.ip_address("10.20.0.240")


def test_the_allowlist_does_not_lift_the_range_limit():
    with pytest.raises(TargetRefused, match="at most"):
        check_value(TargetKind.IP_OR_CIDR, "10.20.0.0/16", LAB)


def test_the_configured_allowlist_is_used(resolver, allow):
    from app.tools.port_scanner.schemas import PortScannerInput

    allow("")
    with pytest.raises(TargetRefused):
        check_network_targets("port_scanner", PortScannerInput(target="10.20.3.4"))
    allow("10.20.0.0/16")
    check_network_targets("port_scanner", PortScannerInput(target="10.20.3.4"))


# --- every tool family, through its real input model ------------------------------


def _model(tool, **fields):
    return _input_class(tool)(**fields)


FAMILIES = [
    # (tool, fields for an internal target, fields for a public one)
    ("ssl_analyzer", {"target": "127.0.0.1"}, {"target": "example.com"}),
    ("ca_analyzer", {"target": "::1"}, {"target": PUBLIC_IP}),
    (
        "pki_certificate_manager",
        {"domain": "localhost:443"},
        {"domain": "https://example.com/"},
    ),
    ("port_scanner", {"target": "wildbox-redis"}, {"target": "example.com"}),
    ("network_port_scanner", {"target": "10.0.0.5"}, {"target": PUBLIC_IP}),
    (
        "network_vulnerability_scanner",
        {"target": "169.254.169.254"},
        {"target": "example.com"},
    ),
    ("iot_security_scanner", {"target_ip": "192.168.1.20"}, {"target_ip": PUBLIC_IP}),
    (
        "iot_security_scanner",
        {"ip_range": "192.168.1.0/24"},
        {"ip_range": "8.8.8.0/24"},
    ),
    ("network_scanner", {"network": "172.16.0.0/24"}, {"network": "8.8.8.0/28"}),
    ("network_scanner", {"network": "10.0.0.1-5"}, {"network": "8.8.8.1-5"}),
    (
        "database_security_analyzer",
        {
            "host": "wildbox-postgres",
            "database_type": "postgresql",
            "port": 5432,
            "username": "u",
        },
        {
            "host": "db.example.com",
            "database_type": "postgresql",
            "port": 5432,
            "username": "u",
        },
    ),
    (
        "dns_enumerator",
        {"target_domain": "example.com", "dns_servers": ["8.8.8.8", "127.0.0.11"]},
        {"target_domain": "example.com", "dns_servers": ["8.8.8.8", "1.1.1.1"]},
    ),
    (
        "container_security_scanner",
        {"image_name": "localhost:5000/app"},
        {"image_name": "alpine:3.19"},
    ),
]


@pytest.mark.parametrize("tool,internal,public", FAMILIES)
def test_each_tool_family_refuses_internal_and_accepts_public(
    resolver, allow, tool, internal, public
):
    with pytest.raises(TargetRefused):
        enforce_target_policy(tool, _model(tool, **internal))
    enforce_target_policy(tool, _model(tool, **public))


def test_the_default_dns_servers_are_accepted(resolver):
    enforce_target_policy(
        "dns_enumerator", _model("dns_enumerator", target_domain="example.com")
    )


def test_the_url_guard_runs_in_the_same_check(resolver):
    from app.tools.header_analyzer.schemas import HeaderAnalyzerInput

    with pytest.raises(TargetRefused, match="SSRF"):
        enforce_target_policy(
            "header_analyzer", HeaderAnalyzerInput(url="http://10.0.0.1/")
        )


def test_a_tool_without_target_fields_is_not_checked(resolver):
    _, lookups = resolver
    enforce_target_policy("hash_generator", _model("hash_generator", input_text="x"))
    assert lookups == []


# --- the three paths that run a tool ------------------------------------------------


@pytest.fixture
def port_scanner_stub():
    """port_scanner's real input model, with an execute_tool that records."""
    from app.tools.port_scanner import schemas

    calls = []

    def execute_tool(input_data):
        calls.append(input_data)
        return schemas.PortScannerOutput(success=True, target=input_data.target)

    module = types.ModuleType("port_scanner")
    module.schemas = schemas
    module.execute_tool = execute_tool
    return module, calls


@pytest.fixture
def client(monkeypatch, port_scanner_stub):
    from app.api import router as router_module
    from app.auth import verify_api_key
    from app.execution_manager import ToolExecutionManager
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    module, _ = port_scanner_stub
    monkeypatch.setattr(router_module, "execution_manager", ToolExecutionManager())
    routes = list(router_module.router.routes)
    # The real port_scanner endpoint is registered when another test builds
    # the whole app (create_app), and the first matching route wins: drop it
    # so the stub answers and nothing is scanned.
    router_module.router.routes[:] = [
        route
        for route in routes
        if getattr(route, "path", "") != "/api/tools/port_scanner"
    ]
    router_module.register_tool_endpoint(None, "port_scanner", module)
    path = router_module.router.routes[-1].path
    application = FastAPI()
    application.include_router(router_module.router)
    application.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=str(uuid.uuid4()), team_id=str(uuid.uuid4()), role="member", auth_type="session"
    )
    yield TestClient(application), path
    router_module.router.routes[:] = routes


@pytest.mark.parametrize(
    "target", ["127.0.0.1", "wildbox-redis", "10.0.0.5", "internal.example.com"]
)
def test_the_sync_endpoint_refuses_before_the_tool_runs(
    resolver, allow, client, port_scanner_stub, target
):
    table, _ = resolver
    table["internal.example.com"] = ["10.1.1.1"]
    http, path = client
    _, calls = port_scanner_stub

    response = http.post(path, json={"target": target, "ports": [6379]})

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "network target policy" in detail["reason"]
    # The field that held the target, where a 422 names its fields; the
    # target itself is nowhere in the answer (#774).
    (error,) = detail["errors"]
    assert error["loc"] == ["target"]
    assert error["msg"] == detail["reason"]
    assert error["type"] == "target_internal"
    assert target not in response.text
    assert calls == []


def test_the_sync_endpoint_runs_the_tool_for_an_allowed_target(
    resolver, allow, client, port_scanner_stub
):
    http, path = client
    _, calls = port_scanner_stub

    assert http.post(path, json={"target": "example.com"}).status_code == 200
    allow("10.20.0.0/16")
    assert http.post(path, json={"target": "10.20.0.9"}).status_code == 200
    assert [c.target for c in calls] == ["example.com", "10.20.0.9"]


@pytest.fixture
def celery_task(monkeypatch, port_scanner_stub):
    pytest.importorskip("celery")
    from app import tasks

    module, _ = port_scanner_stub
    monkeypatch.setattr(tasks.execute_tool_async, "update_state", lambda **kwargs: None)
    monkeypatch.setattr(tasks, "_load_tool_module", lambda name: module)
    return tasks.execute_tool_async


@pytest.mark.parametrize("target", ["127.0.0.1", "wildbox-redis", "fe80::1"])
def test_the_async_task_refuses_before_the_tool_runs(
    resolver, allow, celery_task, port_scanner_stub, target
):
    _, calls = port_scanner_stub

    outcome = celery_task.run(
        tool_name="port_scanner", input_data={"target": target}, user_id="u-1"
    )

    assert outcome["status"] == "failed", outcome
    assert "network target policy" in outcome["error"]
    assert calls == []


def test_the_async_task_runs_the_tool_for_an_allowed_target(
    resolver, allow, celery_task, port_scanner_stub
):
    _, calls = port_scanner_stub
    allow("10.20.0.0/16")

    for target in ("example.com", "10.20.0.9"):
        outcome = celery_task.run(
            tool_name="port_scanner", input_data={"target": target}, user_id="u-1"
        )
        assert outcome["status"] == "completed", outcome
    assert len(calls) == 2


@pytest.fixture
def orchestrator_spy(monkeypatch):
    from app.tools.network_port_scanner import main as nps_main

    calls = []

    async def spy(input_data):
        calls.append(input_data)
        return {"success": True}

    monkeypatch.setattr(nps_main, "execute_tool", spy)
    return calls


def _workflow(*steps):
    from app.tools.security_automation_orchestrator.schemas import (
        AutomationWorkflowInput,
    )

    return AutomationWorkflowInput(
        workflow_name="wf",
        trigger_type="manual",
        workflow_steps=list(steps),
        execution_mode="sequential",
    )


@pytest.mark.parametrize("target", ["127.0.0.1", "wildbox-redis", "169.254.169.254"])
def test_an_orchestrated_step_aimed_inside_is_refused(
    resolver, allow, orchestrator_spy, target
):
    from app.tools.security_automation_orchestrator import main as orch

    step = {"tool": "network_port_scanner", "parameters": {"target": target}}
    out = asyncio.run(orch.execute_tool(_workflow(step)))
    result = out.workflow_execution.step_results[0]

    assert result.status == "failed"
    assert "Blocked target" in result.error_message
    assert "network target policy" in result.error_message
    # The step's parameter that held the target, and not the target (#774).
    assert result.error_message.endswith("(target: target_internal)")
    assert target not in result.error_message
    assert orchestrator_spy == []


def test_an_orchestrated_step_with_an_allowed_target_runs(
    resolver, allow, orchestrator_spy
):
    from app.tools.security_automation_orchestrator import main as orch

    allow("10.20.0.0/16")
    steps = [
        {"tool": "network_port_scanner", "parameters": {"target": "example.com"}},
        {"tool": "network_port_scanner", "parameters": {"target": "10.20.0.9"}},
    ]
    out = asyncio.run(orch.execute_tool(_workflow(*steps)))

    assert [s.status for s in out.workflow_execution.step_results] == [
        "completed",
        "completed",
    ]
    assert [c.target for c in orchestrator_spy] == ["example.com", "10.20.0.9"]


# --- targets a tool takes from a remote answer --------------------------------------


def test_zone_transfers_go_to_checked_name_server_addresses(
    resolver, allow, monkeypatch
):
    """dns_enumerator's NS records name the servers it transfers from."""
    import dns.query
    import dns.zone
    from app.tools.dns_enumerator import main as dns_enum

    table, _ = resolver
    table["ns1.example.com"] = [PUBLIC_IP]
    table["ns2.example.com"] = ["10.0.0.53"]
    dialed = []

    def fake_xfr(where, zone, **kwargs):
        dialed.append(where)
        raise dns.exception.FormError("refused")

    monkeypatch.setattr(dns.query, "xfr", fake_xfr)
    monkeypatch.setattr(dns.zone, "from_xfr", lambda xfr: xfr)

    results = asyncio.run(
        dns_enum.attempt_zone_transfer(
            "example.com", ["ns1.example.com.", "ns2.example.com.", "wildbox-redis."], 5
        )
    )

    assert dialed == [PUBLIC_IP]
    assert [r.server for r in results] == [
        "ns1.example.com.",
        "ns2.example.com.",
        "wildbox-redis.",
    ]
    assert not any(r.successful for r in results)
    assert "network target policy" not in (results[0].error or "")
    assert "network target policy" in results[1].error
    assert "network target policy" in results[2].error


def test_an_allow_listed_name_server_is_transferred_from(resolver, allow, monkeypatch):
    import dns.query
    from app.tools.dns_enumerator import main as dns_enum

    table, _ = resolver
    table["ns.lab.example"] = ["10.20.0.53"]
    allow("10.20.0.0/16")
    dialed = []

    def fake_xfr(where, zone, **kwargs):
        dialed.append(where)
        raise EOFError

    monkeypatch.setattr(dns.query, "xfr", fake_xfr)
    asyncio.run(dns_enum.attempt_zone_transfer("lab.example", ["ns.lab.example."], 5))
    assert dialed == ["10.20.0.53"]


# --- port_scanner scans the host that was checked -----------------------------------


@pytest.mark.parametrize(
    "target", ["2001:4860:4860::8888", "example.com/x", "exa mple.com"]
)
def test_port_scanner_refuses_a_target_it_would_have_rewritten(target):
    from app.tools.port_scanner.main import validate_target

    with pytest.raises(ValueError):
        validate_target(target)


@pytest.mark.parametrize("target", ["example.com", PUBLIC_IP, "scan_me.example.com"])
def test_port_scanner_keeps_a_plain_target(target):
    from app.tools.port_scanner.main import validate_target

    assert validate_target(target) == target
