"""A refusal says what kind it is, not what it refused (#774).

The target policy and the URL guard quoted the refused target in the answer
to the caller who sent it: "Target 'x' is a private ... address". identity
and agents stopped repeating refused values in #722 and #735; these were the
refusals left. Now the text names the kind of refusal and, where the
operator can lift it, the setting that does (``TOOLS_ALLOWED_INTERNAL_TARGETS``);
the field that held the target is in the field errors of the answer, where a
422 has its own. Statuses are what they were.

Also here, because they are the same refusals:

* a target with an IPv6 zone id is refused in the fields that take an
  address or a range, as it was in the fields that take a host and as
  guardian refuses it;
* ``SecurityValidator`` classifies an address through the shared policy,
  not with an expression of its own;
* the middleware that answered the text of an error is gone: nothing
  installed it.
"""

import ipaddress
import json
import os
import random
import socket
import sys
import uuid
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import input_validation, prerun  # noqa: E402
from app import target_policy as tp  # noqa: E402
from app.input_validation import InputSanitizer, UrlField, UrlRefused  # noqa: E402
from app.security.validator import SecurityValidator  # noqa: E402
from app.target_policy import (  # noqa: E402
    TargetKind,
    TargetRefused,
    check_value,
    enforce_target_policy,
    parse_allowlist,
)
from open_security_shared import target_policy as shared  # noqa: E402
from open_security_shared.errors import message_and_details  # noqa: E402
from pydantic import BaseModel, HttpUrl, ValidationError  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads(
    (REPO_ROOT / "tests" / "shared" / "target_policy_vectors.json").read_text(
        encoding="utf-8"
    )
)
SETTING = "TOOLS_ALLOWED_INTERNAL_TARGETS"
# In every refused value below, so that one search finds any of them.
MARK = "echo" + uuid.uuid4().hex[:12]
NONE_ALLOWED = parse_allowlist("")

# Every text the policy answers with. A refusal is one of these, whole.
POLICY_TEXTS = {
    tp.INTERNAL_ADDRESS,
    tp.INTERNAL_RANGE,
    tp.INTERNAL_NAME,
    tp.UNRESOLVABLE,
    tp.RANGE_TOO_LARGE,
    tp.NOT_A_STRING,
    tp.SPACE_OR_CONTROL,
    tp.ZONE_ID,
    tp.NOT_AN_IP,
    tp.NOT_AN_IP_OR_CIDR,
    tp.NOT_A_NETWORK,
    tp.NOT_A_RANGE,
    tp.RANGE_BACKWARDS,
}
LIFTED_BY_THE_SETTING = {
    tp.INTERNAL_ADDRESS,
    tp.INTERNAL_RANGE,
    tp.INTERNAL_NAME,
    tp.UNRESOLVABLE,
}


@pytest.fixture
def resolver(monkeypatch):
    """Names resolve from a table; a name that is not in it does not resolve."""
    table = {}

    def fake_getaddrinfo(host, *args, **kwargs):
        if host not in table:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        ip = table[host]
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return table


def is_a_policy_text(message):
    # A host the parser refuses adds the parser's own sentence, after a colon.
    return message in POLICY_TEXTS or message.startswith(f"{tp.NOT_A_HOST}: ")


# --- the network target policy -------------------------------------------------------

H, P, I, C, N, R = (
    TargetKind.HOST,
    TargetKind.HOST_PORT_OR_URL,
    TargetKind.IP,
    TargetKind.IP_OR_CIDR,
    TargetKind.NETWORK,
    TargetKind.IMAGE_REF,
)

REFUSED = [
    # (kind, value, text, code)
    (H, "10.9.8.7", tp.INTERNAL_ADDRESS, tp.TARGET_INTERNAL),
    (H, "fd12:3456::7", tp.INTERNAL_ADDRESS, tp.TARGET_INTERNAL),
    (H, f"{MARK}-redis", tp.INTERNAL_NAME, tp.TARGET_INTERNAL),
    (H, f"{MARK}.internal", tp.INTERNAL_NAME, tp.TARGET_INTERNAL),
    (H, f"gone.{MARK}.example", tp.UNRESOLVABLE, tp.TARGET_INTERNAL),
    (H, f"inside.{MARK}.example", tp.UNRESOLVABLE, tp.TARGET_INTERNAL),
    (H, f"{MARK} with a space", tp.SPACE_OR_CONTROL, tp.TARGET_INVALID),
    (H, f"{MARK}\x00", tp.SPACE_OR_CONTROL, tp.TARGET_INVALID),
    (H, f"-{MARK}.example", None, tp.TARGET_INVALID),
    (H, "127.1", None, tp.TARGET_INVALID),
    (H, "2606:4700:4700::1111%eth0", None, tp.TARGET_INVALID),
    (H, 10987, tp.NOT_A_STRING, tp.TARGET_INVALID),
    (P, f"https://{MARK}-vault:8200/v1/secret", tp.INTERNAL_NAME, tp.TARGET_INTERNAL),
    (P, "10.9.8.7:8443", tp.INTERNAL_ADDRESS, tp.TARGET_INTERNAL),
    (I, "10.9.8.7", tp.INTERNAL_ADDRESS, tp.TARGET_INTERNAL),
    (I, f"{MARK}.example", tp.NOT_AN_IP, tp.TARGET_INVALID),
    (I, "2606:4700:4700::1111%eth0", tp.ZONE_ID, tp.TARGET_INVALID),
    (C, "10.9.8.0/24", tp.INTERNAL_RANGE, tp.TARGET_INTERNAL),
    (C, "10.9.8.7", tp.INTERNAL_RANGE, tp.TARGET_INTERNAL),
    (C, "8.9.0.0/16", tp.RANGE_TOO_LARGE, tp.TARGET_TOO_LARGE),
    (C, f"{MARK}/24", tp.NOT_AN_IP_OR_CIDR, tp.TARGET_INVALID),
    (C, "2606:4700:4700::%eth0/120", tp.ZONE_ID, tp.TARGET_INVALID),
    (C, "2606:4700:4700::1111%7", tp.ZONE_ID, tp.TARGET_INVALID),
    (N, "10.9.8.1-30", tp.INTERNAL_RANGE, tp.TARGET_INTERNAL),
    (N, "10.9.8.0/24", tp.INTERNAL_RANGE, tp.TARGET_INTERNAL),
    (N, "8.9.8.30-1", tp.RANGE_BACKWARDS, tp.TARGET_INVALID),
    (N, "8.9.8.1-300", tp.NOT_A_RANGE, tp.TARGET_INVALID),
    (N, f"{MARK}.1-9x", tp.NOT_A_NETWORK, tp.TARGET_INVALID),
    (N, "2606:4700:4700::%eth0/120", tp.ZONE_ID, tp.TARGET_INVALID),
    (R, f"{MARK}.internal:5000/team/image:1", tp.INTERNAL_NAME, tp.TARGET_INTERNAL),
    (R, "10.9.8.7:5000/image", tp.INTERNAL_ADDRESS, tp.TARGET_INTERNAL),
]


def distinctive_parts(value):
    """The value, and the parts of it a caller would recognize as theirs."""
    text = str(value)
    parts = {text, MARK, "10.9.8", "8.9.", "fd12", "2606", "eth0", "10987", "127.1"}
    return {part for part in parts if part in text}


@pytest.mark.parametrize(
    "kind,value,text,code",
    REFUSED,
    ids=[f"{k.value}:{v!r}"[:40] for k, v, _, _ in REFUSED],
)
def test_a_refusal_has_the_kind_and_the_setting_and_not_the_value(
    kind, value, text, code, resolver
):
    resolver[f"inside.{MARK}.example"] = "10.9.8.7"

    with pytest.raises(TargetRefused) as refused:
        check_value(kind, value, NONE_ALLOWED)

    message = str(refused.value)
    assert is_a_policy_text(message), message
    if text is not None:
        assert message == text
    assert refused.value.code == code
    for part in distinctive_parts(value):
        assert part not in message, (part, message)
    # The setting, in the refusals it lifts and in no other.
    assert (SETTING in message) is (message in LIFTED_BY_THE_SETTING)
    assert ("network target policy" in message) is (message in LIFTED_BY_THE_SETTING)


def test_the_texts_the_setting_lifts_say_so_and_the_limit_does_not():
    for text in LIFTED_BY_THE_SETTING:
        assert text.endswith(
            f"(network target policy; operators can allow internal targets with {SETTING})"
        )
    assert SETTING not in tp.RANGE_TOO_LARGE
    assert f"at most {shared.MAX_TARGET_ADDRESSES} addresses" in tp.RANGE_TOO_LARGE


def test_no_text_of_the_policy_is_built_from_a_value():
    """No refusal is an f-string over the target: the module has no
    placeholder for one left."""
    source = (
        REPO_ROOT / "open-security-tools" / "app" / "target_policy.py"
    ).read_text()

    for placeholder in (
        "{value",
        "{host",
        "{refusal.address",
        "{refusal.host",
        "{refusal.count",
    ):
        assert placeholder not in source, placeholder


def cases_the_vectors_refuse():
    for case in VECTORS["addresses"]:
        if case["expect"] != "allowed":
            for kind in (H, I, C):
                yield kind, case["address"], case.get("allow", "")
    for case in VECTORS["networks"]:
        if case["expect"] != "allowed":
            for kind in (C, N):
                yield kind, case["network"], case.get("allow", "")
    for value in VECTORS["spellings"]:
        for kind in (H, I, C, N):
            yield kind, value, ""
    for name in VECTORS["names"]["internal"]:
        yield H, name, ""


@pytest.mark.parametrize(
    "kind,value,allow",
    list(cases_the_vectors_refuse()),
    ids=lambda item: getattr(item, "value", item),
)
def test_no_refusal_of_the_shared_vectors_repeats_its_value(
    kind, value, allow, resolver
):
    with pytest.raises(TargetRefused) as refused:
        check_value(kind, value, parse_allowlist(allow))

    message = str(refused.value)
    assert is_a_policy_text(message), message
    assert value not in message
    assert value.lower().rstrip(".") not in message


# --- an IPv6 zone id ---------------------------------------------------------------------


# Public addresses: nothing else about them is refused.
ZONED_ADDRESSES = ["2606:4700:4700::1111%eth0", "2606:4700:4700::1111%1"]
ZONED_RANGES = ["2606:4700:4700::%eth0/120", "2606:4700:4700::1111%eth0/128"]


@pytest.mark.parametrize(
    "kind,value",
    [(kind, value) for kind in (I, C, N) for value in ZONED_ADDRESSES]
    + [(kind, value) for kind in (C, N) for value in ZONED_RANGES],
)
def test_an_address_or_a_range_with_a_zone_id_is_refused(kind, value):
    """It passed as the same address or range without the zone (#774)."""
    address, _, prefix = value.partition("/")
    without_zone = address.split("%")[0] + (f"/{prefix}" if prefix else "")
    check_value(kind, without_zone, NONE_ALLOWED)

    with pytest.raises(TargetRefused) as refused:
        check_value(kind, value, NONE_ALLOWED)

    assert str(refused.value) == tp.ZONE_ID
    assert refused.value.code == tp.TARGET_INVALID


def test_the_allowlist_does_not_lift_a_zone_id():
    listed = parse_allowlist("fe80::/64")

    check_value(I, "fe80::1", listed)
    with pytest.raises(TargetRefused, match="zone id"):
        check_value(I, "fe80::1%eth0", listed)
    with pytest.raises(TargetRefused, match="zone id"):
        check_value(C, "fe80::%eth0/120", listed)


def test_the_shared_vectors_have_a_zone_id_that_nothing_else_refuses():
    """The case that would pass if the check were gone: a public address."""
    zoned = [value for value in VECTORS["spellings"] if "%" in value]

    assert zoned
    for value in zoned:
        assert not shared.is_internal_address(ipaddress.ip_address(value.split("%")[0]))


# --- the field, in the answer -------------------------------------------------------------


def test_the_refusal_names_the_field_that_held_the_target(resolver):
    from app.tools.iot_security_scanner.schemas import IoTSecurityScannerInput
    from app.tools.port_scanner.schemas import PortScannerInput

    with pytest.raises(TargetRefused) as refused:
        enforce_target_policy("port_scanner", PortScannerInput(target="10.9.8.7"))
    assert (refused.value.field, refused.value.code) == ("target", tp.TARGET_INTERNAL)

    # The second target field of a tool, and not the first.
    with pytest.raises(TargetRefused) as refused:
        enforce_target_policy(
            "iot_security_scanner",
            IoTSecurityScannerInput(target_ip="8.8.8.8", ip_range="10.9.8.0/24"),
        )
    assert refused.value.field == "ip_range"
    assert str(refused.value) == tp.INTERNAL_RANGE


def test_a_list_of_targets_names_its_field():
    from app.tools.dns_enumerator.schemas import DNSEnumeratorInput

    with pytest.raises(TargetRefused) as refused:
        enforce_target_policy(
            "dns_enumerator",
            DNSEnumeratorInput(
                target_domain="example.com", dns_servers=["8.8.8.8", "10.9.8.7"]
            ),
        )

    assert refused.value.field == "dns_servers"
    assert "10.9.8.7" not in str(refused.value)


class Mirror(BaseModel):
    link: HttpUrl


class Fetch(BaseModel):
    note: str = ""
    destination: HttpUrl
    mirrors: list[Mirror] = []
    options: dict = {}


@pytest.mark.parametrize(
    "fields,field",
    [
        ({"destination": "http://10.9.8.7/x"}, "destination"),
        (
            {
                "destination": "https://example.com/",
                "mirrors": [{"link": "http://10.9.8.7/"}],
            },
            "mirrors",
        ),
        (
            {
                "destination": "https://example.com/",
                "options": {"deep": {"callback_url": "http://10.9.8.7/hook"}},
            },
            "options",
        ),
    ],
)
def test_a_refused_url_names_the_field_of_the_input_it_is_under(
    resolver, fields, field
):
    resolver["example.com"] = "93.184.215.14"

    with pytest.raises(TargetRefused) as refused:
        enforce_target_policy("no_such_tool", Fetch(**fields))

    assert refused.value.field == field
    assert refused.value.code == tp.URL_REFUSED
    assert str(refused.value) == input_validation.BLOCKED_ADDRESS
    assert "10.9.8" not in str(refused.value)


def test_the_answer_has_the_field_where_a_422_has_its_own():
    refusal = TargetRefused(
        tp.INTERNAL_ADDRESS, code=tp.TARGET_INTERNAL, field="target"
    )

    answer = prerun.http_error(refusal)
    message, details = message_and_details(answer.detail, answer.status_code)

    assert answer.status_code == 400
    # error.message is the sentence it always was a place for; error.details
    # is new, and has the shape of a 422's.
    assert message == tp.INTERNAL_ADDRESS
    assert details["errors"] == [
        {"loc": ["target"], "msg": tp.INTERNAL_ADDRESS, "type": "target_internal"}
    ]
    assert set(details["errors"][0]) == {"loc", "msg", "type"}
    assert (
        prerun.refusal_text(refusal)
        == f"{tp.INTERNAL_ADDRESS} (target: target_internal)"
    )
    assert prerun.refusal_log(refusal) == prerun.TARGET_REFUSED


def test_a_refusal_whose_field_is_not_known_is_the_sentence_alone():
    refusal = TargetRefused(tp.UNRESOLVABLE, code=tp.TARGET_INTERNAL)

    answer = prerun.http_error(refusal)

    assert (answer.status_code, answer.detail) == (400, tp.UNRESOLVABLE)
    assert prerun.refusal_text(refusal) == tp.UNRESOLVABLE


def test_the_documented_example_is_the_text_of_the_code():
    documented = (REPO_ROOT / "docs" / "api" / "tools" / "endpoints.md").read_text()

    assert f"`{tp.INTERNAL_ADDRESS}`" in documented


# --- the URL guard -----------------------------------------------------------------------


URLS = [
    (f"http://{MARK}.localhost/a", input_validation.LOCAL_HOST),
    (
        "http://metadata.google.internal/computeMetadata/v1/",
        input_validation.LOCAL_HOST,
    ),
    (f"https://inside.{MARK}.example/?token={MARK}", input_validation.RESOLVES_INSIDE),
    (f"https://gone.{MARK}.example/{MARK}", input_validation.DOES_NOT_RESOLVE),
    ("http://10.9.8.7/admin", input_validation.BLOCKED_ADDRESS),
    ("http://[fd12:3456::7]/", input_validation.BLOCKED_ADDRESS),
    (f"{MARK}://example.com/", "URL scheme is missing or not allowed"),
    (f"http://[{MARK}]/", "URL is not well formed"),
    (f"https://{MARK}:{MARK}@example.com/", "URL must not contain user info"),
    (f"https://example.com:{MARK}/", "URL port is invalid"),
    (f"https://-{MARK}.example/", "URL host is not a valid domain name"),
]


@pytest.mark.parametrize("url,text", URLS, ids=[text for _, text in URLS])
def test_the_url_guard_says_what_is_wrong_and_not_with_which_url(url, text, resolver):
    resolver[f"inside.{MARK}.example"] = "10.9.8.7"

    with pytest.raises(ValueError) as refused:
        InputSanitizer.validate_url(url)

    message = str(refused.value)
    assert message == text
    for part in (MARK, "10.9.8", "fd12", "example", "metadata"):
        assert part not in message


def test_a_url_field_of_a_schema_reports_no_value_either(resolver):
    """UrlField runs the guard as the model validates: the error is a 422's."""

    class Model(BaseModel):
        api_base_url: UrlField

    with pytest.raises(ValidationError) as refused:
        Model(api_base_url=f"{MARK}://10.9.8.7/")

    (error,) = prerun.input_field_errors(refused.value)
    assert error["loc"] == ["api_base_url"]
    assert MARK not in json.dumps(error) and "10.9.8" not in json.dumps(error)


def test_the_walk_reports_a_refused_url_with_its_field_and_nothing_else_of_it(resolver):
    with pytest.raises(UrlRefused) as refused:
        InputSanitizer.validate_request_urls(Fetch(destination="http://10.9.8.7/"))

    assert (refused.value.field, refused.value.reason) == (
        "destination",
        input_validation.BLOCKED_ADDRESS,
    )
    assert isinstance(refused.value, ValueError)


# --- one classifier ------------------------------------------------------------------------


def old_classifier(addr):
    """What SecurityValidator decided with, to compare."""
    return not addr.is_global or addr.is_multicast


def validator_refuses(addr):
    host = f"[{addr}]" if addr.version == 6 else str(addr)
    try:
        SecurityValidator.validate_url(f"https://{host}/")
    except ValueError:
        return True
    return False


@pytest.mark.parametrize(
    "case",
    [c for c in VECTORS["addresses"] if not c.get("allow")],
    ids=lambda c: c["address"],
)
def test_the_validator_answers_the_shared_vectors(case):
    refused = validator_refuses(ipaddress.ip_address(case["address"]))

    assert refused is (case["expect"] == "internal")


def test_the_validator_classifies_through_the_one_name(monkeypatch):
    """The name the URL guard, app.safe_http and the target policy use: a
    change of it, or the fixture that lets a test reach a local server,
    reaches this validator too."""
    loopback = ipaddress.ip_address("127.0.0.1")
    assert validator_refuses(loopback)

    monkeypatch.setattr(
        InputSanitizer,
        "_is_blocked_ip",
        staticmethod(lambda addr: addr != loopback and shared.is_blocked_address(addr)),
    )

    assert not validator_refuses(loopback)
    assert validator_refuses(ipaddress.ip_address("127.0.0.2"))


def test_the_validator_has_no_classifier_of_its_own():
    source = (
        REPO_ROOT / "open-security-tools" / "app" / "security" / "validator.py"
    ).read_text()
    code = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )

    for flag in (
        "is_global",
        "is_multicast",
        "is_private",
        "is_loopback",
        "is_reserved",
    ):
        assert flag not in code, flag


@pytest.mark.parametrize(
    "address", ["::2", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "4000::1"]
)
def test_reserved_ipv6_space_and_an_internal_address_behind_nat64_are_refused(
    address,
):
    """What the validator's own expression let through, on Python 3.11."""
    assert validator_refuses(ipaddress.ip_address(address))


def generated_addresses():
    """The edges of every special range, addresses inside each, the IPv4
    ranges again inside the IPv6 prefixes that embed one, and random ones."""
    rng = random.Random(774)
    special = [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32", "::/128", "::1/128",
        "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
        "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
    ]  # fmt: skip
    for text in special:
        net = ipaddress.ip_network(text)
        first, last = int(net.network_address), int(net.broadcast_address)
        top = 2**net.max_prefixlen - 1
        make = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
        for value in (first, last, max(first - 1, 0), min(last + 1, top)):
            yield make(value)
        for _ in range(200):
            value = rng.randint(first, last)
            yield make(value)
            if net.version == 4:
                yield ipaddress.IPv6Address((0xFFFF << 32) | value)
                yield ipaddress.IPv6Address((0x2002 << 112) | (value << 80))
                yield ipaddress.IPv6Address((0x64FF9B << 96) | value)
    for _ in range(20000):
        yield ipaddress.IPv4Address(rng.getrandbits(32))
        yield ipaddress.IPv6Address(rng.getrandbits(128))
        yield ipaddress.IPv6Address((0x2 << 124) | rng.getrandbits(124))


def test_nothing_the_old_classifier_refused_is_allowed_now():
    """Old against new, over the vector file and a generated set."""
    addresses = [ipaddress.ip_address(c["address"]) for c in VECTORS["addresses"]]
    addresses += [ipaddress.ip_address(c["address"]) for c in VECTORS["embedded"]]
    addresses += list(generated_addresses())
    assert len(addresses) > 70000

    newly_allowed = [
        addr
        for addr in addresses
        if old_classifier(addr) and not tp.is_internal_address(addr)
    ]
    # Where the two differ, and they do, it is the shared policy that refuses.
    newly_refused = [
        addr
        for addr in addresses
        if not old_classifier(addr) and tp.is_internal_address(addr)
    ]

    assert newly_allowed == []
    # And the method is the shared policy: a sample of each through it.
    for addr in addresses[:400] + newly_refused[:200]:
        assert validator_refuses(addr) is tp.is_internal_address(addr), addr


# --- the middleware that was never installed -----------------------------------------------


def test_the_application_has_the_middlewares_it_had_and_no_other():
    from app.main import create_app

    installed = sorted(m.cls.__name__ for m in create_app().user_middleware)

    assert installed == [
        "CORSMiddleware",
        "CacheControlMiddleware",
        "ObservabilityMiddleware",
        "RequestLoggingMiddleware",
        "SecurityHeadersMiddleware",
    ]


def test_the_uninstalled_middleware_and_what_only_it_used_are_gone():
    for name in ("validate_request_input",):
        assert not hasattr(input_validation, name)
    for name in (
        "sanitize_string",
        "sanitize_dict",
        "sanitize_list",
        "DANGEROUS_PATTERNS",
    ):
        assert not hasattr(InputSanitizer, name)
    source = (
        REPO_ROOT / "open-security-tools" / "app" / "input_validation.py"
    ).read_text()
    # No answer of this module is built from the text of an exception.
    assert "detail=" not in source
    assert "HTTPException" not in source


def test_a_body_the_removed_middleware_would_have_refused_is_answered_by_the_route():
    """What would show it running: its patterns match every URL, so a body
    with one would be a 400 "Input validation failed" before any route."""
    from app.auth import verify_api_key
    from app.main import create_app
    from fastapi.testclient import TestClient
    from open_security_shared.gateway_auth import GatewayUser

    application = create_app()
    application.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=str(uuid.uuid4()),
        team_id=str(uuid.uuid4()),
        role="member",
        auth_type="session",
    )

    response = TestClient(application).post(
        "/api/tools/no_such_tool/async",
        json={"url": "http://example.com/?q=1;wget x | sh", "note": "<script>"},
    )

    assert response.status_code == 404, response.text
    assert "Input validation failed" not in response.text
