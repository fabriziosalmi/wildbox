"""guardian scans no internal target unless the operator allows it (#748).

Asset discovery and port scans connect to the addresses a team's owner or
admin names, from ``guardian-worker``, which sits inside the stack's
networks. Nothing looked at where an address is: a discovery of
``127.0.0.0/30``, ``10.0.0.0/24``, the range Docker gave the stack,
``169.254.169.254/32`` or ``fe80::/120`` was accepted, stored in a rule, and
dialed. The tools service has refused such targets since 0.11.0 (#614).

guardian now applies the same policy, from the implementation the two
services share (``open_security_shared.target_policy``), where a target is
typed (400, with a message written for the caller) and again where the scan
runs. ``GUARDIAN_ALLOWED_INTERNAL_TARGETS`` is the operator's list, empty by
default.

``tests/shared/target_policy_vectors.json`` is run here through guardian's
entry points; the tools service's unit tests and the shared package's run
the same file. Nothing here opens a connection: the socket is a stub that
records what would have been dialed.
"""

import ast
import errno
import ipaddress
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from unittest import mock

import pytest
from apps.assets import networks, tasks
from apps.assets.models import Asset, AssetDiscoveryRule
from apps.assets.networks import (
    MAX_SCAN_ADDRESSES,
    NetworkRefused,
    check_address,
    check_network,
    scan_network,
)
from django.core.exceptions import ImproperlyConfigured
from django.test import Client
from guardian.scan_targets import ALLOWLIST_VARIABLE, allowed_internal_targets
from open_security_shared import target_policy as shared

from tests.unit import team_fixtures as tf

GUARDIAN_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = GUARDIAN_DIR.parent
VECTORS_FILE = REPO_ROOT / "tests" / "shared" / "target_policy_vectors.json"
VECTORS = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))

_GW_SECRET = "test-gateway-secret"
_ASSETS = "/api/v1/assets/assets/"
_DISCOVER = "/api/v1/assets/assets/discover/"
_RULES = "/api/v1/assets/discovery-rules/"

# What the issue names: loopback, RFC 1918, the range Docker takes a compose
# network from, link-local, cloud metadata, and their IPv6 and IPv4-in-IPv6
# spellings. Each was accepted, stored and dialed before.
INTERNAL_NETWORKS = [
    "127.0.0.0/30",
    "10.0.0.0/24",
    "172.18.0.0/24",
    "192.168.1.0/24",
    "169.254.169.254/32",
    "169.254.0.0/24",
    "100.64.0.0/24",
    "0.0.0.0/32",
    "fe80::/120",
    "::1/128",
    "fd00::/118",
    "::ffff:10.0.0.0/120",
    "2002:a00::/118",
    "64:ff9b::a00:0/120",
]
INTERNAL_ADDRESSES = [
    "127.0.0.1",
    "10.0.0.5",
    "172.18.0.2",
    "192.168.1.10",
    "169.254.169.254",
    "0.0.0.0",
    "::1",
    "fe80::1",
    "fd00::c2b6:a9ff:fe52:2ea5",
    "::ffff:10.0.0.5",
    "::ffff:169.254.169.254",
]
PUBLIC_ADDRESS = "93.184.215.14"


def _id(case):
    key = case.get("address") if "network" not in case else case["network"]
    return f"{key}|{case.get('allow', '')}"


@pytest.fixture
def allow(settings):
    """Set the operator's allowlist, as GUARDIAN_ALLOWED_INTERNAL_TARGETS would.

    Empty to begin with: the default of a deployment, not the test settings'
    documentation ranges.
    """

    def set_allowlist(raw):
        settings.SCAN_ALLOWED_INTERNAL_TARGETS = allowed_internal_targets(
            {ALLOWLIST_VARIABLE: raw}
        )

    set_allowlist("")
    return set_allowlist


class _Socket:
    """What tasks.py does with a socket, recording every address it dials."""

    dialed = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, value):
        pass

    def connect_ex(self, address):
        _Socket.dialed.append(address)
        return errno.ECONNREFUSED

    def connect(self, address):
        _Socket.dialed.append(address)
        raise OSError(errno.ECONNREFUSED, "refused")

    def close(self):
        pass


@pytest.fixture
def dialed(monkeypatch):
    """Every (address, port) the scanner would have connected to."""
    _Socket.dialed = []
    monkeypatch.setattr(tasks.socket, "socket", _Socket)
    monkeypatch.setattr(tasks.socket, "gethostbyaddr", lambda ip: ("", [], [ip]))
    return _Socket.dialed


@pytest.fixture
def api(settings, monkeypatch):
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)
    caller = str(uuid.uuid4())

    def call(method, url, team, data=None, role="admin"):
        kwargs = {
            "secure": True,
            "HTTP_X_WILDBOX_USER_ID": caller,
            "HTTP_X_WILDBOX_TEAM_ID": str(team),
            "HTTP_X_WILDBOX_ROLE": role,
            "HTTP_X_WILDBOX_AUTH_TYPE": "session",
            "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        }
        if data is not None:
            kwargs.update(data=json.dumps(data), content_type="application/json")
        return getattr(client, method)(url, **kwargs)

    return call


@pytest.fixture
def queued():
    """The tasks queued, instead of a broker: [(task name, args, kwargs), ...]."""
    calls = []

    def recorder(name):
        def delay(*args, **kwargs):
            calls.append((name, args, kwargs))
            return mock.Mock(id=str(uuid.uuid4()))

        return delay

    with mock.patch.object(
        tasks.discover_assets, "delay", side_effect=recorder("discover")
    ), mock.patch.object(
        tasks.scan_asset_ports, "delay", side_effect=recorder("scan")
    ), mock.patch.object(
        tasks.execute_discovery_rule, "delay", side_effect=recorder("rule")
    ):
        yield calls


def _rule_body(networks_, **fields):
    body = {
        "name": f"rule-{uuid.uuid4().hex[:8]}",
        "discovery_type": "network_scan",
        "target_specification": {"networks": list(networks_)},
        "schedule": "*/10 * * * *",
    }
    body.update(fields)
    return body


# --- the shared vectors, through guardian's entry points ------------------------------


def test_there_are_vectors():
    assert len(VECTORS["addresses"]) >= 60
    assert len(VECTORS["networks"]) >= 50


@pytest.mark.parametrize("case", VECTORS["addresses"], ids=_id)
def test_an_address_is_scanned_or_internal(case, allow):
    allow(case.get("allow", ""))

    address, refusal = check_address(case["address"])
    network, network_refusal = check_network(case["address"])

    if case["expect"] == "allowed":
        assert refusal is None and network_refusal is None
        assert address == ipaddress.ip_address(case["address"])
        assert network == ipaddress.ip_network(case["address"])
    else:
        assert address is None and network is None
        for message in (refusal, network_refusal):
            assert f"{ipaddress.ip_address(case['address'])} is an internal" in message
            assert ALLOWLIST_VARIABLE in message


@pytest.mark.parametrize("value", VECTORS["spellings"])
def test_another_spelling_of_an_address_is_not_one(value, allow):
    # inet_aton reads these as loopback and friends; guardian hands the
    # socket only what ipaddress parsed.
    assert check_address(value) == (None, f"{value!r} is not an IP address.")
    network, refusal = check_network(value)
    assert network is None
    assert refusal == f"{value!r} is not a network in CIDR notation."


@pytest.mark.parametrize("case", VECTORS["networks"], ids=_id)
def test_a_network_is_swept_or_refused_whole(case, allow):
    allow(case.get("allow", ""))

    network, refusal = check_network(case["network"])

    if case["expect"] == "allowed":
        assert refusal is None
        assert network == ipaddress.ip_network(case["network"], strict=False)
        assert scan_network(case["network"]) == network
        return
    assert network is None
    with pytest.raises(NetworkRefused) as refused:
        scan_network(case["network"])
    assert str(refused.value) == refusal
    if case["expect"] == "too_large":
        assert f"more than {MAX_SCAN_ADDRESSES} addresses" in refusal
        assert ALLOWLIST_VARIABLE not in refusal, "no list lifts the limit"
    elif case["expect"] == "internal":
        first = ipaddress.ip_address(case["address"])
        assert (
            f"{first}, an internal" in refusal or f"{first} is an internal" in refusal
        )
        assert ALLOWLIST_VARIABLE in refusal
    else:
        assert "is not a network in CIDR notation" in refusal


@pytest.mark.parametrize("case", VECTORS["allowlist"]["valid"], ids=lambda c: c["raw"])
def test_the_operators_list_is_parsed(case):
    allowlist = allowed_internal_targets({ALLOWLIST_VARIABLE: case["raw"]})

    assert [str(network) for network in allowlist.networks] == case["networks"]


@pytest.mark.parametrize(
    "raw", VECTORS["allowlist"]["invalid"] + VECTORS["allowlist"]["names"]
)
def test_a_bad_entry_is_an_error_that_names_the_variable(raw):
    # A host name too: guardian scans addresses, so a name would be accepted
    # and never match anything.
    with pytest.raises(ImproperlyConfigured, match=ALLOWLIST_VARIABLE):
        allowed_internal_targets({ALLOWLIST_VARIABLE: raw})


# --- one implementation ---------------------------------------------------------------


def test_the_policy_is_the_shared_one_and_not_a_copy():
    assert MAX_SCAN_ADDRESSES is shared.MAX_TARGET_ADDRESSES
    assert isinstance(networks.scan_policy(), shared.TargetPolicy)
    assert networks.scan_policy().blocked is shared.is_blocked_address
    # guardian classifies no address itself.
    for path in ("apps/assets/networks.py", "apps/assets/tasks.py"):
        source = (GUARDIAN_DIR / path).read_text(encoding="utf-8")
        for flag in ("is_private", "is_loopback", "is_link_local", "is_global"):
            assert flag not in source, f"{path} classifies an address itself"


def test_the_setting_is_guardians_own(monkeypatch):
    """The tools service's list says nothing about what guardian may scan."""
    assert ALLOWLIST_VARIABLE == "GUARDIAN_ALLOWED_INTERNAL_TARGETS"
    environ = {"TOOLS_ALLOWED_INTERNAL_TARGETS": "10.0.0.0/8,lab-dc01"}

    assert not allowed_internal_targets(environ)
    assert not allowed_internal_targets({})
    monkeypatch.setenv("TOOLS_ALLOWED_INTERNAL_TARGETS", "10.0.0.0/8")
    monkeypatch.delenv(ALLOWLIST_VARIABLE, raising=False)
    assert not allowed_internal_targets()
    monkeypatch.setenv(ALLOWLIST_VARIABLE, "10.20.0.0/16")
    assert [str(n) for n in allowed_internal_targets().networks] == ["10.20.0.0/16"]


# --- the setting, at start-up -----------------------------------------------------------


def _load_settings(**variables):
    """Load guardian's settings in a new interpreter, as a start-up does."""
    env = {key: value for key, value in os.environ.items() if key != ALLOWLIST_VARIABLE}
    # guardian.settings, not the test settings, which allow a lab.
    env.update(DJANGO_SETTINGS_MODULE="guardian.settings", **variables)
    env.setdefault("SECRET_KEY", "test-secret-key-do-not-use-in-prod")
    program = (
        "import django; django.setup();"
        "from django.conf import settings as s;"
        "a = s.SCAN_ALLOWED_INTERNAL_TARGETS;"
        "print([str(n) for n in a.networks], sorted(a.names))"
    )
    return subprocess.run(
        [sys.executable, "-c", program],
        cwd=GUARDIAN_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_nothing_internal_is_allowed_unless_the_operator_says_so():
    loaded = _load_settings()

    assert loaded.returncode == 0, loaded.stderr[-500:]
    assert loaded.stdout.strip() == "[] []"


def test_start_up_applies_the_variable():
    loaded = _load_settings(
        **{ALLOWLIST_VARIABLE: " 192.168.50.0/24, 10.20.0.0/16 ,fd00:1::/64"}
    )

    assert loaded.returncode == 0, loaded.stderr[-500:]
    assert (
        loaded.stdout.strip() == "['192.168.50.0/24', '10.20.0.0/16', 'fd00:1::/64'] []"
    )


@pytest.mark.parametrize(
    "raw, named",
    [
        ("10.0.0.1/8", "'10.0.0.1/8'"),  # host bits set: a typo, not a range
        ("192.168.50.0/24,lab-dc01", "'lab-dc01'"),
        ("192.168.50.0/24 10.20.0.0/16", "'192.168.50.0/24 10.20.0.0/16'"),
        ("127.1", "'127.1'"),
    ],
)
def test_start_up_fails_on_a_malformed_list(raw, named):
    loaded = _load_settings(**{ALLOWLIST_VARIABLE: raw})

    assert loaded.returncode != 0
    assert "ImproperlyConfigured" in loaded.stderr
    assert f"{ALLOWLIST_VARIABLE}: {named}" in loaded.stderr
    assert loaded.stdout == ""


# --- a discovery, where it is asked for ------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("network", INTERNAL_NETWORKS)
def test_discover_refuses_an_internal_range_and_queues_nothing(
    api, allow, queued, network
):
    response = api("post", _DISCOVER, uuid.uuid4(), {"network_range": network})

    assert response.status_code == 400, response.content[:300]
    (message,) = response.json()["network_range"]
    assert "internal address" in message
    # The caller cannot change the setting; the message says what to ask for.
    assert ALLOWLIST_VARIABLE in message
    assert "task_id" not in response.json()
    assert queued == []


@pytest.mark.django_db
def test_discover_refuses_whole_a_range_that_is_only_partly_internal(
    api, allow, queued
):
    # 203.0.112.0/24 is public; 203.0.113.0/24, in the same /22, is not.
    response = api("post", _DISCOVER, uuid.uuid4(), {"network_range": "203.0.112.0/22"})

    assert response.status_code == 400, response.content[:300]
    (message,) = response.json()["network_range"]
    assert message.startswith("203.0.112.0/22 includes 203.0.113.0, an internal")
    assert queued == []


@pytest.mark.django_db
def test_discover_sweeps_a_public_range_and_what_the_operator_allows(
    api, allow, queued
):
    team = uuid.uuid4()

    assert (
        api("post", _DISCOVER, team, {"network_range": "8.8.8.0/24"}).status_code == 200
    )
    refused = api("post", _DISCOVER, team, {"network_range": "192.168.50.0/24"})
    assert refused.status_code == 400
    allow("192.168.50.0/24")
    assert (
        api("post", _DISCOVER, team, {"network_range": "192.168.50.0/24"}).status_code
        == 200
    )
    # What the list names, and nothing beside it or around it.
    for network in ("192.168.51.0/24", "192.168.50.0/23", "127.0.0.1/32"):
        response = api("post", _DISCOVER, team, {"network_range": network})
        assert response.status_code == 400, network
    assert [args[0] for _, args, _ in queued] == ["8.8.8.0/24", "192.168.50.0/24"]


@pytest.mark.django_db
def test_the_refusal_is_written_for_the_caller_and_is_not_an_exceptions_text(
    api, allow
):
    response = api("post", _DISCOVER, uuid.uuid4(), {"network_range": "10.0.0.0/24"})

    assert response.json() == {
        "network_range": [
            "10.0.0.0/24 includes 10.0.0.0, an internal address (private, "
            "loopback, link-local, multicast, reserved or cloud metadata). "
            "guardian scans an internal address only if the operator of this "
            "deployment lists its range in GUARDIAN_ALLOWED_INTERNAL_TARGETS."
        ]
    }
    # check_network answers; it raises nothing for a view to catch.
    assert check_network("10.0.0.0/24")[0] is None


@pytest.mark.django_db
def test_a_member_who_is_not_an_admin_still_cannot_ask(api, allow, queued):
    response = api(
        "post", _DISCOVER, uuid.uuid4(), {"network_range": "8.8.8.0/24"}, role="member"
    )

    assert response.status_code == 403
    assert queued == []


# --- a rule, where it is saved ----------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("network", INTERNAL_NETWORKS)
def test_a_rule_for_an_internal_range_is_not_stored(api, allow, network):
    response = api("post", _RULES, uuid.uuid4(), _rule_body([network]))

    assert response.status_code == 400, response.content[:300]
    (message,) = response.json()["target_specification"]
    assert "internal address" in message and ALLOWLIST_VARIABLE in message
    assert not AssetDiscoveryRule.objects.exists()


@pytest.mark.django_db
def test_one_internal_network_refuses_the_rule_that_lists_it(api, allow):
    body = _rule_body(["8.8.8.0/24", "8.8.4.0/24", "172.18.0.0/24"])

    response = api("post", _RULES, uuid.uuid4(), body)

    assert response.status_code == 400
    assert "172.18.0.0/24" in response.json()["target_specification"][0]
    assert not AssetDiscoveryRule.objects.exists()


@pytest.mark.django_db
def test_a_rule_cannot_be_edited_into_an_internal_range(api, allow):
    team = uuid.uuid4()
    created = api("post", _RULES, team, _rule_body(["8.8.8.0/24"]))
    assert created.status_code == 201, created.content[:300]
    url = f"{_RULES}{created.json()['id']}/"

    refused = api(
        "patch", url, team, {"target_specification": {"networks": ["10.0.0.0/24"]}}
    )

    assert refused.status_code == 400
    assert ALLOWLIST_VARIABLE in refused.json()["target_specification"][0]
    stored = AssetDiscoveryRule.objects.get().target_specification
    assert stored == {"networks": ["8.8.8.0/24"]}
    allow("10.0.0.0/24")
    assert (
        api(
            "patch", url, team, {"target_specification": {"networks": ["10.0.0.0/24"]}}
        ).status_code
        == 200
    )


# --- a discovery, where it runs ---------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("network", INTERNAL_NETWORKS)
def test_the_task_dials_nothing_in_an_internal_range_and_does_not_retry(
    allow, dialed, network
):
    """A task queued before the check, or before the operator narrowed the list."""
    result = tasks.discover_assets.apply(args=(network,))

    assert result.successful(), "a refusal is an answer, not a failure to retry"
    assert result.get()["status"] == "refused"
    assert ALLOWLIST_VARIABLE in result.get()["reason"]
    assert dialed == []
    assert not Asset.objects.exists()


@pytest.mark.django_db
def test_the_task_sweeps_a_public_range_and_what_the_operator_allows(
    allow, dialed, queued
):
    public = tasks.discover_assets.apply(args=("8.8.8.0/30",)).get()

    assert public["status"] == "completed"
    assert {host for host, _ in dialed} == {"8.8.8.1", "8.8.8.2"}

    del dialed[:]
    allow("10.20.0.0/16")
    lab = tasks.discover_assets.apply(args=("10.20.0.0/30",)).get()

    assert lab["status"] == "completed"
    assert {host for host, _ in dialed} == {"10.20.0.1", "10.20.0.2"}


@pytest.mark.django_db
def test_a_task_queued_under_a_wider_list_is_refused_under_a_narrower_one(
    allow, dialed
):
    allow("10.20.0.0/16")
    assert tasks.discover_assets.apply(args=("10.20.0.0/30",)).get()["status"] == (
        "completed"
    )
    del dialed[:]

    allow("10.20.1.0/24")
    result = tasks.discover_assets.apply(args=("10.20.0.0/30",)).get()

    assert result["status"] == "refused"
    assert dialed == []


@pytest.mark.django_db
def test_a_rule_stored_before_the_check_queues_only_what_may_be_swept(allow, queued):
    rule = tf.make(AssetDiscoveryRule, uuid.uuid4())
    AssetDiscoveryRule.objects.filter(pk=rule.pk).update(
        target_specification={
            "networks": [
                "127.0.0.0/30",
                "8.8.8.0/30",
                "172.18.0.0/24",
                "169.254.169.254/32",
                "192.0.0.0/22",
            ]
        }
    )

    result = tasks.execute_discovery_rule.apply(args=(rule.pk,)).get()

    assert result["networks_queued"] == 1
    assert [(name, args[0]) for name, args, _ in queued] == [("discover", "8.8.8.0/30")]


@pytest.mark.django_db
def test_a_comprehensive_discovery_scans_only_hosts_of_a_range_that_passed(
    allow, dialed, queued
):
    """The port scans a discovery queues are of the hosts it was allowed to find."""
    refused = tasks.discover_assets.apply(args=("10.0.0.0/30", "comprehensive")).get()

    assert refused["status"] == "refused"
    assert queued == [] and dialed == []


# --- a port scan, where it is asked for ---------------------------------------------------


def _asset(team, address):
    with mock.patch("apps.assets.signals.scan_asset_ports"):
        return tf.asset(team, ip_address=address, asset_type="server")


@pytest.mark.django_db
@pytest.mark.parametrize("address", INTERNAL_ADDRESSES)
def test_scan_refuses_an_asset_at_an_internal_address_and_queues_nothing(
    api, allow, queued, address
):
    team = uuid.uuid4()
    asset = _asset(team, address)

    response = api("post", f"{_ASSETS}{asset.pk}/scan/", team)

    assert response.status_code == 400, response.content[:300]
    message = response.json()["error"]
    assert "is an internal address" in message
    assert ALLOWLIST_VARIABLE in message
    assert "task_id" not in response.json()
    assert queued == []


@pytest.mark.django_db
def test_scan_queues_a_public_asset_and_one_the_operator_allows(api, allow, queued):
    team = uuid.uuid4()
    public = _asset(team, PUBLIC_ADDRESS)
    lab = _asset(team, "192.168.50.7")

    assert api("post", f"{_ASSETS}{public.pk}/scan/", team).status_code == 200
    assert api("post", f"{_ASSETS}{lab.pk}/scan/", team).status_code == 400
    allow("192.168.50.0/24")
    assert api("post", f"{_ASSETS}{lab.pk}/scan/", team).status_code == 200
    assert [(name, args) for name, args, _ in queued] == [
        ("scan", (str(public.pk),)),
        ("scan", (str(lab.pk),)),
    ]


# --- an asset is recorded wherever it is; it is scanned only where allowed ------------------


@pytest.mark.django_db
@pytest.mark.parametrize("address", INTERNAL_ADDRESSES)
def test_an_asset_at_an_internal_address_is_recorded_and_not_scanned(
    api, allow, queued, address
):
    """An inventory lists internal hosts: that is most of what it is for."""
    team = uuid.uuid4()
    body = {"name": "db-01", "asset_type": "server", "ip_address": address}

    response = api("post", _ASSETS, team, body)

    assert response.status_code == 201, response.content[:300]
    # The API stores an IPv4-mapped address as the IPv4 address it carries.
    mapped = shared.embedded_ipv4(ipaddress.ip_address(address))
    assert Asset.objects.get().ip_address == (str(mapped) if mapped else address)
    assert queued == []


@pytest.mark.django_db
def test_a_new_asset_is_scanned_when_its_address_may_be(api, allow, queued):
    team = uuid.uuid4()

    for name, address in (("web-01", PUBLIC_ADDRESS), ("db-01", "192.168.50.7")):
        body = {"name": name, "asset_type": "server", "ip_address": address}
        assert api("post", _ASSETS, team, body).status_code == 201
    public = Asset.objects.get(name="web-01")
    assert [(name, args) for name, args, _ in queued] == [("scan", (public.pk,))]

    allow("192.168.50.0/24")
    body = {"name": "db-02", "asset_type": "server", "ip_address": "192.168.50.8"}
    assert api("post", _ASSETS, team, body).status_code == 201
    assert queued[-1][1] == (Asset.objects.get(name="db-02").pk,)
    assert len(queued) == 2


# --- a port scan, where it runs -----------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("address", INTERNAL_ADDRESSES)
def test_the_port_scan_dials_nothing_at_an_internal_address(allow, dialed, address):
    """An asset stored before the check, or a scan queued by any other path."""
    asset = _asset(uuid.uuid4(), address)

    result = tasks.scan_asset_ports.apply(args=(str(asset.pk),)).get()

    assert result["status"] == "refused"
    assert ALLOWLIST_VARIABLE in result["reason"]
    assert dialed == []
    assert not asset.ports.exists()


@pytest.mark.django_db
def test_the_port_scan_runs_for_a_public_asset_and_one_the_operator_allows(
    allow, dialed
):
    team = uuid.uuid4()
    public = _asset(team, PUBLIC_ADDRESS)
    lab = _asset(team, "192.168.50.7")

    assert tasks.scan_asset_ports.apply(args=(str(public.pk),)).get()["status"] == (
        "completed"
    )
    assert {host for host, _ in dialed} == {PUBLIC_ADDRESS}

    assert (
        tasks.scan_asset_ports.apply(args=(str(lab.pk),)).get()["status"] == "refused"
    )
    allow("192.168.50.7")
    assert tasks.scan_asset_ports.apply(args=(str(lab.pk),)).get()["status"] == (
        "completed"
    )
    assert {host for host, _ in dialed} == {PUBLIC_ADDRESS, "192.168.50.7"}


def test_an_address_that_is_not_one_is_not_handed_to_the_socket(allow):
    for value in (
        "fe80::1%eth0",
        "8.8.8.8%eth0",
        "example.com",
        "8.8.8.8 ; id",
        "x" * 500,
    ):
        address, refusal = check_address(value)
        assert address is None
        assert refusal.endswith("is not an IP address.")
        assert len(refusal) < 100
    assert check_address(None) == (None, "The asset has no IP address to scan.")
    assert check_address("") == (None, "The asset has no IP address to scan.")
    # A zone names an interface of the worker; ipaddress would have taken it.
    network, refusal = check_network("fe80::%eth0/120")
    assert network is None and "is not a network" in refusal


# --- every place guardian connects out ------------------------------------------------------

# The modules of guardian that can open a connection, and why the scan
# target policy applies to each or does not. A module that starts importing
# one of these libraries fails the test below until it is reviewed here.
_CONNECTING = ("socket", "requests", "urllib.request", "http.client", "smtplib")
_CONNECTING += ("httpx", "aiohttp", "urllib3", "ftplib", "telnetlib", "subprocess")
_CONNECTING += ("nmap", "paramiko", "pytenable", "ssl", "asyncio", "xmlrpc")
REVIEWED_CONNECTIONS = {
    "apps/assets/tasks.py": (
        "socket: host probes, port scans and banner reads of addresses a team "
        "names. The policy applies: discover_assets and scan_asset_ports check "
        "the target before anything is dialed."
    ),
    "apps/core/notifications.py": (
        "requests: one POST to identity's team-contacts route, at "
        "GUARDIAN_TEAM_CONTACTS_URL, which the operator sets and no request "
        "can. Not a caller's target."
    ),
    "apps/core/management/commands/import_vulnerabilities.py": (
        "requests: a management command the operator runs in the container, "
        "with a URL given on its command line. No API route reaches it."
    ),
}


def _connecting_imports(path):
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and not node.level:
            names = [node.module or ""]
        for name in names:
            for library in _CONNECTING:
                if name == library or name.startswith(library + "."):
                    found.add(library)
    return found


def test_every_module_that_can_connect_out_has_been_reviewed():
    """Three modules can, and one of them dials what a team names.

    So nothing fetches the URLs a team stores (a scanner's or an external
    system's base_url, a framework's website, a ticket's external_url):
    they are records since #715 and #731 removed the code that connected to
    them, and no module that holds them can open a connection.
    """
    connecting = {}
    for directory in ("apps", "guardian"):
        for path in sorted((GUARDIAN_DIR / directory).rglob("*.py")):
            relative = path.relative_to(GUARDIAN_DIR).as_posix()
            if "/migrations/" in relative or "/tests/" in relative:
                continue
            found = _connecting_imports(path)
            if found:
                connecting[relative] = found

    assert set(connecting) == set(REVIEWED_CONNECTIONS), connecting
    assert connecting["apps/assets/tasks.py"] == {"socket"}


def test_the_scanner_dials_only_from_the_two_tasks_that_check_the_target():
    """_host_is_up, _scan_port and _detect_service open the sockets; each is
    called from one task, after its check."""
    tree = ast.parse((GUARDIAN_DIR / "apps/assets/tasks.py").read_text("utf-8"))
    callers = {}
    for function in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(function):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                callers.setdefault(node.func.id, set()).add(function.name)

    assert callers["_host_is_up"] == {"discover_assets"}
    assert callers["_scan_port"] == {"scan_asset_ports"}
    assert callers["_detect_service"] == {"scan_asset_ports"}
    assert callers["scan_network"] >= {"discover_assets", "_execute_network_scan"}
    assert callers["check_address"] == {"scan_asset_ports"}
