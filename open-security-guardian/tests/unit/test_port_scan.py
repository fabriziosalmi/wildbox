"""A port scan reaches an IPv6 asset, and tries a bounded set of ports (#775).

Two things about ``scan_asset_ports``, found by the work on the scan target
policy (#748) and left out of it:

* ``_scan_port`` and ``_detect_service`` opened ``AF_INET`` sockets whatever
  the address. Connecting one to an IPv6 address fails before a packet
  leaves, the failure was caught and read as "closed", and so the scan of an
  IPv6 asset completed with every port closed. ``_host_is_up`` already chose
  the family by the address; the two now do, from the address the target
  check returned.
* ``port_range`` was parsed with ``int`` and nothing else: ``"1-4000000000"``
  was that many connection attempts in one task, ``"0-70000"`` handed the
  socket ports that do not exist, and ``"http"`` failed the task with a
  ValueError. No route passes the argument today; the task checks it all the
  same, as it checks the address whoever queued it.

The policy still decides what is dialed: an internal IPv6 address is refused
before a socket exists, here as for IPv4.

The socket is a stand-in that refuses what the kernel refuses (an address of
the other family) and records the rest; one test listens on the IPv6
loopback for real.
"""

import errno
import ipaddress
import socket
import uuid
from unittest import mock

import pytest
from apps.assets import networks, tasks
from apps.assets.models import Asset, AssetPort
from apps.assets.networks import MAX_PORT, MAX_SCAN_PORTS, check_port_range
from guardian.scan_targets import ALLOWLIST_VARIABLE, allowed_internal_targets

from tests.unit import team_fixtures as tf

PUBLIC_V4 = "93.184.215.14"
PUBLIC_V6 = "2606:2800:21f:cb07:6820:80da:af6b:8b2c"
COMMON_PORTS = 19

# Internal IPv6 addresses, and IPv4 ones written inside an IPv6 address.
INTERNAL_V6 = [
    "::1",
    "fe80::1",
    "fd00::c2b6:a9ff:fe52:2ea5",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.5",
    "::ffff:169.254.169.254",
    "2002:a00:5::1",
    "64:ff9b::a00:5",
]


class _Network:
    """Sockets as tasks.py uses them, over hosts that exist only here."""

    def __init__(self):
        self.listening = set()  # (host, port) that accept a connection
        self.sockets = []  # every socket created: its family
        self.dialed = []  # (family, host, port) of every connection attempt

    def socket(self, family=socket.AF_INET, kind=socket.SOCK_STREAM, *args):
        self.sockets.append(family)
        return _Socket(self, family)


class _Socket:
    def __init__(self, network, family):
        self.network, self.family = network, family

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, value):
        pass

    def close(self):
        pass

    def _reaches(self, address):
        host, port = address[0], address[1]
        version = ipaddress.ip_address(host).version
        if (self.family == socket.AF_INET6) != (version == 6):
            # What connecting a socket of one family to an address of the
            # other answers, before anything is sent.
            raise socket.gaierror(
                socket.EAI_ADDRFAMILY, "Address family for hostname not supported"
            )
        assert 0 < port <= 65535, port
        self.network.dialed.append((self.family, host, port))
        return (host, port) in self.network.listening

    def connect_ex(self, address):
        return 0 if self._reaches(address) else errno.ECONNREFUSED

    def connect(self, address):
        if not self._reaches(address):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

    def recv(self, size):
        return b"SSH-2.0-OpenSSH_9.6\r\n"


@pytest.fixture
def network(monkeypatch):
    stand_in = _Network()
    monkeypatch.setattr(tasks.socket, "socket", stand_in.socket)
    return stand_in


@pytest.fixture
def allow(settings):
    """The operator's list, empty to begin with as in a deployment."""

    def set_allowlist(raw):
        settings.SCAN_ALLOWED_INTERNAL_TARGETS = allowed_internal_targets(
            {ALLOWLIST_VARIABLE: raw}
        )

    set_allowlist("")
    return set_allowlist


def _asset(address):
    """An asset at ``address``, stored as it is given and not scanned yet."""
    with mock.patch("apps.assets.signals.scan_asset_ports"):
        asset = tf.asset(uuid.uuid4(), asset_type="server")
    # As a row stored by another path than the API, which rewrites an
    # IPv4-mapped address as the IPv4 address it carries.
    Asset.objects.filter(pk=asset.pk).update(ip_address=address)
    asset.refresh_from_db()
    assert asset.ip_address == address
    return asset


def _scan(asset, *args):
    return tasks.scan_asset_ports.apply(args=(str(asset.pk), *args)).get()


# --- the family of the address ----------------------------------------------------------


@pytest.mark.django_db
def test_an_ipv6_asset_is_scanned_over_ipv6(allow, network):
    """Every port of it was closed: the sockets were IPv4 ones."""
    asset = _asset(PUBLIC_V6)
    network.listening = {(PUBLIC_V6, 22), (PUBLIC_V6, 443)}

    result = _scan(asset)

    assert result["status"] == "completed"
    assert result["ports_scanned"] == COMMON_PORTS
    assert result["new_open_ports"] == 2
    found = {port.port_number: port for port in AssetPort.objects.filter(asset=asset)}
    assert sorted(found) == [22, 443]
    assert found[22].service == "ssh" and found[22].banner == "SSH-2.0-OpenSSH_9.6"
    assert found[443].service == "https"
    # One probe for each port, and one more to read the banner of an open one.
    assert set(network.sockets) == {socket.AF_INET6}
    assert len(network.dialed) == COMMON_PORTS + 2
    assert {(family, host) for family, host, _ in network.dialed} == {
        (socket.AF_INET6, PUBLIC_V6)
    }


@pytest.mark.django_db
def test_an_ipv4_asset_is_scanned_over_ipv4_as_before(allow, network):
    asset = _asset(PUBLIC_V4)
    network.listening = {(PUBLIC_V4, 80)}

    result = _scan(asset)

    assert result["status"] == "completed" and result["new_open_ports"] == 1
    assert AssetPort.objects.get(asset=asset).port_number == 80
    assert set(network.sockets) == {socket.AF_INET}
    assert len(network.dialed) == COMMON_PORTS + 1


@pytest.mark.django_db
def test_an_ipv4_address_inside_an_ipv6_one_is_dialed_as_it_was_checked(allow, network):
    """A public IPv4-mapped address is an IPv6 address: an IPv6 socket."""
    asset = _asset("::ffff:93.184.215.14")

    assert _scan(asset, "443")["status"] == "completed"

    ((family, host, port),) = network.dialed
    assert family == socket.AF_INET6 and port == 443
    assert ipaddress.ip_address(host) == ipaddress.ip_address("::ffff:93.184.215.14")


@pytest.mark.django_db
def test_an_ipv6_port_that_listens_is_found_open():
    """For real, on the loopback: no stand-in between the task and the kernel."""
    try:
        listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        pytest.skip("this host has no IPv6")
    with listener:
        try:
            listener.bind(("::1", 0))
        except OSError:
            pytest.skip("this host has no IPv6 loopback")
        listener.listen(5)
        port = listener.getsockname()[1]
        asset = _asset("::1")

        with mock.patch.object(
            networks.settings,
            "SCAN_ALLOWED_INTERNAL_TARGETS",
            allowed_internal_targets({ALLOWLIST_VARIABLE: "::1"}),
        ):
            result = _scan(asset, str(port))

    assert result == {
        "status": "completed",
        "asset_name": asset.name,
        "ports_scanned": 1,
        "new_open_ports": 1,
    }
    assert AssetPort.objects.get(asset=asset).port_number == port


# --- the policy decides, for IPv6 too -------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("address", INTERNAL_V6)
def test_no_socket_is_opened_for_an_internal_ipv6_address(allow, network, address):
    asset = _asset(address)

    result = _scan(asset)

    assert result["status"] == "refused"
    assert "is an internal address" in result["reason"]
    assert ALLOWLIST_VARIABLE in result["reason"]
    assert network.sockets == [] and network.dialed == []
    assert not AssetPort.objects.exists()


@pytest.mark.django_db
def test_an_internal_ipv6_range_is_scanned_once_the_operator_lists_it(allow, network):
    inside, outside = _asset("fd00:50::7"), _asset("fd00:51::7")
    network.listening = {("fd00:50::7", 22)}
    allow("fd00:50::/64")

    assert _scan(inside)["new_open_ports"] == 1
    assert _scan(outside)["status"] == "refused"

    assert {host for _, host, _ in network.dialed} == {"fd00:50::7"}
    assert set(network.sockets) == {socket.AF_INET6}


@pytest.mark.django_db
def test_an_ipv4_entry_does_not_open_the_same_range_written_in_ipv6(allow, network):
    """By design (tests/shared/target_policy_vectors.json): each spelling is
    listed, or it is refused. The deployment guide tells the operator."""
    plain, mapped = _asset("10.20.3.4"), _asset("::ffff:10.20.3.4")

    allow("10.20.0.0/16")
    assert _scan(plain, "22")["status"] == "completed"
    assert _scan(mapped, "22")["status"] == "refused"
    assert network.dialed == [(socket.AF_INET, "10.20.3.4", 22)]

    del network.dialed[:]
    allow("10.20.0.0/16,::ffff:10.20.0.0/112")
    assert _scan(mapped, "22")["status"] == "completed"
    ((family, host, port),) = network.dialed
    assert family == socket.AF_INET6 and port == 22
    assert ipaddress.ip_address(host) == ipaddress.ip_address("::ffff:10.20.3.4")


# --- the ports of a scan ----------------------------------------------------------------

GOOD_RANGES = [
    ("443", [443]),
    ("1", [1]),
    ("65535", [65535]),
    (" 22 ", [22]),
    ("22\n", [22]),
    ("8000-8002", [8000, 8001, 8002]),
    ("80-80", [80]),
    ("00080", [80]),
]

BAD_RANGES = [
    # Not a port number.
    "0",
    "65536",
    "99999",
    "0-10",
    "1-65536",
    "65535-65536",
    # More than one scan tries, however it is written.
    f"1-{MAX_SCAN_PORTS + 1}",
    "1-65535",
    "1-4000000000",
    "100000000000000000000-100000000000000000001",
    # Backwards.
    "10-1",
    "443-80",
    # Not a range.
    "http",
    "-",
    "-1",
    "1-",
    "-5",
    "1-2-3",
    "1--5",
    "1,2",
    "1 - 5",
    "1 5",
    "22;id",
    "1e3",
    "0x50",
    # What int() takes and a port number is not written as.
    "+80",
    "1_000",
    "８０",
    "٨٠",
    "80\x00",
    "80\n81",
    # Not text.
    443,
    80.0,
    True,
    b"80",
    ["80"],
    {"start": 1, "end": 5},
]


@pytest.mark.parametrize(("value", "expected"), GOOD_RANGES)
def test_a_port_or_a_range_is_taken(value, expected):
    ports, refusal = check_port_range(value)

    assert refusal is None
    assert list(ports) == expected


def test_a_range_holds_as_many_ports_as_one_scan_tries():
    ports, refusal = check_port_range(f"1-{MAX_SCAN_PORTS}")
    assert refusal is None and len(ports) == MAX_SCAN_PORTS

    top = f"{MAX_PORT - MAX_SCAN_PORTS + 1}-{MAX_PORT}"
    ports, refusal = check_port_range(top)
    assert refusal is None and len(ports) == MAX_SCAN_PORTS
    assert ports[-1] == MAX_PORT

    ports, refusal = check_port_range(f"2-{MAX_SCAN_PORTS + 2}")
    assert ports is None
    assert str(MAX_SCAN_PORTS) in refusal and "Split it" in refusal
    # An unanswered port costs the scan a second; a task has thirty minutes.
    assert MAX_SCAN_PORTS * 1 < tasks.settings.CELERY_TASK_TIME_LIMIT


@pytest.mark.parametrize("value", BAD_RANGES, ids=repr)
def test_anything_else_is_refused_with_a_message_of_guardians_own(value):
    ports, refusal = check_port_range(value)

    assert ports is None
    # Written here, and short whatever was sent.
    assert isinstance(refusal, str) and 20 < len(refusal) < 160


def test_each_refusal_says_what_is_wrong():
    assert "from 1 to 65535" in check_port_range("0")[1]
    assert "from 1 to 65535" in check_port_range("1-65536")[1]
    assert "ends before it starts" in check_port_range("10-1")[1]
    assert "more than 1024 ports" in check_port_range("1-1025")[1]
    assert "for example 443 or 1-1000" in check_port_range("http")[1]
    assert "for example 443 or 1-1000" in check_port_range("1-4000000000")[1]


@pytest.mark.django_db
@pytest.mark.parametrize("value", BAD_RANGES, ids=repr)
def test_the_task_refuses_a_bad_range_and_dials_nothing(allow, network, value):
    asset = _asset(PUBLIC_V4)

    result = tasks.scan_asset_ports.apply(args=(str(asset.pk), value))

    assert result.successful(), "a refusal is an answer, not a failure to retry"
    assert result.get() == {"status": "refused", "reason": check_port_range(value)[1]}
    assert network.sockets == [] and network.dialed == []
    assert not AssetPort.objects.exists()


@pytest.mark.django_db
def test_the_task_scans_the_ports_of_a_good_range_and_no_other(allow, network):
    asset = _asset(PUBLIC_V4)
    network.listening = {(PUBLIC_V4, 8001), (PUBLIC_V4, 8003)}

    result = _scan(asset, "8000-8002")

    assert result["ports_scanned"] == 3 and result["new_open_ports"] == 1
    assert sorted({port for _, _, port in network.dialed}) == [8000, 8001, 8002]
    assert AssetPort.objects.get(asset=asset).port_number == 8001


@pytest.mark.django_db
@pytest.mark.parametrize("unset", [None, ""])
def test_without_a_range_the_common_ports_are_scanned_as_before(allow, network, unset):
    asset = _asset(PUBLIC_V4)

    result = _scan(asset, unset)

    assert result["status"] == "completed"
    assert result["ports_scanned"] == COMMON_PORTS
    assert len({port for _, _, port in network.dialed}) == COMMON_PORTS


@pytest.mark.django_db
def test_the_address_is_checked_before_the_range(allow, network):
    """An internal asset is refused for its address, whatever the range says."""
    asset = _asset("10.0.0.5")

    for value in ("443", "http", "1-4000000000"):
        result = _scan(asset, value)
        assert result["status"] == "refused"
        assert ALLOWLIST_VARIABLE in result["reason"]
    assert network.sockets == []


# --- a probe that fails, and its socket (#788) ----------------------------------------
#
# ``_scan_port`` closed its socket after ``connect_ex`` returned, so not when
# it raised; and it read every error as "closed", a network it could not
# reach like a port that refused. The result of a scan has no place for the
# difference yet (#787): the socket is always closed, and what is not about
# the port is logged, once for the scan.


class _Probe:
    """One socket: what its connection ends with, and whether it was closed."""

    def __init__(self, outcome):
        self.outcome, self.closed = outcome, False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def settimeout(self, value):
        pass

    def close(self):
        self.closed = True

    def connect_ex(self, address):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    def connect(self, address):
        code = self.connect_ex(address)
        if code:
            raise OSError(code, "not connected")

    def recv(self, size):
        return b""


@pytest.fixture
def probes(monkeypatch):
    """Every socket tasks.py opens ends as ``probes.outcome`` says."""

    class Probes(list):
        outcome = errno.ECONNREFUSED

        def socket(self, *args):
            self.append(_Probe(self.outcome))
            return self[-1]

    made = Probes()
    monkeypatch.setattr(tasks.socket, "socket", made.socket)
    return made


ADDRESS = ipaddress.ip_address(PUBLIC_V4)

RAISED = [
    OSError(errno.ENETUNREACH, "Network is unreachable"),
    socket.gaierror(socket.EAI_NONAME, "Name or service not known"),
    OverflowError("connect_ex(): port must be 0-65535."),
    RuntimeError("anything else"),
]


@pytest.mark.parametrize("raised", RAISED, ids=lambda error: type(error).__name__)
def test_the_socket_is_closed_when_the_connection_raises(probes, raised):
    probes.outcome = raised

    assert tasks._scan_port(ADDRESS, 443) is False

    (probe,) = probes
    assert probe.closed


@pytest.mark.parametrize("code", [0, errno.ECONNREFUSED, errno.EHOSTUNREACH])
def test_the_socket_is_closed_when_the_connection_returns(probes, code):
    probes.outcome = code

    assert tasks._scan_port(ADDRESS, 443) is (code == 0)

    (probe,) = probes
    assert probe.closed


@pytest.mark.parametrize("raised", [None, *RAISED], ids=repr)
def test_the_banner_probes_socket_is_closed_too(probes, raised):
    probes.outcome = raised or 0

    tasks._detect_service(ADDRESS, 443)

    (probe,) = probes
    assert probe.closed


NOT_OPEN = [errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK]
NOT_THE_PORT = [
    (errno.ENETUNREACH, "ENETUNREACH"),
    (errno.EHOSTUNREACH, "EHOSTUNREACH"),
    (errno.EACCES, "EACCES"),
    (OSError(errno.EMFILE, "Too many open files"), "EMFILE"),
    # The number a resolver's error carries is not an errno: by its class.
    (socket.gaierror(socket.EAI_NONAME, "Name or service not known"), "gaierror"),
    (RuntimeError("redis://:hunter2@broker:6379/1"), "RuntimeError"),
]


@pytest.mark.parametrize("code", NOT_OPEN, ids=lambda code: errno.errorcode[code])
def test_a_port_that_refuses_or_does_not_answer_is_not_open_and_not_a_failure(
    probes, code
):
    probes.outcome = code
    failures = {}

    assert tasks._scan_port(ADDRESS, 443, failures=failures) is False
    assert failures == {}


@pytest.mark.parametrize(("outcome", "reason"), NOT_THE_PORT, ids=lambda v: str(v)[:24])
def test_an_error_that_is_not_about_the_port_is_counted_by_its_name(
    probes, outcome, reason
):
    probes.outcome = outcome
    failures = {}

    for port in (22, 80, 443):
        assert tasks._scan_port(ADDRESS, port, failures=failures) is False

    assert failures == {reason: 3}


def _scan_log(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.name == "apps.assets.tasks" and record.levelname == "WARNING"
    ]


@pytest.mark.django_db
def test_a_scan_that_could_not_reach_the_host_says_so_once(allow, probes, caplog):
    """Nineteen ports, one line: and the result is the one it was."""
    asset = _asset(PUBLIC_V4)
    probes.outcome = errno.ENETUNREACH

    with caplog.at_level("DEBUG", logger="apps.assets.tasks"):
        result = _scan(asset)

    assert result == {
        "status": "completed",
        "asset_name": asset.name,
        "ports_scanned": COMMON_PORTS,
        "new_open_ports": 0,
    }
    (line,) = _scan_log(caplog)
    assert f"{COMMON_PORTS} of {COMMON_PORTS} ports could not be tried" in line
    assert f"ENETUNREACH x{COMMON_PORTS}" in line and asset.name in line
    assert all(probe.closed for probe in probes) and len(probes) == COMMON_PORTS
    assert not AssetPort.objects.exists()


@pytest.mark.django_db
def test_the_line_holds_the_name_of_an_error_and_not_its_text(allow, probes, caplog):
    asset = _asset(PUBLIC_V4)
    probes.outcome = RuntimeError("redis://:hunter2@broker:6379/1")

    with caplog.at_level("DEBUG", logger="apps.assets.tasks"):
        assert _scan(asset, "443")["status"] == "completed"

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "RuntimeError x1" in logged
    assert "hunter2" not in logged and "broker" not in logged


@pytest.mark.django_db
@pytest.mark.parametrize("code", NOT_OPEN, ids=lambda code: errno.errorcode[code])
def test_a_scan_of_closed_ports_logs_no_failure(allow, probes, caplog, code):
    asset = _asset(PUBLIC_V4)
    probes.outcome = code

    with caplog.at_level("DEBUG", logger="apps.assets.tasks"):
        assert _scan(asset)["new_open_ports"] == 0

    assert _scan_log(caplog) == []


# --- the name of a host found at an address (#788) --------------------------------------


@pytest.mark.parametrize(
    ("address", "name"),
    [
        ("93.184.215.14", "host-93-184-215-14"),
        ("10.0.0.5", "host-10-0-0-5"),
        (PUBLIC_V6, "host-2606-2800-021f-cb07-6820-80da-af6b-8b2c"),
        ("2001:db8::1", "host-2001-0db8-0000-0000-0000-0000-0000-0001"),
        ("2001:db8::", "host-2001-0db8-0000-0000-0000-0000-0000-0000"),
        ("::ffff:93.184.215.14", "host-0000-0000-0000-0000-0000-ffff-5db8-d70e"),
    ],
)
def test_a_host_without_a_name_is_named_after_its_address(address, name):
    """An IPv4 host as it always was; an IPv6 one without its colons."""
    assert tasks._host_name(address) == name
    # A label a host name could hold: letters, digits and hyphens, at most
    # 63 of them, neither first nor last a hyphen.
    assert len(name) <= 63 and name == name.strip("-")
    assert set(name) <= set("abcdefghijklmnopqrstuvwxyz0123456789-")


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("address", "name"),
    [
        (PUBLIC_V4, "host-93-184-215-14"),
        (PUBLIC_V6, "host-2606-2800-021f-cb07-6820-80da-af6b-8b2c"),
    ],
)
def test_a_discovered_host_is_stored_under_that_name(address, name):
    team = uuid.uuid4()

    # No name resolves, and the scan a new asset queues needs no broker.
    with mock.patch.object(tasks, "_resolve_hostname", return_value=None):
        with mock.patch("apps.assets.signals.scan_asset_ports"):
            asset, created = tasks._discover_host(address, "basic", str(team))

    assert created and asset.name == name and ":" not in asset.name
    assert asset.ip_address == address and asset.hostname == ""
    assert str(asset.team_id) == str(team)


@pytest.mark.django_db
def test_a_host_stored_under_the_old_name_keeps_it(network):
    """The team's asset at an address is found by the address: a host named
    with its colons before is seen again, not renamed and not stored twice."""
    team = uuid.uuid4()
    old = f"host-{PUBLIC_V6}"
    with mock.patch("apps.assets.signals.scan_asset_ports"):
        Asset.objects.create(team_id=team, name=old, ip_address=PUBLIC_V6)

    with mock.patch.object(tasks, "_resolve_hostname", return_value=None):
        asset, created = tasks._discover_host(PUBLIC_V6, "basic", str(team))

    assert not created and asset.name == old
    assert Asset.objects.filter(team_id=team).count() == 1
