"""The registered network scanner (app/tools/network_scanner/main.py).

Every run used to fail before the first probe (#615): ping_host indexed the
boolean that its stub target check returned (``scan_validation['allowed']``),
the TypeError escaped, and execute_tool's gather swallowed it, so each scan
reported no hosts at all. Here ``ping`` and TCP connections are replaced, and
what is checked is what the scanner decides: which hosts and ports it probes,
how, and what it reports.
"""

import asyncio
import os
import sys

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.tools.network_scanner import main  # noqa: E402
from app.tools.network_scanner.schemas import (  # noqa: E402
    NetworkScannerInput,
    NetworkScannerOutput,
)

PING = "/usr/bin/ping"
SCAN_DEADLINE = 10


class FakeProcess:
    def __init__(self, returncode, hang=False):
        self.returncode = returncode
        self.hang = hang
        self.killed = False

    async def communicate(self):
        if self.hang:
            await asyncio.sleep(3600)
        return b"", b""

    def kill(self):
        self.killed = True

    async def wait(self):
        return self.returncode


class FakeWriter:
    def close(self):
        pass

    async def wait_closed(self):
        pass


class Network:
    """A fake network: which hosts answer ping, which ports accept."""

    def __init__(self, alive=(), open_ports=None, hang_ping=(), hang_ports=()):
        self.alive = set(alive)
        self.open_ports = open_ports or {}
        self.hang_ping = set(hang_ping)
        self.hang_ports = set(hang_ports)
        self.pings = []
        self.connects = []
        self.processes = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def create_subprocess_exec(self, *argv, **kwargs):
        assert "shell" not in kwargs
        self.pings.append(argv)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(0.01)
        finally:
            self.in_flight -= 1
        address = argv[-1]
        process = FakeProcess(
            0 if address in self.alive else 1, hang=address in self.hang_ping
        )
        self.processes.append(process)
        return process

    async def open_connection(self, host, port, **kwargs):
        self.connects.append((host, port))
        if (host, port) in self.hang_ports:
            await asyncio.sleep(3600)
        if port in self.open_ports.get(host, ()):
            return object(), FakeWriter()
        raise ConnectionRefusedError(f"{host}:{port} refused")


@pytest.fixture
def network(monkeypatch):
    fake = Network()
    monkeypatch.setattr(main.shutil, "which", lambda name: PING)
    monkeypatch.setattr(
        main.asyncio, "create_subprocess_exec", fake.create_subprocess_exec
    )
    monkeypatch.setattr(main.asyncio, "open_connection", fake.open_connection)

    def no_reverse_dns(address):
        raise main.socket.herror("no PTR record")

    monkeypatch.setattr(main.socket, "gethostbyaddr", no_reverse_dns)
    return fake


def scan(network, **options):
    # A probe left without its timeout fails the test instead of hanging it.
    result = asyncio.run(
        asyncio.wait_for(
            main.execute_tool(NetworkScannerInput(network=network, **options)),
            SCAN_DEADLINE,
        )
    )
    # Rebuilt from its own fields, so a field set after construction cannot
    # hide an invalid output.
    NetworkScannerOutput.model_validate(result.model_dump())
    return result


def pinged(fake):
    return sorted(argv[-1] for argv in fake.pings)


def by_address(result):
    return {host.ip_address: host for host in result.hosts}


def test_a_ping_scan_probes_each_host_and_reports_what_answered(network):
    network.alive = {"192.0.2.1", "192.0.2.3"}

    result = scan("192.0.2.0/29")

    assert result.success is True, result.error_message
    # .0 is the network address and .7 the broadcast address.
    expected = [f"192.0.2.{n}" for n in range(1, 7)]
    assert pinged(network) == expected
    hosts = by_address(result)
    assert sorted(hosts) == expected
    assert {a for a, h in hosts.items() if h.status == "alive"} == network.alive
    assert {h.status for a, h in hosts.items() if a not in network.alive} == {"dead"}
    assert result.total_hosts == 6
    assert result.alive_hosts == 2
    assert result.network == "192.0.2.0/29"
    assert network.connects == []


def test_ping_runs_without_a_shell_with_the_address_as_its_own_argument(network):
    network.alive = {"192.0.2.10"}

    result = scan("192.0.2.10", timeout=2)

    assert result.success is True, result.error_message
    assert network.pings == [(PING, "-c", "1", "-W", "2", "192.0.2.10")]
    assert by_address(result)["192.0.2.10"].status == "alive"


def test_a_tcp_scan_probes_the_common_ports_of_the_hosts_that_answer(network):
    network.alive = {"192.0.2.1"}
    network.open_ports = {"192.0.2.1": {22, 443}}

    result = scan("192.0.2.0/30", scan_type="tcp")

    assert result.success is True, result.error_message
    assert pinged(network) == ["192.0.2.1", "192.0.2.2"]
    # Every common port, 22 and 3389 included, on the live host only.
    assert sorted(network.connects) == [("192.0.2.1", p) for p in main.COMMON_PORTS]
    hosts = by_address(result)
    assert hosts["192.0.2.1"].open_ports == [22, 443]
    assert hosts["192.0.2.2"].status == "dead"
    assert hosts["192.0.2.2"].open_ports == []


def test_a_last_octet_range_is_scanned_host_by_host(network):
    result = scan("192.0.2.10-12")

    assert result.success is True, result.error_message
    assert pinged(network) == ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
    assert result.total_hosts == 3


def test_concurrency_is_bounded_by_max_threads(network):
    result = scan("192.0.2.0/28", max_threads=3)

    assert result.success is True, result.error_message
    assert len(network.pings) == 14
    assert network.max_in_flight == 3


@pytest.mark.parametrize(
    "target", ["10.0.0.0/16", "2001:db8::/64", "0.0.0.0/0", "10.0.0.0/21"]
)
def test_a_range_larger_than_the_limit_is_refused_before_any_probe(network, target):
    result = scan(target)

    assert result.success is False
    assert "too large" in result.error_message
    assert result.hosts == []
    assert network.pings == []


def test_the_largest_allowed_range_is_scanned(network):
    result = scan("10.0.0.0/22", max_threads=100)

    assert result.success is True, result.error_message
    assert len(network.pings) == 1022
    assert network.max_in_flight <= 100


@pytest.mark.parametrize(
    "target",
    ["example.com", "192.0.2.1; id", "-c 1000 192.0.2.1", "192.0.2.300", "192.0.2.9-3"],
)
def test_anything_but_an_address_range_or_cidr_is_refused(network, target):
    result = scan(target)

    assert result.success is False
    assert "Invalid network" in result.error_message
    assert network.pings == []


def test_a_ping_that_does_not_return_is_killed_and_reported(network, monkeypatch):
    monkeypatch.setattr(main, "PING_GRACE_SECONDS", 0)
    network.hang_ping = {"192.0.2.1"}

    result = scan("192.0.2.1", timeout=1)

    assert result.success is True, result.error_message
    assert by_address(result)["192.0.2.1"].status == "timeout"
    assert network.processes[0].killed is True


def test_a_port_that_does_not_answer_is_not_reported_open(network):
    network.alive = {"192.0.2.1"}
    network.open_ports = {"192.0.2.1": {80}}
    network.hang_ports = {("192.0.2.1", 8080)}

    result = scan("192.0.2.1", scan_type="tcp", timeout=1)

    assert result.success is True, result.error_message
    assert by_address(result)["192.0.2.1"].open_ports == [80]


def test_a_missing_ping_binary_fails_the_scan_with_an_actionable_error(
    network, monkeypatch
):
    monkeypatch.setattr(main.shutil, "which", lambda name: None)

    result = scan("192.0.2.0/30")

    assert result.success is False
    assert "iputils-ping" in result.error_message
    assert network.pings == []
