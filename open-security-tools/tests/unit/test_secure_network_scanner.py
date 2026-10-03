"""The CIDR-bounded network scanner (secure_scan.py).

Moved from tests/tools/test_network_scanner.py, which no CI job collected
(#582). That version sent real pings, so its result depended on the network
the runner sat on; here ``ping`` is replaced, and what is checked is what the
scanner decides: which addresses it pings, how, and what it refuses.
"""

import asyncio

import pytest
from app.tools.network_scanner import secure_scan
from app.tools.network_scanner.secure_scan_schemas import SecureNetworkScannerInput


class FakeProcess:
    def __init__(self, returncode):
        self.returncode = returncode

    async def communicate(self):
        return b"", b""


@pytest.fixture
def pings(monkeypatch):
    """Record every ping the scanner starts; only 127.0.0.1 answers."""
    started = []

    async def create_subprocess_exec(*argv, **kwargs):
        started.append(argv)
        return FakeProcess(0 if argv[-1] == "127.0.0.1" else 1)

    monkeypatch.setattr(
        secure_scan.asyncio, "create_subprocess_exec", create_subprocess_exec
    )
    return started


def scan(network, **options):
    return asyncio.run(
        secure_scan.execute_secure_scanner(
            SecureNetworkScannerInput(network=network, **options)
        )
    )


def test_a_single_address_is_pinged_and_reported_alive(pings):
    result = scan("127.0.0.1")
    assert result.success is True
    assert [host.ip_address for host in result.hosts] == ["127.0.0.1"]
    assert result.hosts[0].status == "alive"
    assert "Found 1 alive hosts out of 1" in result.summary


def test_a_small_network_pings_its_host_addresses_only(pings):
    result = scan("192.168.255.0/30")
    assert result.success is True
    # .0 is the network address and .3 the broadcast address.
    assert sorted(argv[-1] for argv in pings) == ["192.168.255.1", "192.168.255.2"]
    assert [host.status for host in result.hosts] == ["unreachable", "unreachable"]
    assert "Found 0 alive hosts out of 2" in result.summary


def test_a_network_larger_than_the_limit_is_refused_before_any_ping(pings):
    # A /21 holds 2048 addresses; the limit is 1024.
    result = scan("192.168.0.0/21")
    assert result.success is False
    assert "Network is too large" in result.error
    assert result.hosts == []
    assert pings == []


def test_the_largest_allowed_network_is_scanned(pings):
    result = scan("10.0.0.0/22", max_concurrent_scans=200)
    assert result.success is True
    assert len(pings) == 1022


@pytest.mark.parametrize(
    "network",
    ["example.com", "127.0.0.1; id", "10.0.0.0/33", "-c 1000 127.0.0.1"],
)
def test_anything_but_an_address_or_cidr_is_refused_before_any_ping(pings, network):
    result = scan(network)
    assert result.success is False
    assert "Invalid network format" in result.error
    assert pings == []


def test_ping_runs_without_a_shell_with_the_address_as_one_argument(pings):
    host = asyncio.run(secure_scan.ping_host("127.0.0.1", 2))
    assert pings == [("ping", "-c", "1", "-W2", "127.0.0.1")]
    assert host.status == "alive"
