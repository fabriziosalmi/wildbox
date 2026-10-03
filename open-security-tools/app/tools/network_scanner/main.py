"""Network Scanner: host discovery over a small range, with an optional TCP
connect probe of common ports on the hosts that answer.

This is the only tool that sweeps a range of addresses; port_scanner and
network_port_scanner each scan one host. Every run used to fail before the
first probe (#615): ping_host indexed the boolean that a stub target check
returned, and the TypeError was swallowed by asyncio.gather, so each scan
reported success with no hosts. The stubs (a rate limiter that slept while
holding its lock, a port "restriction" that skipped 22, 445 and 3389) are
gone; probes are bounded by ``max_threads`` and each one by ``timeout``.

Which targets may be scanned at all is decided centrally (#614), not here.
"""

import asyncio
import ipaddress
import logging
import shutil
import socket
import time
from datetime import datetime
from typing import List, Optional

from ...tool_errors import RUN_ERRORS
from .schemas import HostInfo, NetworkScannerInput, NetworkScannerOutput

logger = logging.getLogger(__name__)

TOOL_INFO = {
    "name": "Network Scanner",
    "description": (
        "Discovers live hosts in a small range with ping and, with scan_type "
        "tcp, probes their common ports with a TCP connect"
    ),
    "category": "network_scanning",
    "author": "Wildbox Security",
    "version": "2.1.0",
    "input_schema": NetworkScannerInput,
    "output_schema": NetworkScannerOutput,
    "tags": ["network", "scanning", "discovery", "hosts"],
}

# Ports probed on each live host by a tcp scan.
COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3389,
    5900,
    8080,
]

# A /22: the most addresses one run may cover. Larger ranges are refused
# before any probe rather than silently truncated.
MAX_HOSTS = 1024

# How long past its own -W deadline a ping may run before it is killed.
PING_GRACE_SECONDS = 2.0

# Bound on the reverse DNS lookup of a live host.
REVERSE_DNS_TIMEOUT = 2.0

PING_MISSING = (
    "The 'ping' binary is not installed or not on PATH. Install iputils-ping "
    "(it is in the tools image) to run host discovery."
)


def parse_targets(network: str) -> List[str]:
    """The addresses ``network`` names, refusing more than MAX_HOSTS.

    Accepts a single address, CIDR notation, or a last-octet IPv4 range such
    as ``192.168.1.10-20``. The size is checked before the addresses are
    listed, so an IPv6 /64 costs nothing to refuse.
    """
    text = network.strip()
    if "-" in text and "/" not in text:
        return _parse_last_octet_range(text)
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid network {network!r}: {e}") from None
    if net.num_addresses > MAX_HOSTS:
        raise ValueError(
            f"Range is too large: {net.num_addresses} addresses, the limit is "
            f"{MAX_HOSTS} (a /22)."
        )
    if net.num_addresses <= 2:
        # A single address, or a /31 or /127 point-to-point link: every
        # address is a host.
        return [str(ip) for ip in net]
    return [str(ip) for ip in net.hosts()]


def _parse_last_octet_range(text: str) -> List[str]:
    base, _, last = text.rpartition(".")
    start_text, _, end_text = last.partition("-")
    try:
        first = ipaddress.IPv4Address(f"{base}.{start_text}")
        final = ipaddress.IPv4Address(f"{base}.{end_text}")
    except ValueError as e:
        raise ValueError(f"Invalid network {text!r}: {e}") from None
    if final < first:
        raise ValueError(f"Invalid network {text!r}: the range ends before it starts")
    return [str(ipaddress.IPv4Address(n)) for n in range(int(first), int(final) + 1)]


class NetworkScanner:
    """Probes a list of addresses, at most ``max_concurrent`` at a time.

    The semaphore is taken per probe (one ping, one connect, one lookup),
    never per host, so a host waiting for its port probes holds no slot.
    """

    def __init__(self, ping_bin: str, timeout: int, max_concurrent: int):
        self.ping_bin = ping_bin
        self.timeout = timeout
        self.slots = asyncio.Semaphore(max_concurrent)

    async def ping(self, ip: str) -> HostInfo:
        """One echo request, run without a shell, the address as its own
        argument. -W is in seconds with iputils ping."""
        argv = [self.ping_bin, "-c", "1", "-W", str(self.timeout), ip]
        async with self.slots:
            start = time.monotonic()
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            except OSError as e:
                return HostInfo(ip_address=ip, status="error", error=f"ping: {e}")
            try:
                await asyncio.wait_for(
                    process.communicate(), self.timeout + PING_GRACE_SECONDS
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return HostInfo(
                    ip_address=ip,
                    status="timeout",
                    error=f"ping did not return within {self.timeout}s",
                )
            elapsed_ms = (time.monotonic() - start) * 1000
        if process.returncode == 0:
            return HostInfo(ip_address=ip, status="alive", response_time=elapsed_ms)
        return HostInfo(ip_address=ip, status="dead")

    async def port_is_open(self, ip: str, port: int) -> bool:
        """A TCP connect, given up after ``timeout`` seconds."""
        async with self.slots:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), self.timeout
                )
            except (OSError, asyncio.TimeoutError):
                return False
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return True

    async def hostname(self, ip: str) -> Optional[str]:
        async with self.slots:
            loop = asyncio.get_running_loop()
            try:
                name, _, _ = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyaddr, ip),
                    REVERSE_DNS_TIMEOUT,
                )
            except (OSError, asyncio.TimeoutError):
                return None
            return name

    async def scan_host(self, ip: str, tcp: bool) -> HostInfo:
        host = await self.ping(ip)
        if host.status != "alive":
            return host
        host.hostname = await self.hostname(ip)
        if tcp:
            open_flags = await asyncio.gather(
                *(self.port_is_open(ip, port) for port in COMMON_PORTS)
            )
            host.open_ports = [
                port for port, is_open in zip(COMMON_PORTS, open_flags) if is_open
            ]
        return host


def _scan_output(
    target_network: str,
    timestamp: datetime,
    execution_time: float,
    hosts_discovered: List[HostInfo],
    total_hosts_scanned: int,
    alive_hosts: int,
    success: bool,
    scan_type: Optional[str] = None,
    error: Optional[str] = None,
    message: Optional[str] = None,
) -> NetworkScannerOutput:
    """The scan's result in NetworkScannerOutput's own fields (#611)."""
    return NetworkScannerOutput(
        success=success,
        target=target_network,
        network=target_network,
        timestamp=timestamp,
        total_hosts=total_hosts_scanned,
        alive_hosts=alive_hosts,
        scan_duration=execution_time,
        execution_time=execution_time,
        hosts=hosts_discovered,
        error_message=error,
        summary=message,
        metadata={"scan_type": scan_type} if scan_type else {},
    )


async def execute_tool(input_data: NetworkScannerInput) -> NetworkScannerOutput:
    """Discover the live hosts of ``input_data.network``."""
    start_time = datetime.now()
    scan_type = input_data.scan_type.lower()

    def failed(error: str) -> NetworkScannerOutput:
        return _scan_output(
            target_network=input_data.network,
            scan_type=scan_type,
            timestamp=start_time,
            execution_time=(datetime.now() - start_time).total_seconds(),
            hosts_discovered=[],
            total_hosts_scanned=0,
            alive_hosts=0,
            success=False,
            error=error,
        )

    try:
        ip_list = parse_targets(input_data.network)
    except ValueError as e:
        return failed(str(e))

    ping_bin = shutil.which("ping")
    if not ping_bin:
        return failed(PING_MISSING)

    scanner = NetworkScanner(ping_bin, input_data.timeout, input_data.max_threads)
    logger.info("%s scan of %d addresses", scan_type, len(ip_list))
    try:
        hosts = await asyncio.gather(
            *(scanner.scan_host(ip, tcp=scan_type == "tcp") for ip in ip_list)
        )
    except RUN_ERRORS as e:
        logger.error("Network scan failed: %s", e, exc_info=True)
        return failed(f"Scan failed: {type(e).__name__}: {e}")

    alive = sum(1 for host in hosts if host.status == "alive")
    execution_time = (datetime.now() - start_time).total_seconds()
    return _scan_output(
        target_network=input_data.network,
        scan_type=scan_type,
        timestamp=start_time,
        execution_time=execution_time,
        hosts_discovered=list(hosts),
        total_hosts_scanned=len(ip_list),
        alive_hosts=alive,
        success=True,
        message=f"{alive} of {len(ip_list)} hosts answered ({scan_type} scan)",
    )


# Export tool info for registration
tool_info = TOOL_INFO
