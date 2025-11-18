"""
Secure Network Scanner Tool
A simplified and secure implementation of a network scanner that only accepts
CIDR notation or single IP addresses.
"""

import asyncio
import ipaddress
import time
from datetime import datetime
from typing import List, Optional
import logging

# Assuming schemas are defined in a file named secure_schemas.py in the same directory
from .schemas import SecureNetworkScannerInput, SecureNetworkScannerOutput, HostInfo

logger = logging.getLogger(__name__)

MAX_HOSTS_TO_SCAN = 1024 # Reduced for safety, equivalent to a /22

async def ping_host(ip: str, timeout: int) -> HostInfo:
    """Ping a single host to check if it's alive. Securely executes ping."""
    start_time = time.time()
    proc = await asyncio.create_subprocess_exec(
        'ping', '-c', '1', f'-W{timeout}', str(ip),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    response_time = (time.time() - start_time) * 1000

    if proc.returncode == 0:
        return HostInfo(ip_address=ip, status="alive", response_time=response_time)
    else:
        return HostInfo(ip_address=ip, status="unreachable", response_time=response_time)

async def execute_secure_scanner(input_data: SecureNetworkScannerInput) -> SecureNetworkScannerOutput:
    """
    Executes the secure network scan.
    1. Validates the input network.
    2. Generates a list of IPs.
    3. Pings each host concurrently.
    4. Returns the results.
    """
    start_time = datetime.now()
    
    try:
        network = ipaddress.ip_network(input_data.network, strict=False)
    except ValueError:
        return SecureNetworkScannerOutput(
            success=False,
            error="Invalid network format. Please use CIDR notation (e.g., 192.168.1.0/24) or a single IP.",
            timestamp=start_time,
            scan_duration=0,
            hosts=[]
        )

    if network.num_addresses > MAX_HOSTS_TO_SCAN:
        return SecureNetworkScannerOutput(
            success=False,
            error=f"Network is too large. Maximum allowed hosts is {MAX_HOSTS_TO_SCAN}.",
            timestamp=start_time,
            scan_duration=0,
            hosts=[]
        )

    if network.num_addresses == 1:
        ip_list = [network.network_address]
    else:
        ip_list = list(network.hosts())

    scan_start_time = time.time()

    semaphore = asyncio.Semaphore(input_data.max_concurrent_scans)
    
    async def scan_with_semaphore(ip):
        async with semaphore:
            return await ping_host(str(ip), input_data.timeout)

    tasks = [scan_with_semaphore(ip) for ip in ip_list]
    results = await asyncio.gather(*tasks)

    scan_duration = time.time() - scan_start_time
    
    alive_hosts = [host for host in results if host.status == "alive"]

    return SecureNetworkScannerOutput(
        success=True,
        timestamp=start_time,
        scan_duration=scan_duration,
        hosts=results,
        summary=f"Scan complete. Found {len(alive_hosts)} alive hosts out of {len(ip_list)}."
    )
