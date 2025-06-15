"""Network Scanner Tool - Discovers hosts and services on a network."""

import asyncio
import socket
import subprocess
import ipaddress
import time
from datetime import datetime
from typing import List, Optional
try:
    from .schemas import NetworkScannerInput, NetworkScannerOutput, HostInfo
except ImportError:
    from schemas import NetworkScannerInput, NetworkScannerOutput, HostInfo

# Common ports to scan for TCP scans
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3389, 5900, 8080]

async def ping_host(ip: str, timeout: int) -> HostInfo:
    """Ping a single host to check if it's alive."""
    start_time = time.time()
    
    try:
        # Use subprocess to ping (works on both Unix and Windows)
        process = await asyncio.create_subprocess_exec(
            'ping', '-c', '1', '-W', str(timeout * 1000), ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            # Host is alive, try to get hostname
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            # Calculate response time
            response_time = (time.time() - start_time) * 1000
            
            return HostInfo(
                ip_address=ip,
                hostname=hostname,
                status="alive",
                response_time=response_time
            )
        else:
            return HostInfo(
                ip_address=ip,
                hostname=None,
                status="dead",
                response_time=None
            )
    
    except Exception:
        return HostInfo(
            ip_address=ip,
            hostname=None,
            status="dead",
            response_time=None
        )

async def tcp_scan_host(ip: str, timeout: int) -> HostInfo:
    """Perform TCP scan on a host to detect open ports."""
    start_time = time.time()
    
    # First ping the host
    host_info = await ping_host(ip, timeout)
    
    if host_info.status == "alive":
        # Scan common ports
        open_ports = []
        
        async def scan_port(port):
            try:
                future = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        # Create tasks for all ports
        tasks = [scan_port(port) for port in COMMON_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect open ports
        for result in results:
            if isinstance(result, int):
                open_ports.append(result)
        
        host_info.open_ports = sorted(open_ports)
        
        # Simple OS detection based on open ports
        if 3389 in open_ports:
            host_info.os_guess = "Windows"
        elif 22 in open_ports and 80 in open_ports:
            host_info.os_guess = "Linux/Unix"
        elif 445 in open_ports:
            host_info.os_guess = "Windows"
    
    return host_info

async def comprehensive_scan_host(ip: str, timeout: int) -> HostInfo:
    """Perform comprehensive scan including TCP and additional checks."""
    host_info = await tcp_scan_host(ip, timeout)
    
    if host_info.status == "alive":
        # Try to get MAC address (only works on local network)
        try:
            # This is a simplified approach - in real scenarios you'd use ARP
            process = await asyncio.create_subprocess_exec(
                'arp', '-n', ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Parse ARP output to get MAC address
                lines = stdout.decode().split('\n')
                for line in lines:
                    if ip in line and ':' in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                host_info.mac_address = part
                                break
        except:
            pass
    
    return host_info

def generate_ip_list(network: str) -> List[str]:
    """Generate list of IP addresses from CIDR notation."""
    try:
        network_obj = ipaddress.ip_network(network, strict=False)
        return [str(ip) for ip in network_obj.hosts()]
    except:
        # If not CIDR, try to parse as single IP or range
        if '-' in network:
            # Range like 192.168.1.1-10
            base, range_part = network.rsplit('.', 1)
            start, end = range_part.split('-')
            ips = []
            for i in range(int(start), int(end) + 1):
                ips.append(f"{base}.{i}")
            return ips
        else:
            # Single IP
            return [network]

async def execute_tool(input_data: NetworkScannerInput) -> NetworkScannerOutput:
    """Execute the network scanner tool."""
    start_time = datetime.now()
    scan_start = time.time()
    
    # Generate IP list
    ip_list = generate_ip_list(input_data.network)
    
    if not ip_list:
        return NetworkScannerOutput(
            network=input_data.network,
            timestamp=start_time,
            total_hosts=0,
            alive_hosts=0,
            scan_duration=0,
            hosts=[]
        )
    
    # Create semaphore to limit concurrent scans
    semaphore = asyncio.Semaphore(input_data.max_threads)
    
    async def scan_with_semaphore(ip):
        async with semaphore:
            if input_data.scan_type == "ping":
                return await ping_host(ip, input_data.timeout)
            elif input_data.scan_type == "tcp":
                return await tcp_scan_host(ip, input_data.timeout)
            else:  # comprehensive
                return await comprehensive_scan_host(ip, input_data.timeout)
    
    # Scan all IPs
    tasks = [scan_with_semaphore(ip) for ip in ip_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out exceptions and get valid results
    hosts = []
    for result in results:
        if isinstance(result, HostInfo):
            hosts.append(result)
    
    # Count alive hosts
    alive_hosts = sum(1 for host in hosts if host.status == "alive")
    
    scan_duration = time.time() - scan_start
    
    return NetworkScannerOutput(
        network=input_data.network,
        timestamp=start_time,
        total_hosts=len(ip_list),
        alive_hosts=alive_hosts,
        scan_duration=scan_duration,
        hosts=hosts
    )

# Tool metadata
TOOL_INFO = {
    "name": "network_scanner",
    "display_name": "Network Scanner",
    "description": "Discovers hosts and services on a network using ping and TCP scans",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "network_reconnaissance"
}
