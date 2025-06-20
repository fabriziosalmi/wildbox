"""Port Scanner Tool - Scans TCP ports on a target host."""

import socket
import asyncio
import logging
from datetime import datetime
from typing import List, Optional
try:
    from .schemas import PortScannerInput, PortScannerOutput, PortScanResult
except ImportError:
    from schemas import PortScannerInput, PortScannerOutput, PortScanResult

logger = logging.getLogger(__name__)

def validate_target(target: str) -> str:
    """Validate and sanitize target input"""
    if not target:
        raise ValueError("Target cannot be empty")
    
    # Remove any potentially dangerous characters
    import re
    # Allow only alphanumeric, dots, hyphens, and underscores
    cleaned_target = re.sub(r'[^a-zA-Z0-9\.\-_]', '', target.strip())
    
    if not cleaned_target:
        raise ValueError("Target contains no valid characters")
    
    # Limit length
    if len(cleaned_target) > 253:  # Max domain name length
        raise ValueError("Target too long")
    
    return cleaned_target

def validate_timeout(timeout: int) -> int:
    """Validate and sanitize timeout input"""
    if timeout <= 0:
        return 5  # Default timeout
    if timeout > 300:  # Max 5 minutes
        return 300
    return timeout

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3389, 8080, 8443]

SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    3389: "rdp",
    8080: "http-proxy",
    8443: "https-alt"
}

async def scan_port_async(target: str, port: int, timeout: int) -> PortScanResult:
    """Asynchronously scan a single port."""
    try:
        future = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(future, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        state = "open"
        logger.debug(f"Port {port} is open on {target}")
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        state = "closed"
        logger.debug(f"Port {port} is closed on {target}: {type(e).__name__}")
    
    service = SERVICE_MAP.get(port)
    return PortScanResult(port=port, state=state, service=service)

def scan_port(target: str, port: int, timeout: int) -> PortScanResult:
    """Synchronously scan a single port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((target, port))
        state = "open" if result == 0 else "closed"
    except (socket.timeout, ConnectionRefusedError, OSError):
        state = "closed"
    finally:
        s.close()
    
    service = SERVICE_MAP.get(port)
    return PortScanResult(port=port, state=state, service=service)

async def execute_tool(input_data: PortScannerInput) -> PortScannerOutput:
    """Execute the port scanner tool - main entry point."""
    start_time = datetime.now()
    
    # Validate and sanitize inputs
    safe_target = validate_target(input_data.target)
    safe_timeout = validate_timeout(input_data.timeout)
    
    logger.info(f"Starting port scan on {safe_target}")
    
    try:
        # Resolve target if it's a domain
        try:
            target_ip = socket.gethostbyname(safe_target)
            logger.info(f"Resolved {safe_target} to {target_ip}")
        except socket.gaierror:
            target_ip = safe_target
            logger.info(f"Using IP address directly: {target_ip}")
        
        # Determine ports to scan
        ports = input_data.ports or COMMON_PORTS
        logger.info(f"Scanning {len(ports)} ports with timeout {safe_timeout}s")
        
        # Perform concurrent port scanning
        tasks = []
        for port in ports:
            task = scan_port_async(target_ip, port, safe_timeout)
            tasks.append(task)
        
        # Execute all scans concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and get successful results
        valid_results = []
        for result in results:
            if isinstance(result, PortScanResult):
                valid_results.append(result)
            else:
                logger.warning(f"Port scan failed: {result}")
        
        # Filter to only include open ports in final results
        open_ports = [result for result in valid_results if result.state == "open"]
        
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Port scan completed in {duration:.2f}s, found {len(open_ports)} open ports")
        
        return PortScannerOutput(target=input_data.target, results=open_ports)
        
    except Exception as e:
        logger.error(f"Port scan failed: {e}")
        return PortScannerOutput(target=input_data.target, results=[])

# Tool metadata
TOOL_INFO = {
    "name": "port_scanner",
    "display_name": "TCP Port Scanner",
    "description": "Fast and reliable TCP port scanner for discovering open ports on target hosts",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "network_reconnaissance"
}
