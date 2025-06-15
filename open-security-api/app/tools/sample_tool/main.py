"""Sample security tool implementation."""

import asyncio
import random
from datetime import datetime
from typing import Dict, Any

try:
    from .schemas import SampleToolInput, SampleToolOutput, PortInfo
except ImportError:
    from schemas import SampleToolInput, SampleToolOutput, PortInfo


# Tool metadata
TOOL_INFO = {
    "name": "sample_tool",
    "display_name": "Sample Security Scanner",
    "description": "A demonstration security tool that simulates port scanning and vulnerability detection",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "network_scanning"
}


async def simulate_port_scan(target: str, timeout: int) -> list[PortInfo]:
    """Simulate a port scan with realistic delays."""
    
    # Common ports to check
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
    
    # Simulate scan delay
    await asyncio.sleep(random.uniform(0.5, 2.0))
    
    open_ports = []
    
    # Randomly determine which ports are "open"
    for port in common_ports:
        if random.random() < 0.3:  # 30% chance a port is open
            service_map = {
                21: ("ftp", "vsftpd 3.0.3"),
                22: ("ssh", "OpenSSH 8.2"),
                25: ("smtp", "Postfix 3.4.13"),
                53: ("dns", "BIND 9.16.1"),
                80: ("http", "Apache 2.4.41"),
                110: ("pop3", "Dovecot 2.3.7"),
                143: ("imap", "Dovecot 2.3.7"),
                443: ("https", "Apache 2.4.41"),
                993: ("imaps", "Dovecot 2.3.7"),
                995: ("pop3s", "Dovecot 2.3.7"),
                8080: ("http-proxy", "Squid 4.10"),
                8443: ("https-alt", "Apache 2.4.41")
            }
            
            service, version = service_map.get(port, ("unknown", None))
            
            open_ports.append(PortInfo(
                port=port,
                state="open",
                service=service,
                version=version
            ))
    
    return open_ports


async def detect_vulnerabilities(open_ports: list[PortInfo]) -> list[str]:
    """Simulate vulnerability detection based on open ports."""
    
    vulnerabilities = []
    
    for port_info in open_ports:
        if port_info.port == 21:
            vulnerabilities.append("FTP service detected - consider using SFTP instead")
        elif port_info.port == 23:
            vulnerabilities.append("Telnet service detected - highly insecure, use SSH instead")
        elif port_info.port == 80 and any(p.port == 443 for p in open_ports):
            vulnerabilities.append("HTTP and HTTPS both available - ensure HTTP redirects to HTTPS")
        elif port_info.service == "ssh" and "OpenSSH" in (port_info.version or ""):
            vulnerabilities.append("SSH service detected - ensure key-based authentication is used")
    
    # Add some random vulnerabilities for demonstration
    potential_vulns = [
        "Outdated SSL/TLS configuration detected",
        "Server information disclosure in HTTP headers",
        "Missing security headers (X-Frame-Options, CSP)",
        "Weak cipher suites detected"
    ]
    
    for vuln in potential_vulns:
        if random.random() < 0.4:  # 40% chance
            vulnerabilities.append(vuln)
    
    return vulnerabilities


def generate_recommendations(vulnerabilities: list[str], open_ports: list[PortInfo]) -> list[str]:
    """Generate security recommendations based on findings."""
    
    recommendations = []
    
    if vulnerabilities:
        recommendations.append("Address identified vulnerabilities promptly")
        recommendations.append("Implement regular security patching schedule")
    
    if len(open_ports) > 5:
        recommendations.append("Consider closing unnecessary open ports")
        recommendations.append("Implement network segmentation and firewall rules")
    
    recommendations.extend([
        "Enable intrusion detection/prevention systems",
        "Implement regular security monitoring and logging",
        "Conduct periodic penetration testing",
        "Ensure all services are running latest secure versions"
    ])
    
    return recommendations


async def execute_tool(input_data: SampleToolInput) -> SampleToolOutput:
    """
    Execute the sample security tool with the provided input.
    
    Args:
        input_data: Input parameters for the tool
        
    Returns:
        Tool execution results
    """
    
    start_time = datetime.utcnow()
    
    try:
        # Simulate the scanning process
        open_ports = await simulate_port_scan(input_data.target, input_data.timeout)
        vulnerabilities = await detect_vulnerabilities(open_ports)
        recommendations = generate_recommendations(vulnerabilities, open_ports)
        
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        # Create detailed findings
        findings = {
            "total_ports_scanned": 13,
            "open_ports_count": len(open_ports),
            "vulnerabilities_count": len(vulnerabilities),
            "risk_level": "high" if len(vulnerabilities) > 3 else "medium" if len(vulnerabilities) > 0 else "low",
            "scan_method": "TCP SYN scan simulation",
            "target_resolved": input_data.target,
            "additional_info": f"Scan completed successfully in {duration:.2f} seconds"
        }
        
        return SampleToolOutput(
            target=input_data.target,
            scan_type=input_data.scan_type,
            timestamp=start_time,
            duration=duration,
            status="success",
            findings=findings,
            open_ports=open_ports,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations
        )
        
    except Exception as e:
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        return SampleToolOutput(
            target=input_data.target,
            scan_type=input_data.scan_type,
            timestamp=start_time,
            duration=duration,
            status="failed",
            findings={"error": str(e)},
            open_ports=[],
            vulnerabilities=[],
            recommendations=["Fix the error and retry the scan"]
        )
