import asyncio
import logging
import socket
import time
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import random

try:
    from .schemas import PortScannerRequest, PortScannerResponse, PortInfo
except ImportError:
    from schemas import PortScannerRequest, PortScannerResponse, PortInfo

logger = logging.getLogger(__name__)

TOOL_INFO = {
    "name": "Network Port Scanner",
    "description": "Advanced network port scanner with service detection and security analysis",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "network_scanning",
    "tags": ["port-scan", "network", "services", "reconnaissance"]
}

# Common service definitions
COMMON_SERVICES = {
    21: ("ftp", "File Transfer Protocol"),
    22: ("ssh", "Secure Shell"),
    23: ("telnet", "Telnet"),
    25: ("smtp", "Simple Mail Transfer Protocol"),
    53: ("dns", "Domain Name System"),
    80: ("http", "HyperText Transfer Protocol"),
    110: ("pop3", "Post Office Protocol v3"),
    143: ("imap", "Internet Message Access Protocol"),
    443: ("https", "HTTP Secure"),
    993: ("imaps", "IMAP Secure"),
    995: ("pop3s", "POP3 Secure"),
    1433: ("mssql", "Microsoft SQL Server"),
    3306: ("mysql", "MySQL Database"),
    3389: ("rdp", "Remote Desktop Protocol"),
    5432: ("postgresql", "PostgreSQL Database"),
    5900: ("vnc", "Virtual Network Computing"),
    6379: ("redis", "Redis Database"),
    8080: ("http-alt", "HTTP Alternate"),
    8443: ("https-alt", "HTTPS Alternate"),
    9200: ("elasticsearch", "Elasticsearch"),
    27017: ("mongodb", "MongoDB Database")
}

# Top 1000 most common ports (simplified subset)
TOP_1000_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080,
    20, 69, 79, 88, 106, 109, 137, 138, 389, 427, 465, 514, 543, 544, 545, 548, 554, 587, 631,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
    8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
]


def parse_port_specification(port_spec: str) -> List[int]:
    """Parse port specification into list of ports."""
    if port_spec.lower() == "top1000":
        return TOP_1000_PORTS
    
    ports = []
    
    # Handle comma-separated ports and ranges
    for part in port_spec.split(','):
        part = part.strip()
        
        if '-' in part:
            # Port range
            try:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            except ValueError:
                logger.warning(f"Invalid port range: {part}")
        else:
            # Single port
            try:
                ports.append(int(part))
            except ValueError:
                logger.warning(f"Invalid port: {part}")
    
    return sorted(list(set(ports)))  # Remove duplicates and sort


async def resolve_hostname(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            return target  # Already an IP address
        
        # Real DNS resolution
        import socket
        loop = asyncio.get_event_loop()
        
        # Use asyncio to run blocking socket operation in thread pool
        ip = await loop.run_in_executor(None, socket.gethostbyname, target)
        return ip
        
    except Exception as e:
        logger.error(f"Failed to resolve hostname {target}: {str(e)}")
        raise


async def scan_tcp_port(ip: str, port: int, timeout: int = 3) -> str:
    """Scan a single TCP port using real network connection."""
    try:
        # Real TCP connection attempt
        future = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(future, timeout=timeout)
        
        # Connection successful - port is open
        writer.close()
        await writer.wait_closed()
        return "open"
        
    except asyncio.TimeoutError:
        return "filtered"  # Timeout usually means filtered
    except ConnectionRefusedError:
        return "closed"  # Connection refused means closed
    except OSError as e:
        # Handle various network errors
        if "Network is unreachable" in str(e):
            return "filtered"
        elif "No route to host" in str(e):
            return "filtered"
        else:
            return "filtered"
    except Exception:
        return "filtered"


async def scan_udp_port(ip: str, port: int, timeout: int = 3) -> str:
    """Scan a single UDP port using real network probes."""
    try:
        import socket
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        try:
            # Send UDP probe
            sock.sendto(b'', (ip, port))
            
            # Try to receive response
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return "open"  # Got response
            except socket.timeout:
                sock.close()
                return "open|filtered"  # No response, could be open or filtered
                
        except socket.error as e:
            sock.close()
            if "Connection refused" in str(e):
                return "closed"  # ICMP port unreachable
            else:
                return "open|filtered"
                
    except Exception:
        return "open|filtered"
                
    except Exception:
        return "open|filtered"


async def detect_service(ip: str, port: int, protocol: str = "tcp") -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Detect service running on a port using real banner grabbing."""
    
    service_name = None
    version = None
    banner = None
    
    # First check if it's a known service by port
    if port in COMMON_SERVICES:
        service_name, _ = COMMON_SERVICES[port]
    
    # Try to grab banner for TCP services
    if protocol == "tcp":
        try:
            banner = await grab_banner(ip, port)
            if banner:
                # Parse banner to extract service and version
                parsed = parse_banner(banner, port)
                if parsed['service']:
                    service_name = parsed['service']
                if parsed['version']:
                    version = parsed['version']
        except Exception as e:
            logger.debug(f"Banner grab failed for {ip}:{port}: {e}")
    
    return service_name, version, banner


async def grab_banner(ip: str, port: int, timeout: int = 5) -> Optional[str]:
    """Grab service banner from a TCP port."""
    try:
        # Connect to the service
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), 
            timeout=timeout
        )
        
        # Try to read initial banner (some services send it immediately)
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            if banner:
                writer.close()
                await writer.wait_closed()
                return banner.decode('utf-8', errors='ignore').strip()
        except asyncio.TimeoutError:
            pass
        
        # For HTTP services, send a basic request
        if port in [80, 8080, 8000, 8888]:
            writer.write(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            
            if response:
                return response.decode('utf-8', errors='ignore').strip()
        
        # For HTTPS services, we can't easily grab banners without SSL
        elif port in [443, 8443]:
            writer.close()
            await writer.wait_closed()
            return "HTTPS service detected"
        
        # For other services, try sending a newline and reading response
        else:
            writer.write(b"\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            
            if response:
                return response.decode('utf-8', errors='ignore').strip()
    
    except Exception as e:
        logger.debug(f"Banner grab error for {ip}:{port}: {e}")
    
    return None


def parse_banner(banner: str, port: int) -> Dict[str, Optional[str]]:
    """Parse service banner to extract service type and version."""
    
    result = {'service': None, 'version': None}
    
    if not banner:
        return result
    
    banner_lower = banner.lower()
    
    # SSH detection
    if 'ssh-' in banner_lower:
        result['service'] = 'ssh'
        if 'openssh' in banner_lower:
            # Extract OpenSSH version
            match = re.search(r'openssh[_\s]+(\d+\.\d+[\w\.-]*)', banner_lower)
            if match:
                result['version'] = f"OpenSSH {match.group(1)}"
    
    # HTTP server detection
    elif 'server:' in banner_lower or 'http/' in banner_lower:
        result['service'] = 'http'
        # Extract server version
        if 'apache' in banner_lower:
            match = re.search(r'apache[/\s]+(\d+\.\d+[\.\d]*)', banner_lower)
            if match:
                result['version'] = f"Apache/{match.group(1)}"
        elif 'nginx' in banner_lower:
            match = re.search(r'nginx[/\s]+(\d+\.\d+[\.\d]*)', banner_lower)
            if match:
                result['version'] = f"nginx/{match.group(1)}"
        elif 'microsoft-iis' in banner_lower:
            match = re.search(r'microsoft-iis[/\s]+(\d+\.\d+)', banner_lower)
            if match:
                result['version'] = f"Microsoft-IIS/{match.group(1)}"
    
    # FTP detection
    elif '220' in banner and ('ftp' in banner_lower or 'ready' in banner_lower):
        result['service'] = 'ftp'
        if 'vsftpd' in banner_lower:
            match = re.search(r'vsftpd\s+(\d+\.\d+[\.\d]*)', banner_lower)
            if match:
                result['version'] = f"vsftpd {match.group(1)}"
        elif 'proftpd' in banner_lower:
            match = re.search(r'proftpd\s+(\d+\.\d+[\.\d]*)', banner_lower)
            if match:
                result['version'] = f"ProFTPD {match.group(1)}"
    
    # SMTP detection
    elif '220' in banner and 'esmtp' in banner_lower:
        result['service'] = 'smtp'
        if 'postfix' in banner_lower:
            result['version'] = "Postfix"
        elif 'sendmail' in banner_lower:
            match = re.search(r'sendmail\s+(\d+\.\d+[\.\d]*)', banner_lower)
            if match:
                result['version'] = f"sendmail {match.group(1)}"
    
    # Additional service detections can be added here
    
    return result


async def perform_os_fingerprinting(ip: str, open_ports: List[PortInfo]) -> Optional[Dict[str, Any]]:
    """Perform basic OS fingerprinting based on open ports and services."""
    await asyncio.sleep(0.5)  # OS fingerprinting takes more time
    
    if not open_ports:
        return None
    
    # Analyze port patterns to guess OS
    windows_indicators = 0
    linux_indicators = 0
    
    for port_info in open_ports:
        # Windows indicators
        if port_info.port in [135, 139, 445, 3389]:  # Windows-specific ports
            windows_indicators += 2
        elif port_info.port in [1433, 1434]:  # SQL Server
            windows_indicators += 1
        elif port_info.service and "Microsoft" in str(port_info.version):
            windows_indicators += 1
        
        # Linux indicators
        if port_info.port == 22 and port_info.service == "ssh":
            linux_indicators += 1
        elif port_info.service and any(service in str(port_info.version) 
                                     for service in ["Apache", "nginx", "OpenSSH"]):
            linux_indicators += 1
    
    # Determine most likely OS
    if windows_indicators > linux_indicators:
        os_family = "Windows"
        confidence = min(90, 50 + windows_indicators * 10)
        possible_versions = ["Windows 10", "Windows Server 2019", "Windows Server 2016"]
    elif linux_indicators > 0:
        os_family = "Linux"
        confidence = min(85, 40 + linux_indicators * 10)
        possible_versions = ["Ubuntu 20.04", "CentOS 7", "Red Hat Enterprise Linux 8", "Debian 10"]
    else:
        os_family = "Unknown"
        confidence = 0
        possible_versions = []
    
    fingerprint = {
        "os_family": os_family,
        "confidence": confidence,
        "possible_versions": possible_versions,
        "indicators": {
            "windows_score": windows_indicators,
            "linux_score": linux_indicators
        }
    }
    
    return fingerprint


def analyze_security_posture(open_ports: List[PortInfo], os_fingerprint: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze security posture based on scan results."""
    analysis = {
        "risk_level": "Low",
        "attack_surface": len(open_ports),
        "critical_services": [],
        "insecure_services": [],
        "administrative_access": [],
        "database_services": [],
        "web_services": [],
        "security_concerns": []
    }
    
    critical_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 6379, 27017]
    insecure_protocols = [21, 23, 80, 1433, 3306]  # Unencrypted protocols
    admin_ports = [22, 3389, 5900]  # Remote administration
    db_ports = [1433, 3306, 5432, 6379, 27017]  # Database services
    web_ports = [80, 443, 8080, 8443]  # Web services
    
    # Categorize open ports
    for port_info in open_ports:
        port = port_info.port
        
        if port in critical_ports:
            analysis["critical_services"].append({
                "port": port,
                "service": port_info.service,
                "reason": "High-value target for attackers"
            })
        
        if port in insecure_protocols:
            analysis["insecure_services"].append({
                "port": port,
                "service": port_info.service,
                "reason": "Unencrypted protocol"
            })
        
        if port in admin_ports:
            analysis["administrative_access"].append({
                "port": port,
                "service": port_info.service
            })
        
        if port in db_ports:
            analysis["database_services"].append({
                "port": port,
                "service": port_info.service
            })
        
        if port in web_ports:
            analysis["web_services"].append({
                "port": port,
                "service": port_info.service
            })
    
    # Determine risk level
    risk_score = 0
    risk_score += len(analysis["critical_services"]) * 3
    risk_score += len(analysis["insecure_services"]) * 2
    risk_score += len(analysis["administrative_access"]) * 2
    risk_score += len(analysis["database_services"]) * 2
    
    if risk_score >= 10:
        analysis["risk_level"] = "High"
    elif risk_score >= 5:
        analysis["risk_level"] = "Medium"
    else:
        analysis["risk_level"] = "Low"
    
    # Generate security concerns
    if analysis["insecure_services"]:
        analysis["security_concerns"].append("Unencrypted services detected - data transmission may be intercepted")
    
    if analysis["administrative_access"]:
        analysis["security_concerns"].append("Remote administration services exposed - potential for unauthorized access")
    
    if analysis["database_services"]:
        analysis["security_concerns"].append("Database services exposed - sensitive data may be at risk")
    
    if len(open_ports) > 10:
        analysis["security_concerns"].append("Large attack surface - many services exposed")
    
    # OS-specific concerns
    if os_fingerprint and os_fingerprint.get("os_family") == "Windows":
        windows_ports = [135, 139, 445]
        if any(port.port in windows_ports for port in open_ports):
            analysis["security_concerns"].append("Windows file sharing services exposed - potential for lateral movement")
    
    return analysis


def generate_recommendations(open_ports: List[PortInfo], security_analysis: Dict[str, Any]) -> List[str]:
    """Generate security recommendations based on scan results."""
    recommendations = []
    
    # General recommendations
    recommendations.append("Implement a firewall to restrict unnecessary port access")
    recommendations.append("Regularly update all services to their latest versions")
    recommendations.append("Use strong authentication mechanisms for all services")
    
    # Service-specific recommendations
    if security_analysis["insecure_services"]:
        recommendations.append("Replace insecure protocols with encrypted alternatives (HTTP→HTTPS, FTP→SFTP, Telnet→SSH)")
    
    if security_analysis["administrative_access"]:
        recommendations.append("Restrict administrative access to specific IP ranges or VPN")
        recommendations.append("Use key-based authentication instead of passwords for SSH")
    
    if security_analysis["database_services"]:
        recommendations.append("Ensure database services are not accessible from the internet")
        recommendations.append("Implement database access controls and encryption")
    
    if security_analysis["web_services"]:
        recommendations.append("Keep web servers updated and properly configured")
        recommendations.append("Implement Web Application Firewall (WAF) protection")
    
    # Risk-level specific recommendations
    if security_analysis["risk_level"] == "High":
        recommendations.append("URGENT: Review and minimize exposed services immediately")
        recommendations.append("Conduct a comprehensive security audit")
    elif security_analysis["risk_level"] == "Medium":
        recommendations.append("Review service necessity and disable unused services")
        recommendations.append("Implement additional monitoring and logging")
    
    # Port-specific recommendations
    critical_findings = []
    for port_info in open_ports:
        port = port_info.port
        
        if port == 21:  # FTP
            critical_findings.append("FTP service detected - consider using SFTP instead")
        elif port == 23:  # Telnet
            critical_findings.append("Telnet service detected - replace with SSH immediately")
        elif port == 135:  # RPC
            critical_findings.append("RPC service exposed - restrict access or disable")
        elif port == 445:  # SMB
            critical_findings.append("SMB service exposed - ensure proper access controls")
        elif port == 3389:  # RDP
            critical_findings.append("RDP service exposed - enable Network Level Authentication and restrict access")
    
    recommendations.extend(critical_findings)
    
    return recommendations


async def execute_tool(request: PortScannerRequest) -> PortScannerResponse:
    """Execute network port scanning."""
    start_time = time.time()
    
    try:
        logger.info(f"Starting port scan for target: {request.target}")
        
        # Resolve target to IP
        target_ip = await resolve_hostname(request.target)
        
        # Parse port specification
        ports_to_scan = parse_port_specification(request.ports)
        
        # Limit port range for performance
        if len(ports_to_scan) > 1000:
            ports_to_scan = ports_to_scan[:1000]
            logger.warning(f"Limited scan to first 1000 ports for performance")
        
        open_ports = []
        closed_ports = []
        filtered_ports = []
        
        # Scan ports
        for port in ports_to_scan:
            if request.scan_type in ["tcp", "both"]:
                state = await scan_tcp_port(target_ip, port, request.timeout)
                
                if state == "open":
                    port_info = PortInfo(port=port, protocol="tcp", state=state)
                    
                    # Detect service if requested
                    if request.service_detection:
                        service, version, banner = await detect_service(target_ip, port, "tcp")
                        port_info.service = service
                        port_info.version = version
                        port_info.banner = banner
                        port_info.confidence = 85 if service else 0
                    
                    open_ports.append(port_info)
                elif state == "closed":
                    closed_ports.append(port)
                else:
                    filtered_ports.append(port)
            
            # UDP scanning (if requested)
            if request.scan_type in ["udp", "both"]:
                state = await scan_udp_port(target_ip, port, request.timeout)
                
                if state == "open":
                    port_info = PortInfo(port=port, protocol="udp", state=state)
                    
                    if request.service_detection:
                        service, version, banner = await detect_service(target_ip, port, "udp")
                        port_info.service = service
                        port_info.version = version
                        port_info.banner = banner
                        port_info.confidence = 70 if service else 0  # UDP detection is less reliable
                    
                    open_ports.append(port_info)
        
        # Generate service summary
        service_summary = {}
        for port_info in open_ports:
            if port_info.service:
                if port_info.service not in service_summary:
                    service_summary[port_info.service] = []
                service_summary[port_info.service].append(port_info.port)
        
        # OS fingerprinting if requested
        os_fingerprint = None
        if request.os_detection:
            os_fingerprint = await perform_os_fingerprinting(target_ip, open_ports)
        
        # Security analysis
        security_analysis = analyze_security_posture(open_ports, os_fingerprint)
        
        # Generate recommendations
        recommendations = generate_recommendations(open_ports, security_analysis)
        
        scan_duration = time.time() - start_time
        
        return PortScannerResponse(
            target=request.target,
            target_ip=target_ip,
            ports_scanned=len(ports_to_scan),
            open_ports=open_ports,
            closed_ports=closed_ports[:50],  # Limit response size
            filtered_ports=filtered_ports[:50],  # Limit response size
            service_summary=service_summary,
            os_fingerprint=os_fingerprint,
            security_analysis=security_analysis,
            recommendations=recommendations,
            scan_duration=scan_duration,
            timestamp=datetime.now().isoformat(),
            success=True,
            message=f"Scan completed: {len(open_ports)} open ports found"
        )
        
    except Exception as e:
        scan_duration = time.time() - start_time
        logger.error(f"Error in port scanner: {str(e)}")
        
        return PortScannerResponse(
            target=request.target,
            target_ip="",
            ports_scanned=0,
            open_ports=[],
            closed_ports=[],
            filtered_ports=[],
            service_summary={},
            security_analysis={},
            recommendations=[],
            scan_duration=scan_duration,
            timestamp=datetime.now().isoformat(),
            success=False,
            message=f"Port scan failed: {str(e)}"
        )
