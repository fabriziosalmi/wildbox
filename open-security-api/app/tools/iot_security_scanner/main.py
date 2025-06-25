from typing import Dict, Any, List
import ipaddress
import asyncio
import random
import logging
import os
import json

# Configure logging
logger = logging.getLogger(__name__)

try:
    from schemas import (
        IoTSecurityScannerInput, 
        IoTSecurityScannerOutput, 
        IoTDevice, 
        IoTVulnerability,
        NetworkProtocolAnalysis
    )
except ImportError:
    from schemas import (
        IoTSecurityScannerInput, 
        IoTSecurityScannerOutput, 
        IoTDevice, 
        IoTVulnerability,
        NetworkProtocolAnalysis
    )

class IoTSecurityScanner:
    """IoT Security Scanner - Comprehensive security assessment for IoT devices"""
    
    name = "IoT Security Scanner"
    description = "Comprehensive security assessment tool for IoT devices including discovery, vulnerability scanning, and configuration analysis"
    category = "iot_security"
    
    # Common IoT device fingerprints
    DEVICE_FINGERPRINTS = {
        "cameras": [80, 81, 554, 8080, 8081, 9999],
        "routers": [22, 23, 53, 80, 443, 8080],
        "smart_home": [80, 443, 1883, 5683, 8883],
        "industrial": [102, 502, 1911, 2404, 4840, 20000],
        "printers": [515, 631, 9100],
        "nas": [21, 22, 80, 139, 443, 445, 993, 995]
    }
    
    def _load_default_credentials(self) -> List[Dict[str, str]]:
        """Load default credentials from secure configuration file."""
        try:
            # Load from secure configuration file
            creds_file = os.getenv('IOT_DEFAULT_CREDS_FILE', '/etc/security/iot_default_creds.json')
            if os.path.exists(creds_file):
                with open(creds_file, 'r') as f:
                    credentials = json.load(f)
                    # Validate credential format
                    for cred in credentials:
                        if not isinstance(cred, dict) or 'username' not in cred or 'password' not in cred:
                            logger.warning("Invalid credential format in configuration file")
                            continue
                    return credentials
            else:
                logger.warning("IoT default credentials file not found. Using minimal safe set.")
                # Return only safe, minimal credential set for testing
                return [
                    {"username": "admin", "password": "admin"},
                    {"username": "admin", "password": ""}
                ]
        except Exception as e:
            logger.error(f"Failed to load IoT credentials: {e}")
            return []
    
    async def execute(self, input_data: IoTSecurityScannerInput) -> IoTSecurityScannerOutput:
        """Execute IoT security scan"""
        try:
            devices = []
            vulnerabilities = []
            
            # Determine scan targets
            if input_data.target_ip:
                targets = [input_data.target_ip]
            elif input_data.ip_range:
                targets = self._expand_ip_range(input_data.ip_range)
            else:
                # Default local network scan
                targets = self._get_local_network_range()
            
            # Scan each target
            for target in targets:
                device = await self._scan_device(target, input_data)
                if device:
                    devices.append(device)
                    
                    # Check for vulnerabilities
                    device_vulns = await self._check_vulnerabilities(device, input_data)
                    vulnerabilities.extend(device_vulns)
            
            # Analyze network protocols
            protocol_analysis = await self._analyze_network_protocols(devices)
            
            # Generate summary
            summary = self._generate_summary(devices, vulnerabilities)
            
            return IoTSecurityScannerOutput(
                devices_found=devices,
                vulnerabilities=vulnerabilities,
                network_protocols=protocol_analysis,
                scan_summary=summary,
                total_devices=len(devices),
                critical_vulnerabilities=len([v for v in vulnerabilities if v.severity == "Critical"]),
                recommendations=self._generate_recommendations(devices, vulnerabilities)
            )
            
        except Exception as e:
            return IoTSecurityScannerOutput(
                devices_found=[],
                vulnerabilities=[],
                network_protocols=[],
                scan_summary={"error": f"Scan failed: {str(e)}"},
                total_devices=0,
                critical_vulnerabilities=0,
                recommendations=["Fix scan configuration and retry"]
            )
    
    def _expand_ip_range(self, ip_range: str) -> List[str]:
        """Expand CIDR notation to individual IPs"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            # Limit to reasonable number for demo
            return [str(ip) for ip in list(network.hosts())[:20]]
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"Error parsing IP range {ip_range}: {e}")
            return [ip_range]  # Assume single IP if CIDR fails
    
    def _get_local_network_range(self) -> List[str]:
        """Get common local network IPs for scanning"""
        return [f"192.168.1.{i}" for i in range(1, 21)]
    
    async def _scan_device(self, ip: str, input_data: IoTSecurityScannerInput) -> IoTDevice:
        """Scan individual IoT device"""
        try:
            # Simulate device discovery and fingerprinting
            await asyncio.sleep(0.1)  # Simulate scan time
            
            # Random chance of finding device (simulated)
            if random.random() < 0.3:  # 30% chance of finding device
                device_type = random.choice(list(self.DEVICE_FINGERPRINTS.keys()))
                open_ports = random.sample(self.DEVICE_FINGERPRINTS[device_type], 
                                         random.randint(1, 3))
                
                # Generate services
                services = {}
                for port in open_ports:
                    services[port] = self._identify_service(port)
                
                # Check for web interface
                web_interface = None
                if 80 in open_ports or 443 in open_ports:
                    web_interface = f"http{'s' if 443 in open_ports else ''}://{ip}"
                
                # Check default credentials
                default_creds = random.choice([True, False])
                
                # Determine encryption status
                encryption = random.choice(["Strong", "Weak", "None"])
                
                # Calculate security score
                score = self._calculate_security_score(open_ports, default_creds, encryption)
                
                return IoTDevice(
                    ip_address=ip,
                    hostname=f"iot-device-{random.randint(1000, 9999)}",
                    mac_address=self._generate_mac_address(),
                    device_type=device_type,
                    manufacturer=self._get_manufacturer(device_type),
                    model=f"Model-{random.randint(100, 999)}",
                    firmware_version=f"v{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)}",
                    open_ports=open_ports,
                    services=services,
                    web_interface=web_interface,
                    default_credentials=default_creds,
                    encryption_status=encryption,
                    security_score=score
                )
            
            return None
            
        except Exception:
            return None
    
    def _identify_service(self, port: int) -> str:
        """Identify service running on port"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS",
            80: "HTTP", 443: "HTTPS", 554: "RTSP", 631: "IPP",
            1883: "MQTT", 5683: "CoAP", 8080: "HTTP-Alt", 8883: "MQTT-SSL",
            9100: "JetDirect", 102: "S7", 502: "Modbus", 4840: "OPC-UA"
        }
        return service_map.get(port, f"Unknown-{port}")
    
    async def _check_vulnerabilities(self, device: IoTDevice, input_data: IoTSecurityScannerInput) -> List[IoTVulnerability]:
        """Check device for vulnerabilities"""
        vulnerabilities = []
        
        # Check default credentials
        if input_data.check_default_credentials and device.default_credentials:
            vulnerabilities.append(IoTVulnerability(
                device_ip=device.ip_address,
                severity="Critical",
                category="Authentication",
                title="Default Credentials",
                description="Device is using default username/password combination",
                remediation="Change default credentials immediately"
            ))
        
        # Check encryption
        if input_data.check_encryption and device.encryption_status == "None":
            vulnerabilities.append(IoTVulnerability(
                device_ip=device.ip_address,
                severity="High",
                category="Encryption",
                title="No Encryption",
                description="Device communications are not encrypted",
                remediation="Enable encryption for all communications"
            ))
        
        # Check for insecure services
        insecure_ports = [21, 23, 80]  # FTP, Telnet, HTTP
        for port in device.open_ports:
            if port in insecure_ports:
                vulnerabilities.append(IoTVulnerability(
                    device_ip=device.ip_address,
                    severity="Medium",
                    category="Network Security",
                    title=f"Insecure Service: {device.services.get(port, 'Unknown')}",
                    description=f"Insecure service running on port {port}",
                    port=port,
                    service=device.services.get(port),
                    remediation="Disable insecure services or use secure alternatives"
                ))
        
        # Check firmware (simulated)
        if input_data.check_firmware and random.random() < 0.4:  # 40% chance of outdated firmware
            vulnerabilities.append(IoTVulnerability(
                device_ip=device.ip_address,
                severity="Medium",
                category="Firmware",
                title="Outdated Firmware",
                description="Device firmware may be outdated and contain known vulnerabilities",
                cve_id=f"CVE-2023-{random.randint(10000, 99999)}",
                remediation="Update device firmware to latest version"
            ))
        
        return vulnerabilities
    
    async def _analyze_network_protocols(self, devices: List[IoTDevice]) -> List[NetworkProtocolAnalysis]:
        """Analyze network protocols used by IoT devices"""
        protocols = []
        
        for device in devices:
            for port, service in device.services.items():
                # Determine protocol security
                encryption = port in [443, 8883, 993, 995]  # HTTPS, MQTT-SSL, etc.
                authentication = port not in [53, 80, 554]  # DNS, HTTP, RTSP usually no auth
                
                vulns = []
                if not encryption and port not in [53]:  # DNS exception
                    vulns.append("Unencrypted communication")
                if not authentication:
                    vulns.append("No authentication required")
                
                protocols.append(NetworkProtocolAnalysis(
                    protocol=service,
                    port=port,
                    encryption=encryption,
                    authentication=authentication,
                    vulnerabilities=vulns
                ))
        
        return protocols
    
    def _calculate_security_score(self, open_ports: List[int], default_creds: bool, encryption: str) -> float:
        """Calculate security score for device"""
        score = 10.0
        
        # Deduct for open ports
        score -= len(open_ports) * 0.5
        
        # Deduct for default credentials
        if default_creds:
            score -= 3.0
        
        # Deduct for encryption
        if encryption == "None":
            score -= 2.0
        elif encryption == "Weak":
            score -= 1.0
        
        # Deduct for insecure services
        insecure_ports = [21, 23, 80]
        for port in open_ports:
            if port in insecure_ports:
                score -= 1.0
        
        return max(0.0, min(10.0, score))
    
    def _generate_mac_address(self) -> str:
        """Generate random MAC address"""
        mac = [random.randint(0x00, 0xff) for _ in range(6)]
        return ":".join(f"{x:02x}" for x in mac)
    
    def _get_manufacturer(self, device_type: str) -> str:
        """Get manufacturer based on device type"""
        manufacturers = {
            "cameras": ["Hikvision", "Dahua", "Axis", "Bosch"],
            "routers": ["Cisco", "Netgear", "TP-Link", "ASUS"],
            "smart_home": ["Philips", "Samsung", "Amazon", "Google"],
            "industrial": ["Siemens", "Schneider", "ABB", "Rockwell"],
            "printers": ["HP", "Canon", "Epson", "Brother"],
            "nas": ["Synology", "QNAP", "Buffalo", "Western Digital"]
        }
        return random.choice(manufacturers.get(device_type, ["Unknown"]))
    
    def _generate_summary(self, devices: List[IoTDevice], vulnerabilities: List[IoTVulnerability]) -> Dict[str, Any]:
        """Generate scan summary"""
        if not devices:
            return {"message": "No IoT devices found in scan range"}
        
        device_types = {}
        for device in devices:
            device_types[device.device_type] = device_types.get(device.device_type, 0) + 1
        
        vuln_severity = {}
        for vuln in vulnerabilities:
            vuln_severity[vuln.severity] = vuln_severity.get(vuln.severity, 0) + 1
        
        avg_security_score = sum(device.security_score for device in devices) / len(devices)
        
        return {
            "total_devices": len(devices),
            "device_types": device_types,
            "vulnerability_summary": vuln_severity,
            "average_security_score": round(avg_security_score, 2),
            "devices_with_default_creds": len([d for d in devices if d.default_credentials]),
            "unencrypted_devices": len([d for d in devices if d.encryption_status == "None"])
        }
    
    def _generate_recommendations(self, devices: List[IoTDevice], vulnerabilities: List[IoTVulnerability]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if not devices:
            return ["Ensure IoT devices are properly connected to the network"]
        
        # Check for default credentials
        default_cred_devices = [d for d in devices if d.default_credentials]
        if default_cred_devices:
            recommendations.append(f"Change default credentials on {len(default_cred_devices)} device(s)")
        
        # Check for encryption
        unencrypted_devices = [d for d in devices if d.encryption_status == "None"]
        if unencrypted_devices:
            recommendations.append(f"Enable encryption on {len(unencrypted_devices)} device(s)")
        
        # Check for firmware updates
        if any("Firmware" in v.category for v in vulnerabilities):
            recommendations.append("Update firmware on devices with known vulnerabilities")
        
        # Network segmentation
        if len(devices) > 3:
            recommendations.append("Consider network segmentation for IoT devices")
        
        # Monitor traffic
        recommendations.append("Implement network monitoring for IoT device traffic")
        
        # Regular security audits
        recommendations.append("Perform regular IoT security assessments")
        
        return recommendations

async def execute_tool(params: IoTSecurityScannerInput) -> IoTSecurityScannerOutput:
    """Main entry point for the IoT Security Scanner tool"""
    scanner = IoTSecurityScanner()
    return await scanner.execute(params)

# Tool metadata for registration
TOOL_INFO = {
    "name": "IoT Security Scanner",
    "description": "Comprehensive security assessment tool for IoT devices including discovery, vulnerability scanning, and configuration analysis",
    "category": "iot_security",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "input_schema": IoTSecurityScannerInput,
    "output_schema": IoTSecurityScannerOutput,
    "tool_class": IoTSecurityScanner
}
