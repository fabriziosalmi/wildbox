from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union

class IoTSecurityScannerInput(BaseModel):
    """Input schema for IoT Security Scanner tool"""
    target_ip: Optional[str] = Field(None, description="Target IoT device IP address")
    ip_range: Optional[str] = Field(None, description="IP range to scan for IoT devices (CIDR notation)")
    device_type: str = Field(default="unknown", description="Known device type (camera, router, smart_home, industrial)")
    scan_depth: str = Field(default="standard", description="Scan depth (quick, standard, comprehensive)")
    check_default_credentials: bool = Field(default=True, description="Test for default credentials")
    check_firmware: bool = Field(default=True, description="Analyze firmware security")
    check_encryption: bool = Field(default=True, description="Check encryption implementations")
    check_network_protocols: bool = Field(default=True, description="Analyze network protocol security")
    check_web_interface: bool = Field(default=True, description="Scan web management interface")
    port_scan_range: str = Field(default="1-10000", description="Port range to scan")
    timeout: int = Field(default=30, description="Scan timeout in seconds")

class IoTDevice(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    device_type: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    open_ports: List[int]
    services: Dict[int, str]  # port -> service
    web_interface: Optional[str] = None
    default_credentials: bool
    encryption_status: str  # Strong, Weak, None
    security_score: float

class IoTVulnerability(BaseModel):
    device_ip: str
    severity: str  # Critical, High, Medium, Low
    category: str
    title: str
    description: str
    port: Optional[int] = None
    service: Optional[str] = None
    proof_of_concept: Optional[str] = None
    cve_id: Optional[str] = None
    remediation: str

class NetworkProtocolAnalysis(BaseModel):
    protocol: str
    port: int
    encryption: bool
    authentication: bool
    vulnerabilities: List[str]
    recommendations: List[str]

class FirmwareAnalysis(BaseModel):
    device_ip: str
    firmware_version: Optional[str] = None
    known_vulnerabilities: List[str]
    outdated: bool
    update_available: bool
    security_features: List[str]
    missing_features: List[str]

class IoTSecurityScannerOutput(BaseModel):
    """Output schema for IoT Security Scanner tool"""
    devices_found: List[IoTDevice]
    vulnerabilities: List[IoTVulnerability]
    network_protocols: List[NetworkProtocolAnalysis]
    scan_summary: Dict[str, Any]
    total_devices: int
    critical_vulnerabilities: int
    recommendations: List[str]

# Tool metadata
TOOL_INFO = {
    "name": "IoT Security Scanner",
    "description": "Comprehensive IoT device security scanner for identifying vulnerabilities, weak configurations, and security issues in connected devices",
    "category": "iot_security",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["iot", "devices", "firmware", "protocols", "embedded", "security"]
}
