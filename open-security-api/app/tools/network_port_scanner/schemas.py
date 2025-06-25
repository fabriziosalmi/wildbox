from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from standardized_schemas import BaseToolInput, BaseToolOutput


class NetworkPortScannerInput(BaseToolInput):
    """Input schema for Network Port Scanner tool"""
    target: str = Field(..., description="Target IP address or hostname to scan")
    ports: Optional[str] = Field(
        default="1-1000",
        description="Port range to scan (e.g., '1-1000', '80,443,22' or 'top1000')"
    )
    scan_type: str = Field(
        default="tcp",
        description="Type of scan: tcp, udp, or both"
    )
    timeout: int = Field(
        default=3,
        description="Connection timeout in seconds"
    )
    service_detection: bool = Field(
        default=True,
        description="Attempt to detect services running on open ports"
    )
    os_detection: bool = Field(
        default=False,
        description="Attempt OS fingerprinting (may be slower)"
    )


class PortInfo(BaseModel):
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: Optional[int] = None


class NetworkPortScannerOutput(BaseToolOutput):
    """Output schema for Network Port Scanner tool"""
    target: str
    target_ip: str
    ports_scanned: int
    open_ports: List[PortInfo]
    closed_ports: List[int]
    filtered_ports: List[int]
    service_summary: Dict[str, Any]
    os_fingerprint: Optional[Dict[str, Any]] = None
    security_analysis: Dict[str, Any]
    recommendations: List[str]
    scan_duration: float
    timestamp: str
    success: bool
    message: str
