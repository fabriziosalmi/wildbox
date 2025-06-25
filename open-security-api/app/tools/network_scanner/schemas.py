"""Pydantic schemas for the network scanner tool."""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict
from datetime import datetime

class NetworkScannerInput(BaseToolInput):
    network: str = Field(..., description="Network range to scan (CIDR notation)", example="192.168.1.0/24")
    scan_type: str = Field(default="ping", description="Scan type: ping, tcp, comprehensive", example="ping")
    timeout: int = Field(default=3, description="Timeout in seconds for each host", ge=1, le=30)
    max_threads: int = Field(default=50, description="Maximum concurrent threads", ge=1, le=100)

class HostInfo(BaseModel):
    ip_address: str = Field(..., description="IP address of the host")
    hostname: Optional[str] = Field(None, description="Hostname if resolvable")
    status: str = Field(..., description="Host status (alive/dead)")
    response_time: Optional[float] = Field(None, description="Response time in milliseconds")
    open_ports: List[int] = Field(default=[], description="List of open ports")
    os_guess: Optional[str] = Field(None, description="Operating system guess")
    mac_address: Optional[str] = Field(None, description="MAC address if available")

class NetworkScannerOutput(BaseToolOutput):
    network: str = Field(..., description="Scanned network range")
    timestamp: datetime = Field(..., description="Scan timestamp")
    total_hosts: int = Field(..., description="Total hosts in range")
    alive_hosts: int = Field(..., description="Number of alive hosts")
    scan_duration: float = Field(..., description="Total scan duration in seconds")
    hosts: List[HostInfo] = Field(..., description="Detailed host information")
