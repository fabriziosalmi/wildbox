"""Pydantic schemas for the network scanner (fixed) tool."""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput, CaseInsensitiveChoice
from typing import List, Optional, Dict
from datetime import datetime

# Compared regardless of case by main.py (#611).
ScanType = CaseInsensitiveChoice("ping", "tcp")


class NetworkScannerInput(BaseToolInput):
    network: str = Field(
        ...,
        description=(
            "Address, CIDR range (a.b.c.0/24) or last-octet range (a.b.c.10-20) "
            "to scan; at most 1024 addresses. Private and other internal "
            "ranges, such as 192.168.1.0/24, are refused unless the operator "
            "allows them (TOOLS_ALLOWED_INTERNAL_TARGETS)"
        ),
        # A value the default target policy accepts: the dashboard shows it
        # as the field's placeholder. It was 192.168.1.0/24, which the
        # service refuses (#646).
        example="8.8.8.8",
    )
    # main.py implements ping and tcp; "comprehensive" and any other value
    # ran a ping scan (#611).
    scan_type: ScanType = Field(default="ping", description="Scan type: ping or tcp", example="ping")
    timeout: int = Field(default=3, description="Timeout in seconds for each host", ge=1, le=30)
    max_threads: int = Field(default=50, description="Maximum concurrent probes (pings and TCP connects)", ge=1, le=100)

class HostInfo(BaseModel):
    ip_address: str = Field(..., description="IP address of the host")
    hostname: Optional[str] = Field(None, description="Hostname if resolvable")
    status: str = Field(..., description="Host status: alive, dead, timeout or error")
    response_time: Optional[float] = Field(None, description="Response time in milliseconds")
    open_ports: List[int] = Field(default=[], description="List of open ports")
    os_guess: Optional[str] = Field(None, description="Operating system guess")
    mac_address: Optional[str] = Field(None, description="MAC address if available")
    # main.py set error= on every failed probe, a field this model lacked.
    error: Optional[str] = Field(None, description="Why the probe of this host failed")

class NetworkScannerOutput(BaseToolOutput):
    network: str = Field(..., description="Scanned network range")
    timestamp: datetime = Field(..., description="Scan timestamp")
    total_hosts: int = Field(..., description="Total hosts in range")
    alive_hosts: int = Field(..., description="Number of alive hosts")
    scan_duration: float = Field(..., description="Total scan duration in seconds")
    hosts: List[HostInfo] = Field(..., description="Detailed host information")
