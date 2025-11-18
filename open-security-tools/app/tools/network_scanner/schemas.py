"""
Pydantic schemas for the Secure Network Scanner tool.
"""

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class SecureNetworkScannerInput(BaseModel):
    network: str = Field(
        description="Network to scan in CIDR notation or a single IP.",
        json_schema_extra={'example': "192.168.1.0/24"}
    )
    timeout: int = Field(
        default=1,
        ge=1,
        le=10,
        description="Timeout in seconds for each ping."
    )
    max_concurrent_scans: int = Field(
        default=100,
        ge=1,
        le=200,
        description="Maximum number of concurrent pings."
    )

class HostInfo(BaseModel):
    ip_address: str
    status: str
    response_time: Optional[float] = None

class SecureNetworkScannerOutput(BaseModel):
    success: bool
    error: Optional[str] = None
    timestamp: datetime
    scan_duration: float
    summary: Optional[str] = None
    hosts: List[HostInfo]
