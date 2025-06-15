"""Pydantic schemas for the port scanner tool."""

from pydantic import BaseModel, Field
from typing import List, Optional

class PortScannerInput(BaseModel):
    target: str = Field(..., description="Target domain or IP address to scan", example="example.com")
    ports: Optional[List[int]] = Field(None, description="List of ports to scan. If not provided, scans common ports.")
    timeout: int = Field(default=3, description="Timeout in seconds for each port scan.", ge=1, le=60)

class PortScanResult(BaseModel):
    port: int = Field(..., description="Port number")
    state: str = Field(..., description="Port state (open/closed)")
    service: Optional[str] = Field(None, description="Service running on the port, if detected.")

class PortScannerOutput(BaseModel):
    target: str = Field(..., description="Scanned target")
    results: List[PortScanResult] = Field(..., description="List of port scan results.")
