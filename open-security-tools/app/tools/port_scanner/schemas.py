from ...standardized_schemas import BaseToolInput, BaseToolOutput
"""Pydantic schemas for the port scanner tool - STANDARDIZED VERSION."""

from pydantic import Field
from typing import Annotated, List, Literal, Optional
import sys
import os

# Add app directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..'))

from ...standardized_schemas import (
    BaseToolInput, 
    BaseToolOutput, 
    NetworkPort,
    ToolCategory,
    ToolMetadata
)

class PortScannerInput(BaseToolInput):
    """Port scanner input schema - inherits from BaseToolInput."""
    # Required here although optional in BaseToolInput: main.py refuses an
    # empty target, so the defaults alone could not run (#611).
    target: str = Field(..., min_length=1, description="Host name or IP address to scan", examples=["127.0.0.1"])
    ports: Optional[List[Annotated[int, Field(ge=1, le=65535)]]] = Field(
        None, description="List of ports to scan. If not provided, scans common ports."
    )
    # main.py performs a TCP connect scan only; udp and syn were offered and
    # ignored (#611).
    scan_type: Literal["tcp"] = Field(default="tcp", description="Scan type (tcp: TCP connect scan)")

class PortScannerOutput(BaseToolOutput):
    """Port scanner output schema - inherits from BaseToolOutput."""
    open_ports: List[NetworkPort] = Field(default_factory=list, description="Open ports found")
    closed_ports: int = Field(default=0, description="Number of closed ports")
    filtered_ports: int = Field(default=0, description="Number of filtered ports")
    scan_statistics: dict = Field(default_factory=dict, description="Scan statistics")

class PortScanResult(BaseToolOutput):
    """Individual port scan result - for backwards compatibility."""
    port: int = Field(description="Port number")
    state: str = Field(description="Port state (open/closed/filtered)")
    service: Optional[str] = Field(None, description="Service running on port")
    version: Optional[str] = Field(None, description="Service version if detected")

# Tool metadata for registration
TOOL_METADATA = ToolMetadata(
    name="port_scanner",
    version="1.0.0",
    category=ToolCategory.NETWORK_SCANNING,
    description="Network port scanner for discovering open services",
    author="Wildbox Security",
    tags=["network", "scanning", "ports", "tcp", "udp"]
)
