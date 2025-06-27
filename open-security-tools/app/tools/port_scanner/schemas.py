from standardized_schemas import BaseToolInput, BaseToolOutput
"""Pydantic schemas for the port scanner tool - STANDARDIZED VERSION."""

from pydantic import Field
from typing import List, Optional
import sys
import os

# Add app directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..'))

from app.standardized_schemas import (
    BaseToolInput, 
    BaseToolOutput, 
    NetworkPort,
    ToolCategory,
    ToolMetadata
)

class PortScannerInput(BaseToolInput):
    """Port scanner input schema - inherits from BaseToolInput."""
    ports: Optional[List[int]] = Field(None, description="List of ports to scan. If not provided, scans common ports.")
    scan_type: str = Field(default="tcp", description="Scan type (tcp/udp/syn)")

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
