"""Pydantic schemas for the subdomain scanner tool."""

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class SubdomainScannerInput(BaseModel):
    domain: str = Field(..., description="Target domain to scan for subdomains", example="example.com")
    wordlist_size: str = Field(default="medium", description="Wordlist size: small, medium, large", example="medium")
    timeout: int = Field(default=5, description="Timeout in seconds for DNS queries", ge=1, le=30)

class SubdomainResult(BaseModel):
    subdomain: str = Field(..., description="Discovered subdomain")
    ip_addresses: List[str] = Field(..., description="IP addresses for the subdomain")
    status: str = Field(..., description="Status of the subdomain (active/inactive)")

class SubdomainScannerOutput(BaseModel):
    domain: str = Field(..., description="Target domain")
    timestamp: datetime = Field(..., description="Scan timestamp")
    duration: float = Field(..., description="Scan duration in seconds")
    total_found: int = Field(..., description="Total subdomains found")
    subdomains: List[SubdomainResult] = Field(..., description="List of discovered subdomains")
