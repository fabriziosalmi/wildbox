"""DNS enumeration tool schemas."""

from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum


class RecordType(str, Enum):
    """DNS record types to query."""
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"


class EnumerationMode(str, Enum):
    """DNS enumeration modes."""
    BASIC = "basic"
    COMPREHENSIVE = "comprehensive"
    SUBDOMAIN_BRUTE = "subdomain_brute"


class DNSEnumeratorInput(BaseModel):
    """Input schema for the DNS enumeration tool."""
    
    target_domain: str = Field(
        ...,
        description="Target domain to enumerate",
        example="example.com"
    )
    enumeration_mode: EnumerationMode = Field(
        default=EnumerationMode.BASIC,
        description="Type of DNS enumeration to perform"
    )
    record_types: List[RecordType] = Field(
        default=[RecordType.A, RecordType.AAAA, RecordType.MX, RecordType.NS, RecordType.TXT],
        description="DNS record types to query"
    )
    subdomain_wordlist: Optional[str] = Field(
        default="common",
        description="Wordlist for subdomain brute forcing (common, extensive, custom)"
    )
    max_subdomains: int = Field(
        default=100,
        description="Maximum number of subdomains to test",
        ge=10,
        le=1000
    )
    dns_servers: List[str] = Field(
        default=["8.8.8.8", "1.1.1.1"],
        description="DNS servers to use for queries"
    )
    timeout: int = Field(
        default=30,
        description="Timeout in seconds for DNS queries",
        ge=5,
        le=120
    )
    check_zone_transfer: bool = Field(
        default=True,
        description="Attempt zone transfer (AXFR)"
    )


class DNSRecord(BaseModel):
    """DNS record information."""
    
    name: str = Field(..., description="Record name/hostname")
    type: str = Field(..., description="Record type (A, CNAME, etc.)")
    value: str = Field(..., description="Record value/target")
    ttl: Optional[int] = Field(None, description="Time to live in seconds")


class SubdomainInfo(BaseModel):
    """Subdomain discovery information."""
    
    subdomain: str = Field(..., description="Discovered subdomain")
    ip_addresses: List[str] = Field(default=[], description="IP addresses")
    cname: Optional[str] = Field(None, description="CNAME record if present")
    status: str = Field(..., description="Discovery status (active/inactive)")


class ZoneTransferResult(BaseModel):
    """Zone transfer attempt result."""
    
    server: str = Field(..., description="DNS server tested")
    successful: bool = Field(..., description="Whether zone transfer succeeded")
    records: List[DNSRecord] = Field(default=[], description="Records obtained if successful")
    error: Optional[str] = Field(None, description="Error message if failed")


class DNSEnumeratorOutput(BaseModel):
    """Output schema for the DNS enumeration tool."""
    
    target_domain: str = Field(..., description="Target domain that was enumerated")
    enumeration_mode: str = Field(..., description="Enumeration mode used")
    timestamp: datetime = Field(..., description="When the enumeration was performed")
    duration: float = Field(..., description="Enumeration duration in seconds")
    status: str = Field(..., description="Enumeration status")
    dns_records: List[DNSRecord] = Field(default=[], description="DNS records discovered")
    subdomains: List[SubdomainInfo] = Field(default=[], description="Subdomains discovered")
    zone_transfers: List[ZoneTransferResult] = Field(default=[], description="Zone transfer results")
    name_servers: List[str] = Field(default=[], description="Authoritative name servers")
    mail_servers: List[str] = Field(default=[], description="Mail servers (MX records)")
    security_findings: List[str] = Field(default=[], description="Security-related findings")
    statistics: Dict[str, int] = Field(default={}, description="Enumeration statistics")
    recommendations: List[str] = Field(default=[], description="Security recommendations")
