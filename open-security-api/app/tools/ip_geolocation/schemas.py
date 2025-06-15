"""
Schemas for IP Geolocation Tool
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class IPGeolocationInput(BaseModel):
    """Input schema for IP geolocation lookup"""
    ip_address: str = Field(
        description="IP address to geolocate",
        example="8.8.8.8"
    )
    include_isp_info: bool = Field(
        default=True,
        description="Include ISP and organization information"
    )
    include_threat_intel: bool = Field(
        default=True,
        description="Include threat intelligence data"
    )
    include_whois: bool = Field(
        default=True,
        description="Include WHOIS information"
    )
    timeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="Request timeout in seconds"
    )


class GeolocationData(BaseModel):
    """Geolocation information"""
    country: Optional[str] = Field(description="Country name")
    country_code: Optional[str] = Field(description="Country code (ISO 3166-1 alpha-2)")
    region: Optional[str] = Field(description="Region/state name")
    region_code: Optional[str] = Field(description="Region/state code")
    city: Optional[str] = Field(description="City name")
    postal_code: Optional[str] = Field(description="Postal/ZIP code")
    latitude: Optional[float] = Field(description="Latitude coordinate")
    longitude: Optional[float] = Field(description="Longitude coordinate")
    timezone: Optional[str] = Field(description="Timezone")


class ISPInfo(BaseModel):
    """ISP and organization information"""
    isp: Optional[str] = Field(description="Internet Service Provider")
    organization: Optional[str] = Field(description="Organization name")
    asn: Optional[int] = Field(description="Autonomous System Number")
    asn_name: Optional[str] = Field(description="AS organization name")


class ThreatIntel(BaseModel):
    """Threat intelligence information"""
    is_malicious: bool = Field(description="Whether IP is flagged as malicious")
    threat_types: List[str] = Field(description="Types of threats detected")
    reputation_score: Optional[int] = Field(description="Reputation score (0-100)")
    last_seen: Optional[str] = Field(description="Last seen in threat feeds")
    blacklist_sources: List[str] = Field(description="Blacklist sources")


class WHOISInfo(BaseModel):
    """WHOIS information"""
    network_range: Optional[str] = Field(description="Network range")
    allocation_date: Optional[str] = Field(description="Allocation date")
    registry: Optional[str] = Field(description="Regional Internet Registry")
    registrant: Optional[str] = Field(description="Registrant organization")
    admin_contact: Optional[str] = Field(description="Administrative contact")
    tech_contact: Optional[str] = Field(description="Technical contact")


class IPGeolocationOutput(BaseModel):
    """Output schema for IP geolocation lookup"""
    success: bool = Field(description="Whether the lookup was successful")
    ip_address: str = Field(description="IP address that was analyzed")
    ip_version: int = Field(description="IP version (4 or 6)")
    is_private: bool = Field(description="Whether IP is in private range")
    is_reserved: bool = Field(description="Whether IP is in reserved range")
    geolocation: GeolocationData = Field(description="Geolocation information")
    isp_info: Optional[ISPInfo] = Field(description="ISP and organization information")
    threat_intel: Optional[ThreatIntel] = Field(description="Threat intelligence data")
    whois_info: Optional[WHOISInfo] = Field(description="WHOIS information")
    accuracy_radius: Optional[int] = Field(description="Geolocation accuracy radius in kilometers")
    data_sources: List[str] = Field(description="Data sources used")
    timestamp: datetime = Field(description="Lookup timestamp")
    error: Optional[str] = Field(default=None, description="Error message if lookup failed")
