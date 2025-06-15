"""Pydantic schemas for the WHOIS lookup tool."""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class WHOISLookupInput(BaseModel):
    domain: str = Field(..., description="Domain to lookup", example="example.com")
    include_raw: bool = Field(default=False, description="Include raw WHOIS data")
    timeout: int = Field(default=30, description="Timeout in seconds", ge=5, le=120)

class WHOISContact(BaseModel):
    name: Optional[str] = Field(None, description="Contact name")
    organization: Optional[str] = Field(None, description="Organization")
    email: Optional[str] = Field(None, description="Email address")
    phone: Optional[str] = Field(None, description="Phone number")
    address: Optional[str] = Field(None, description="Physical address")

class WHOISResult(BaseModel):
    domain: str = Field(..., description="Domain name")
    registrar: Optional[str] = Field(None, description="Domain registrar")
    registration_date: Optional[datetime] = Field(None, description="Registration date")
    expiration_date: Optional[datetime] = Field(None, description="Expiration date")
    last_updated: Optional[datetime] = Field(None, description="Last updated date")
    name_servers: List[str] = Field(default=[], description="Name servers")
    status: List[str] = Field(default=[], description="Domain status")
    registrant: Optional[WHOISContact] = Field(None, description="Registrant contact")
    admin_contact: Optional[WHOISContact] = Field(None, description="Administrative contact")
    tech_contact: Optional[WHOISContact] = Field(None, description="Technical contact")
    dnssec: Optional[str] = Field(None, description="DNSSEC status")
    
class WHOISLookupOutput(BaseModel):
    timestamp: datetime = Field(..., description="Lookup timestamp")
    domain: str = Field(..., description="Queried domain")
    success: bool = Field(..., description="Whether lookup was successful")
    result: Optional[WHOISResult] = Field(None, description="Parsed WHOIS data")
    raw_data: Optional[str] = Field(None, description="Raw WHOIS response")
    error_message: Optional[str] = Field(None, description="Error message if lookup failed")
    days_until_expiry: Optional[int] = Field(None, description="Days until domain expires")
