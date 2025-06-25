"""Pydantic schemas for the email harvester tool."""

from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict
from datetime import datetime

class EmailHarvesterInput(BaseToolInput):
    domain: str = Field(..., description="Target domain to harvest emails from", example="example.com")
    search_engines: Optional[List[str]] = Field(default=["google", "bing"], description="Search engines to use")
    max_results: int = Field(default=100, description="Maximum results per search engine", ge=10, le=500)
    timeout: int = Field(default=10, description="Request timeout in seconds", ge=1, le=60)

class EmailSource(BaseModel):
    email: str = Field(..., description="Discovered email address")
    source: str = Field(..., description="Source where email was found")
    url: Optional[str] = Field(None, description="URL where email was discovered")

class EmailHarvesterOutput(BaseToolOutput):
    domain: str = Field(..., description="Target domain")
    timestamp: datetime = Field(..., description="Harvest timestamp")
    total_emails: int = Field(..., description="Total unique emails found")
    sources_searched: List[str] = Field(..., description="Search engines and sources used")
    emails: List[EmailSource] = Field(..., description="Discovered email addresses")
    statistics: Dict[str, int] = Field(..., description="Statistics by source")
