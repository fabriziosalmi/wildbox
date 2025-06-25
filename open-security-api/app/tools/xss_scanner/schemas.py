"""Pydantic schemas for the XSS scanner tool."""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict
from datetime import datetime

class XSSScannerInput(BaseToolInput):
    target_url: str = Field(..., description="Target URL to test for XSS", example="https://example.com/search")
    method: str = Field(default="GET", description="HTTP method to use", example="GET")
    parameters: Optional[Dict[str, str]] = Field(None, description="Parameters to test", example={"q": "test", "category": "all"})
    headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")
    payload_type: str = Field(default="all", description="Payload type: reflected, stored, dom, all", example="all")
    timeout: int = Field(default=10, description="Request timeout in seconds", ge=1, le=60)

class XSSResult(BaseModel):
    parameter: str = Field(..., description="Parameter that was tested")
    payload: str = Field(..., description="XSS payload used")
    xss_type: str = Field(..., description="Type of XSS (reflected, stored, dom)")
    vulnerable: bool = Field(..., description="Whether XSS vulnerability was detected")
    evidence: Optional[str] = Field(None, description="Evidence of successful XSS")
    response_time: float = Field(..., description="Response time in seconds")
    confidence: str = Field(..., description="Confidence level: low, medium, high")

class XSSScannerOutput(BaseToolOutput):
    target_url: str = Field(..., description="Target URL that was tested")
    timestamp: datetime = Field(..., description="Scan timestamp")
    total_tests: int = Field(..., description="Total number of tests performed")
    vulnerabilities_found: int = Field(..., description="Number of vulnerabilities found")
    results: List[XSSResult] = Field(..., description="Detailed test results")
    recommendations: List[str] = Field(..., description="Security recommendations")
