"""Pydantic schemas for the SQL injection scanner tool."""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime

class SQLInjectionScannerInput(BaseModel):
    target_url: str = Field(..., description="Target URL to test for SQL injection", example="https://example.com/login.php")
    method: str = Field(default="GET", description="HTTP method to use", example="GET")
    parameters: Optional[Dict[str, str]] = Field(None, description="Parameters to test", example={"id": "1", "name": "test"})
    headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")
    timeout: int = Field(default=10, description="Request timeout in seconds", ge=1, le=60)

class SQLInjectionResult(BaseModel):
    parameter: str = Field(..., description="Parameter that was tested")
    payload: str = Field(..., description="SQL injection payload used")
    vulnerable: bool = Field(..., description="Whether vulnerability was detected")
    error_message: Optional[str] = Field(None, description="Database error message if detected")
    response_time: float = Field(..., description="Response time in seconds")

class SQLInjectionScannerOutput(BaseModel):
    target_url: str = Field(..., description="Target URL that was tested")
    timestamp: datetime = Field(..., description="Scan timestamp")
    total_tests: int = Field(..., description="Total number of tests performed")
    vulnerabilities_found: int = Field(..., description="Number of vulnerabilities found")
    results: List[SQLInjectionResult] = Field(..., description="Detailed test results")
    recommendations: List[str] = Field(..., description="Security recommendations")
