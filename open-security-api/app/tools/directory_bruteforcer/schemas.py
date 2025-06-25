"""Pydantic schemas for the directory brute forcer tool."""

from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict
from datetime import datetime

class DirectoryBruteforcerInput(BaseToolInput):
    target_url: str = Field(..., description="Target URL to brute force", example="https://example.com")
    wordlist_size: str = Field(default="medium", description="Wordlist size: small, medium, large", example="medium")
    extensions: Optional[List[str]] = Field(default=["php", "html", "txt", "js"], description="File extensions to test")
    threads: int = Field(default=10, description="Number of concurrent threads", ge=1, le=50)
    timeout: int = Field(default=5, description="Request timeout in seconds", ge=1, le=30)

class DirectoryResult(BaseModel):
    path: str = Field(..., description="Discovered path")
    status_code: int = Field(..., description="HTTP status code")
    size: int = Field(..., description="Response size in bytes")
    response_time: float = Field(..., description="Response time in seconds")

class DirectoryBruteforcerOutput(BaseToolOutput):
    target_url: str = Field(..., description="Target URL that was tested")
    timestamp: datetime = Field(..., description="Scan timestamp")
    total_requests: int = Field(..., description="Total requests made")
    found_paths: int = Field(..., description="Number of paths found")
    results: List[DirectoryResult] = Field(..., description="Discovered paths and files")
    duration: float = Field(..., description="Total scan duration in seconds")
