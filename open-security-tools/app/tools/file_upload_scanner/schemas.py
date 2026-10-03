"""Pydantic schemas for the file upload scanner tool."""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Literal, Optional, Dict
from datetime import datetime

class FileUploadScannerInput(BaseToolInput):
    target_url: str = Field(..., description="Target URL with file upload functionality", example="https://example.com/upload")
    file_param: str = Field(default="file", description="File parameter name", example="file")
    additional_params: Optional[Dict[str, str]] = Field(None, description="Additional form parameters")
    # The test groups main.py maps to test files; an unknown name was dropped
    # silently (#611).
    test_types: List[Literal[
        "extension", "content_type", "magic_bytes", "path_traversal",
        "large_file", "executable", "all",
    ]] = Field(
        default=["extension", "content_type", "magic_bytes"], min_length=1,
        description="Types of tests to perform (extension, content_type, magic_bytes, "
                    "path_traversal, large_file, executable, or all)"
    )
    timeout: int = Field(default=30, description="Request timeout in seconds", ge=5, le=120)

class FileUploadResult(BaseModel):
    test_type: str = Field(..., description="Type of test performed")
    filename: str = Field(..., description="Filename used in test")
    content_type: str = Field(..., description="Content-Type used")
    file_content: str = Field(..., description="File content used")
    upload_successful: bool = Field(..., description="Whether upload was successful")
    response_status: int = Field(..., description="HTTP response status code")
    vulnerability_detected: bool = Field(..., description="Whether a vulnerability was detected")
    evidence: Optional[str] = Field(None, description="Evidence of vulnerability")
    risk_level: str = Field(..., description="Risk level: low, medium, high, critical")

class FileUploadScannerOutput(BaseToolOutput):
    target_url: str = Field(..., description="Target URL that was tested")
    timestamp: datetime = Field(..., description="Scan timestamp")
    total_tests: int = Field(..., description="Total number of tests performed")
    vulnerabilities_found: int = Field(..., description="Number of vulnerabilities found")
    results: List[FileUploadResult] = Field(..., description="Detailed test results")
    recommendations: List[str] = Field(..., description="Security recommendations")
