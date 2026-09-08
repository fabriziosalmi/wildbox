"""
Schemas for Metadata Extractor Tool
"""

from pydantic import BaseModel, Field
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any, Union
from datetime import datetime


class MetadataExtractorInput(BaseToolInput):
    """Input schema for metadata extraction"""
    file_url: Optional[str] = Field(
        default=None,
        description="URL of file to analyze (alternative to file_data)"
    )
    file_data: Optional[str] = Field(
        default=None,
        description="Base64 encoded file data (alternative to file_url)"
    )
    file_type: Optional[str] = Field(
        default=None,
        description="File type hint (pdf, docx, xlsx, jpg, png, etc.)"
    )
    extract_exif: bool = Field(
        default=True,
        description="Extract EXIF data from images"
    )
    extract_document_properties: bool = Field(
        default=True,
        description="Extract document properties (title, author, etc.)"
    )
    extract_hidden_data: bool = Field(
        default=True,
        description="Extract hidden data and comments"
    )
    timeout: int = Field(
        default=30,
        ge=1,
        le=120,
        description="Processing timeout in seconds"
    )


class FileInfo(BaseModel):
    """Basic file information"""
    filename: Optional[str] = Field(description="Original filename")
    file_size: int = Field(description="File size in bytes")
    file_type: str = Field(description="Detected file type")
    mime_type: str = Field(description="MIME type")
    file_hash: str = Field(description="SHA256 hash of file")
    created_date: Optional[datetime] = Field(description="File creation date")
    modified_date: Optional[datetime] = Field(description="File modification date")


class EXIFData(BaseModel):
    """EXIF metadata from images"""
    camera_make: Optional[str] = Field(description="Camera manufacturer")
    camera_model: Optional[str] = Field(description="Camera model")
    date_taken: Optional[datetime] = Field(description="Date photo was taken")
    gps_latitude: Optional[float] = Field(description="GPS latitude")
    gps_longitude: Optional[float] = Field(description="GPS longitude")
    gps_location: Optional[str] = Field(description="Approximate location")
    image_width: Optional[int] = Field(description="Image width in pixels")
    image_height: Optional[int] = Field(description="Image height in pixels")
    iso_speed: Optional[int] = Field(description="ISO speed rating")
    focal_length: Optional[str] = Field(description="Focal length")
    flash_used: Optional[bool] = Field(description="Whether flash was used")
    software: Optional[str] = Field(description="Software used to process image")


class DocumentProperties(BaseModel):
    """Document metadata properties"""
    title: Optional[str] = Field(description="Document title")
    author: Optional[str] = Field(description="Document author")
    subject: Optional[str] = Field(description="Document subject")
    creator: Optional[str] = Field(description="Application that created document")
    producer: Optional[str] = Field(description="Application that produced document")
    creation_date: Optional[datetime] = Field(description="Document creation date")
    modification_date: Optional[datetime] = Field(description="Last modification date")
    keywords: Optional[str] = Field(description="Document keywords")
    page_count: Optional[int] = Field(description="Number of pages")
    word_count: Optional[int] = Field(description="Word count")
    character_count: Optional[int] = Field(description="Character count")


class HiddenData(BaseModel):
    """Hidden data and security issues"""
    hidden_text: List[str] = Field(description="Hidden text content")
    comments: List[str] = Field(description="Comments and annotations")
    revision_history: List[str] = Field(description="Revision history")
    deleted_content: List[str] = Field(description="Deleted content that may be recoverable")
    personal_info: List[str] = Field(description="Personal information found")
    hyperlinks: List[str] = Field(description="External hyperlinks")
    embedded_files: List[str] = Field(description="Embedded files")


class SecurityAnalysis(BaseModel):
    """Security analysis of metadata"""
    privacy_risk: str = Field(description="Privacy risk level (low, medium, high, critical)")
    exposed_data: List[str] = Field(description="Types of potentially exposed data")
    recommendations: List[str] = Field(description="Security recommendations")
    metadata_size: int = Field(description="Total metadata size in bytes")
    metadata_ratio: float = Field(description="Metadata to file size ratio")


class MetadataExtractorOutput(BaseToolOutput):
    """Output schema for metadata extraction"""
    success: bool = Field(description="Whether extraction was successful")
    file_info: FileInfo = Field(description="Basic file information")
    exif_data: Optional[EXIFData] = Field(description="EXIF metadata (for images)")
    document_properties: Optional[DocumentProperties] = Field(description="Document properties")
    hidden_data: Optional[HiddenData] = Field(description="Hidden data found")
    security_analysis: SecurityAnalysis = Field(description="Security analysis")
    raw_metadata: Dict[str, Any] = Field(description="Raw metadata dump")
    timestamp: datetime = Field(description="Extraction timestamp")
    error: Optional[str] = Field(default=None, description="Error message if extraction failed")
