"""
Metadata Extractor Tool

This tool extracts metadata from various file types including images, documents,
and PDFs. It analyzes EXIF data, document properties, and hidden information
for security and privacy assessment.
"""

import asyncio
import aiohttp
import base64
import hashlib
import tempfile
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
import mimetypes
import re
from urllib.parse import urlparse

try:
    from .schemas import (MetadataExtractorInput, MetadataExtractorOutput, FileInfo,
                         EXIFData, DocumentProperties, HiddenData, SecurityAnalysis)
except ImportError:
    from schemas import (MetadataExtractorInput, MetadataExtractorOutput, FileInfo,
                        EXIFData, DocumentProperties, HiddenData, SecurityAnalysis)


class MetadataExtractor:
    """File Metadata Extraction and Analysis Tool"""
    
    # Supported file types
    SUPPORTED_TYPES = {
        'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'],
        'document': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
        'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
        'text': ['.txt', '.csv', '.json', '.xml', '.html']
    }
    
    # Privacy-sensitive metadata fields
    SENSITIVE_FIELDS = [
        'author', 'creator', 'producer', 'user', 'owner', 'company',
        'gps', 'location', 'latitude', 'longitude', 'address',
        'phone', 'email', 'username', 'computer', 'machine',
        'revision', 'comment', 'annotation', 'track_changes'
    ]
    
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=60)
    
    async def extract_metadata(self, file_url: str = None, file_data: str = None,
                              file_type: str = None, extract_exif: bool = True,
                              extract_document_properties: bool = True,
                              extract_hidden_data: bool = True,
                              timeout: int = 30) -> Dict[str, Any]:
        """Extract metadata from file"""
        
        try:
            # Get file data
            if file_url:
                file_bytes, filename = await self._download_file(file_url, timeout)
            elif file_data:
                file_bytes = base64.b64decode(file_data)
                filename = None
            else:
                raise ValueError("Either file_url or file_data must be provided")
            
            # Analyze file
            file_info = await self._analyze_file(file_bytes, filename, file_type)
            
            # Extract specific metadata based on file type
            exif_data = None
            document_properties = None
            hidden_data = None
            raw_metadata = {}
            
            if file_info.file_type.startswith('image') and extract_exif:
                exif_data = await self._extract_exif_data(file_bytes)
                raw_metadata['exif'] = exif_data
            
            if file_info.file_type in ['pdf', 'document'] and extract_document_properties:
                document_properties = await self._extract_document_properties(file_bytes, file_info.file_type)
                raw_metadata['document'] = document_properties
            
            if extract_hidden_data:
                hidden_data = await self._extract_hidden_data(file_bytes, file_info.file_type)
                raw_metadata['hidden'] = hidden_data
            
            # Perform security analysis
            security_analysis = self._analyze_security(
                file_info, exif_data, document_properties, hidden_data
            )
            
            return {
                'file_info': file_info,
                'exif_data': exif_data,
                'document_properties': document_properties,
                'hidden_data': hidden_data,
                'security_analysis': security_analysis,
                'raw_metadata': raw_metadata
            }
            
        except Exception as e:
            raise Exception(f"Metadata extraction failed: {str(e)}")
    
    async def _download_file(self, url: str, timeout: int) -> tuple:
        """Download file from URL"""
        custom_timeout = aiohttp.ClientTimeout(total=timeout)
        
        async with aiohttp.ClientSession(timeout=custom_timeout) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"Failed to download file: HTTP {response.status}")
                
                file_bytes = await response.read()
                
                # Extract filename from URL or Content-Disposition header
                filename = None
                content_disp = response.headers.get('content-disposition', '')
                if 'filename=' in content_disp:
                    filename = content_disp.split('filename=')[1].strip('"')
                else:
                    parsed_url = urlparse(url)
                    filename = os.path.basename(parsed_url.path)
                
                return file_bytes, filename
    
    async def _analyze_file(self, file_bytes: bytes, filename: str = None,
                           file_type_hint: str = None) -> FileInfo:
        """Analyze basic file information"""
        
        # Calculate file hash
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        
        # Detect file type
        if file_type_hint:
            file_type = file_type_hint
            mime_type = mimetypes.guess_type(f"file.{file_type}")[0] or 'application/octet-stream'
        else:
            # Simple file type detection based on magic bytes
            file_type, mime_type = self._detect_file_type(file_bytes)
        
        return FileInfo(
            filename=filename,
            file_size=len(file_bytes),
            file_type=file_type,
            mime_type=mime_type,
            file_hash=file_hash,
            created_date=None,  # Would require filesystem access
            modified_date=None  # Would require filesystem access
        )
    
    def _detect_file_type(self, file_bytes: bytes) -> tuple:
        """Detect file type from magic bytes"""
        
        # Common file signatures
        signatures = {
            b'\xFF\xD8\xFF': ('jpeg', 'image/jpeg'),
            b'\x89PNG\r\n\x1a\n': ('png', 'image/png'),
            b'GIF87a': ('gif', 'image/gif'),
            b'GIF89a': ('gif', 'image/gif'),
            b'%PDF-': ('pdf', 'application/pdf'),
            b'PK\x03\x04': ('zip', 'application/zip'),
            b'PK\x05\x06': ('zip', 'application/zip'),
            b'\x1f\x8b\x08': ('gzip', 'application/gzip'),
            b'BM': ('bmp', 'image/bmp'),
            b'RIFF': ('wav', 'audio/wav'),
        }
        
        for signature, (file_type, mime_type) in signatures.items():
            if file_bytes.startswith(signature):
                return file_type, mime_type
        
        # Check for Office documents (simplified)
        if b'word' in file_bytes[:1000].lower():
            return 'docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        elif b'excel' in file_bytes[:1000].lower():
            return 'xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        
        return 'unknown', 'application/octet-stream'
    
    async def _extract_exif_data(self, file_bytes: bytes) -> Optional[EXIFData]:
        """Extract EXIF data from images (simplified implementation)"""
        try:
            # This is a simplified implementation
            # In a real tool, you'd use libraries like Pillow or exifread
            
            # Look for EXIF marker in JPEG files
            if file_bytes.startswith(b'\xFF\xD8\xFF'):
                # Simple EXIF simulation for demo
                return EXIFData(
                    camera_make="Demo Camera Make",
                    camera_model="Demo Camera Model",
                    date_taken=datetime.now(),
                    gps_latitude=None,  # Would extract from actual EXIF
                    gps_longitude=None,
                    gps_location=None,
                    image_width=1920,  # Would extract from actual EXIF
                    image_height=1080,
                    iso_speed=100,
                    focal_length="50mm",
                    flash_used=False,
                    software="Demo Image Editor"
                )
            
            return None
            
        except Exception:
            return None
    
    async def _extract_document_properties(self, file_bytes: bytes, file_type: str) -> Optional[DocumentProperties]:
        """Extract document properties (simplified implementation)"""
        try:
            # This is a simplified implementation
            # In a real tool, you'd use libraries like PyPDF2, python-docx, etc.
            
            if file_type == 'pdf':
                # Look for PDF metadata
                content = file_bytes.decode('latin-1', errors='ignore')
                
                # Simple regex patterns for demo
                title_match = re.search(r'/Title\s*\(([^)]+)\)', content)
                author_match = re.search(r'/Author\s*\(([^)]+)\)', content)
                creator_match = re.search(r'/Creator\s*\(([^)]+)\)', content)
                
                return DocumentProperties(
                    title=title_match.group(1) if title_match else None,
                    author=author_match.group(1) if author_match else None,
                    subject=None,
                    creator=creator_match.group(1) if creator_match else None,
                    producer=None,
                    creation_date=None,
                    modification_date=None,
                    keywords=None,
                    page_count=content.count('/Page ') if '/Page ' in content else None,
                    word_count=None,
                    character_count=len(content)
                )
            
            elif file_type in ['docx', 'xlsx', 'pptx']:
                # Office documents are ZIP files
                return DocumentProperties(
                    title="Demo Document Title",
                    author="Demo Author",
                    subject="Demo Subject",
                    creator="Demo Application",
                    producer="Demo Producer",
                    creation_date=datetime.now(),
                    modification_date=datetime.now(),
                    keywords="demo, metadata, extraction",
                    page_count=1,
                    word_count=100,
                    character_count=500
                )
            
            return None
            
        except Exception:
            return None
    
    async def _extract_hidden_data(self, file_bytes: bytes, file_type: str) -> Optional[HiddenData]:
        """Extract hidden data and comments (simplified implementation)"""
        try:
            content = file_bytes.decode('latin-1', errors='ignore')
            
            # Look for common hidden data patterns
            hidden_text = []
            comments = []
            revision_history = []
            deleted_content = []
            personal_info = []
            hyperlinks = []
            embedded_files = []
            
            # Extract URLs
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, content)
            hyperlinks.extend(urls)
            
            # Look for email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, content)
            personal_info.extend(emails)
            
            # Look for potential usernames/paths
            path_pattern = r'[A-Z]:\\Users\\[^\\]+|/home/[^/\s]+'
            paths = re.findall(path_pattern, content)
            personal_info.extend(paths)
            
            # Look for comment markers
            comment_patterns = [
                r'<!--.*?-->',  # HTML comments
                r'/\*.*?\*/',   # CSS/JS comments
                r'//.*?\n',     # Single line comments
            ]
            
            for pattern in comment_patterns:
                matches = re.findall(pattern, content, re.DOTALL)
                comments.extend(matches)
            
            return HiddenData(
                hidden_text=hidden_text,
                comments=comments[:10],  # Limit to first 10
                revision_history=revision_history,
                deleted_content=deleted_content,
                personal_info=personal_info[:10],  # Limit to first 10
                hyperlinks=hyperlinks[:20],  # Limit to first 20
                embedded_files=embedded_files
            )
            
        except Exception:
            return None
    
    def _analyze_security(self, file_info: FileInfo, exif_data: Optional[EXIFData],
                         document_properties: Optional[DocumentProperties],
                         hidden_data: Optional[HiddenData]) -> SecurityAnalysis:
        """Analyze security and privacy implications of metadata"""
        
        privacy_risk = "low"
        exposed_data = []
        recommendations = []
        
        # Calculate metadata size and ratio
        metadata_size = 0
        if exif_data:
            metadata_size += 1000  # Estimated EXIF size
        if document_properties:
            metadata_size += 500   # Estimated document properties size
        if hidden_data:
            metadata_size += len(str(hidden_data))
        
        metadata_ratio = metadata_size / file_info.file_size if file_info.file_size > 0 else 0
        
        # Check for GPS data
        if exif_data and (exif_data.gps_latitude or exif_data.gps_longitude):
            privacy_risk = "high"
            exposed_data.append("GPS coordinates")
            recommendations.append("Remove GPS data before sharing images")
        
        # Check for personal information in document properties
        if document_properties:
            if document_properties.author:
                exposed_data.append("Author name")
                if privacy_risk == "low":
                    privacy_risk = "medium"
            
            if document_properties.creator and any(word in document_properties.creator.lower() 
                                                 for word in ['user', 'admin', 'personal']):
                exposed_data.append("Software/system information")
                if privacy_risk == "low":
                    privacy_risk = "medium"
        
        # Check hidden data
        if hidden_data:
            if hidden_data.personal_info:
                exposed_data.append("Personal information in hidden data")
                privacy_risk = "high"
                recommendations.append("Remove personal information from hidden data")
            
            if hidden_data.comments:
                exposed_data.append("Comments and annotations")
                if privacy_risk == "low":
                    privacy_risk = "medium"
                recommendations.append("Review and remove unnecessary comments")
            
            if hidden_data.hyperlinks:
                exposed_data.append("External hyperlinks")
                recommendations.append("Review external links for privacy implications")
        
        # Check metadata ratio
        if metadata_ratio > 0.1:  # More than 10% metadata
            if privacy_risk == "low":
                privacy_risk = "medium"
            recommendations.append("Large amount of metadata detected - consider cleaning")
        
        # General recommendations
        if not recommendations:
            recommendations.append("Metadata appears clean")
        
        recommendations.append("Always review metadata before sharing sensitive files")
        
        return SecurityAnalysis(
            privacy_risk=privacy_risk,
            exposed_data=exposed_data,
            recommendations=recommendations,
            metadata_size=metadata_size,
            metadata_ratio=round(metadata_ratio, 4)
        )


async def execute_tool(params: MetadataExtractorInput) -> MetadataExtractorOutput:
    """Main entry point for the metadata extractor tool"""
    extractor = MetadataExtractor()
    
    try:
        # Perform metadata extraction
        result = await extractor.extract_metadata(
            file_url=params.file_url,
            file_data=params.file_data,
            file_type=params.file_type,
            extract_exif=params.extract_exif,
            extract_document_properties=params.extract_document_properties,
            extract_hidden_data=params.extract_hidden_data,
            timeout=params.timeout
        )
        
        return MetadataExtractorOutput(
            success=True,
            file_info=result['file_info'],
            exif_data=result['exif_data'],
            document_properties=result['document_properties'],
            hidden_data=result['hidden_data'],
            security_analysis=result['security_analysis'],
            raw_metadata=result['raw_metadata'],
            timestamp=datetime.now(),
            error=None
        )
        
    except Exception as e:
        return MetadataExtractorOutput(
            success=False,
            file_info=FileInfo(
                filename=None,
                file_size=0,
                file_type="unknown",
                mime_type="application/octet-stream",
                file_hash="",
                created_date=None,
                modified_date=None
            ),
            exif_data=None,
            document_properties=None,
            hidden_data=None,
            security_analysis=SecurityAnalysis(
                privacy_risk="unknown",
                exposed_data=[],
                recommendations=[],
                metadata_size=0,
                metadata_ratio=0.0
            ),
            raw_metadata={},
            timestamp=datetime.now(),
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "metadata_extractor",
    "display_name": "Metadata Extractor",
    "description": "Extracts and analyzes metadata from files for security and privacy assessment",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "data_analysis"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        # Test with a sample image URL
        test_input = MetadataExtractorInput(
            file_url="https://via.placeholder.com/150.jpg",
            extract_exif=True,
            extract_document_properties=True,
            extract_hidden_data=True
        )
        result = await execute_tool(test_input)
        print(f"Success: {result.success}")
        if result.success:
            print(f"File Type: {result.file_info.file_type}")
            print(f"File Size: {result.file_info.file_size} bytes")
            print(f"Privacy Risk: {result.security_analysis.privacy_risk}")
        else:
            print(f"Error: {result.error}")
    
    asyncio.run(test())
