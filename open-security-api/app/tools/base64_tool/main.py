"""
Base64 Encoder/Decoder Tool

This tool provides comprehensive Base64 encoding and decoding functionality
with support for various formats and validation.
"""

import base64
import re
import binascii
from typing import Optional, Dict, Any

try:
    from .schemas import Base64ToolInput, Base64ToolOutput
except ImportError:
    from schemas import Base64ToolInput, Base64ToolOutput


class Base64Tool:
    """Base64 encoder/decoder with advanced features"""
    
    # Common file signatures for content type detection
    FILE_SIGNATURES = {
        b'\x89PNG\r\n\x1a\n': 'image/png',
        b'\xff\xd8\xff': 'image/jpeg',
        b'GIF87a': 'image/gif',
        b'GIF89a': 'image/gif',
        b'%PDF-': 'application/pdf',
        b'PK\x03\x04': 'application/zip',
        b'PK\x05\x06': 'application/zip',
        b'PK\x07\x08': 'application/zip',
        b'\x1f\x8b\x08': 'application/gzip',
        b'BM': 'image/bmp',
        b'RIFF': 'audio/wav',
        b'\x00\x00\x00 ftypmp4': 'video/mp4',
        b'\x00\x00\x00\x18ftypmp4': 'video/mp4',
        b'<?xml': 'text/xml',
        b'<!DOCTYPE': 'text/html',
        b'<html': 'text/html',
        b'{"': 'application/json',
        b'[{': 'application/json',
    }
    
    def __init__(self):
        pass
    
    def encode(
        self,
        data: str,
        url_safe: bool = False,
        remove_padding: bool = False,
        chunk_size: Optional[int] = None
    ) -> Dict[str, Any]:
        """Encode data to Base64"""
        try:
            # Convert string to bytes
            data_bytes = data.encode('utf-8')
            
            # Perform encoding
            if url_safe:
                encoded_bytes = base64.urlsafe_b64encode(data_bytes)
            else:
                encoded_bytes = base64.b64encode(data_bytes)
            
            # Convert to string
            encoded_str = encoded_bytes.decode('ascii')
            
            # Remove padding if requested
            if remove_padding:
                encoded_str = encoded_str.rstrip('=')
            
            # Add chunks if requested
            if chunk_size:
                encoded_str = self._add_chunks(encoded_str, chunk_size)
            
            # Calculate efficiency
            efficiency = (len(data_bytes) / len(encoded_bytes)) * 100
            
            encoding_info = {
                'url_safe': url_safe,
                'padding_removed': remove_padding,
                'chunked': chunk_size is not None,
                'chunk_size': chunk_size,
                'efficiency_percent': round(efficiency, 2),
                'expansion_ratio': round(len(encoded_bytes) / len(data_bytes), 2)
            }
            
            return {
                'output': encoded_str,
                'encoding_info': encoding_info,
                'valid': True
            }
            
        except Exception as e:
            raise Exception(f"Encoding failed: {str(e)}")
    
    def decode(
        self,
        data: str,
        url_safe: bool = False,
        validate_input: bool = True
    ) -> Dict[str, Any]:
        """Decode Base64 data"""
        try:
            # Clean the input
            cleaned_data = self._clean_base64_input(data)
            
            # Validate if requested
            is_valid = True
            if validate_input:
                is_valid = self._validate_base64(cleaned_data, url_safe)
                if not is_valid:
                    raise ValueError("Invalid Base64 input")
            
            # Add padding if necessary
            padded_data = self._add_padding(cleaned_data)
            
            # Perform decoding
            try:
                if url_safe:
                    decoded_bytes = base64.urlsafe_b64decode(padded_data)
                else:
                    decoded_bytes = base64.b64decode(padded_data)
            except Exception:
                # Try the other method if the first fails
                if url_safe:
                    decoded_bytes = base64.b64decode(padded_data)
                else:
                    decoded_bytes = base64.urlsafe_b64decode(padded_data)
            
            # Try to decode as UTF-8 text
            try:
                decoded_str = decoded_bytes.decode('utf-8')
                is_text = True
            except UnicodeDecodeError:
                # If not valid UTF-8, represent as hex
                decoded_str = decoded_bytes.hex()
                is_text = False
            
            # Detect content type
            content_type = self._detect_content_type(decoded_bytes)
            
            encoding_info = {
                'is_text': is_text,
                'is_binary': not is_text,
                'detected_encoding': 'utf-8' if is_text else 'binary',
                'padding_added': len(padded_data) > len(cleaned_data),
                'original_had_padding': '=' in data
            }
            
            return {
                'output': decoded_str,
                'encoding_info': encoding_info,
                'valid': is_valid,
                'content_type': content_type
            }
            
        except Exception as e:
            raise Exception(f"Decoding failed: {str(e)}")
    
    def _clean_base64_input(self, data: str) -> str:
        """Clean Base64 input by removing whitespace and line breaks"""
        return re.sub(r'\s+', '', data)
    
    def _validate_base64(self, data: str, url_safe: bool = False) -> bool:
        """Validate Base64 input"""
        if not data:
            return False
        
        # Check character set
        if url_safe:
            valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=')
        else:
            valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        
        if not all(c in valid_chars for c in data):
            return False
        
        # Check length (should be multiple of 4 after padding)
        padded_data = self._add_padding(data)
        if len(padded_data) % 4 != 0:
            return False
        
        # Try to decode to verify
        try:
            if url_safe:
                base64.urlsafe_b64decode(padded_data)
            else:
                base64.b64decode(padded_data)
            return True
        except Exception:
            return False
    
    def _add_padding(self, data: str) -> str:
        """Add padding to Base64 string if necessary"""
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return data
    
    def _add_chunks(self, data: str, chunk_size: int) -> str:
        """Split data into chunks"""
        return '\n'.join(data[i:i+chunk_size] for i in range(0, len(data), chunk_size))
    
    def _detect_content_type(self, data: bytes) -> Optional[str]:
        """Detect content type from binary data"""
        if not data:
            return None
        
        # Check file signatures
        for signature, content_type in self.FILE_SIGNATURES.items():
            if data.startswith(signature):
                return content_type
        
        # Check if it's printable text
        try:
            text = data.decode('utf-8')
            if text.isprintable() or all(ord(c) < 128 for c in text):
                return 'text/plain'
        except UnicodeDecodeError:
            pass
        
        # Default to binary
        return 'application/octet-stream'
    
    def analyze_base64(self, data: str) -> Dict[str, Any]:
        """Analyze Base64 data and provide information"""
        cleaned_data = self._clean_base64_input(data)
        
        analysis = {
            'length': len(data),
            'cleaned_length': len(cleaned_data),
            'has_whitespace': len(data) != len(cleaned_data),
            'has_padding': '=' in data,
            'padding_chars': data.count('='),
            'is_url_safe': self._is_url_safe_base64(cleaned_data),
            'is_standard': self._is_standard_base64(cleaned_data),
            'estimated_decoded_size': (len(cleaned_data) * 3) // 4,
            'is_likely_valid': self._validate_base64(cleaned_data, False) or self._validate_base64(cleaned_data, True)
        }
        
        return analysis
    
    def _is_url_safe_base64(self, data: str) -> bool:
        """Check if data uses URL-safe Base64 characters"""
        return '-' in data or '_' in data
    
    def _is_standard_base64(self, data: str) -> bool:
        """Check if data uses standard Base64 characters"""
        return '+' in data or '/' in data


async def execute_tool(params: Base64ToolInput) -> Base64ToolOutput:
    """Main entry point for the Base64 tool"""
    tool = Base64Tool()
    
    try:
        if params.operation == "encode":
            result = tool.encode(
                data=params.data,
                url_safe=params.url_safe,
                remove_padding=params.remove_padding,
                chunk_size=params.chunk_size
            )
            
            return Base64ToolOutput(
                success=True,
                operation="encode",
                input_data=params.data,
                output_data=result['output'],
                input_length=len(params.data),
                output_length=len(result['output']),
                encoding_info=result['encoding_info'],
                is_valid_base64=None,
                detected_content_type=None,
                error=None
            )
            
        elif params.operation == "decode":
            result = tool.decode(
                data=params.data,
                url_safe=params.url_safe,
                validate_input=params.validate_input
            )
            
            return Base64ToolOutput(
                success=True,
                operation="decode",
                input_data=params.data,
                output_data=result['output'],
                input_length=len(params.data),
                output_length=len(result['output']),
                encoding_info=result['encoding_info'],
                is_valid_base64=result['valid'],
                detected_content_type=result['content_type'],
                error=None
            )
        
        else:
            raise ValueError(f"Unknown operation: {params.operation}")
            
    except Exception as e:
        return Base64ToolOutput(
            success=False,
            operation=params.operation,
            input_data=params.data,
            output_data="",
            input_length=len(params.data),
            output_length=0,
            encoding_info={},
            is_valid_base64=None,
            detected_content_type=None,
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "base64_tool",
    "display_name": "Base64 Encoder/Decoder",
    "description": "Comprehensive Base64 encoding and decoding with content type detection",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "data_analysis"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        # Test encoding
        test_input = Base64ToolInput(
            operation="encode",
            data="Hello, World!",
            url_safe=False,
            chunk_size=10
        )
        result = await execute_tool(test_input)
        print(f"Encode Success: {result.success}")
        print(f"Encoded: {result.output_data}")
        
        # Test decoding
        test_input2 = Base64ToolInput(
            operation="decode",
            data=result.output_data.replace('\n', ''),  # Remove chunks for decode test
            url_safe=False
        )
        result2 = await execute_tool(test_input2)
        print(f"Decode Success: {result2.success}")
        print(f"Decoded: {result2.output_data}")
        print(f"Content Type: {result2.detected_content_type}")
    
    asyncio.run(test())
