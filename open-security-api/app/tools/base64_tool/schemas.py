"""
Schemas for Base64 Decoder/Encoder Tool
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal


class Base64ToolInput(BaseModel):
    """Input schema for Base64 operations"""
    operation: Literal["encode", "decode"] = Field(
        description="Operation to perform: encode or decode"
    )
    data: str = Field(
        description="Data to encode/decode"
    )
    url_safe: bool = Field(
        default=False,
        description="Use URL-safe Base64 encoding/decoding"
    )
    remove_padding: bool = Field(
        default=False,
        description="Remove padding characters (=) from encoded output"
    )
    chunk_size: Optional[int] = Field(
        default=None,
        ge=1,
        le=1000,
        description="Split encoded output into chunks of specified size"
    )
    validate_input: bool = Field(
        default=True,
        description="Validate Base64 input when decoding"
    )


class Base64ToolOutput(BaseModel):
    """Output schema for Base64 operations"""
    success: bool = Field(description="Whether the operation was successful")
    operation: str = Field(description="Operation performed")
    input_data: str = Field(description="Original input data")
    output_data: str = Field(description="Processed output data")
    input_length: int = Field(description="Length of input data")
    output_length: int = Field(description="Length of output data")
    encoding_info: dict = Field(description="Information about the encoding/decoding")
    is_valid_base64: Optional[bool] = Field(
        default=None,
        description="Whether input was valid Base64 (for decode operations)"
    )
    detected_content_type: Optional[str] = Field(
        default=None,
        description="Detected content type of decoded data"
    )
    error: Optional[str] = Field(default=None, description="Error message if operation failed")
