"""Pydantic schemas for the hash cracker tool."""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime

class HashCrackerInput(BaseModel):
    hash_value: str = Field(..., description="Hash value to crack", example="5d41402abc4b2a76b9719d911017c592")
    hash_type: str = Field(default="auto", description="Hash type (md5, sha1, sha256, auto)", example="md5")
    wordlist_type: str = Field(default="common", description="Wordlist type (common, rockyou, custom)", example="common")
    custom_wordlist: Optional[List[str]] = Field(None, description="Custom wordlist if wordlist_type is 'custom'")
    max_attempts: int = Field(default=10000, description="Maximum crack attempts", ge=100, le=1000000)

class HashResult(BaseModel):
    hash_value: str = Field(..., description="Original hash value")
    hash_type: str = Field(..., description="Detected/specified hash type")
    cracked: bool = Field(..., description="Whether hash was successfully cracked")
    plaintext: Optional[str] = Field(None, description="Cracked plaintext value")
    attempts: int = Field(..., description="Number of attempts made")
    time_taken: float = Field(..., description="Time taken in seconds")

class HashCrackerOutput(BaseModel):
    timestamp: datetime = Field(..., description="Analysis timestamp")
    total_hashes: int = Field(..., description="Total hashes processed")
    successful_cracks: int = Field(..., description="Number of successfully cracked hashes")
    results: List[HashResult] = Field(..., description="Detailed results for each hash")
    statistics: Dict[str, int] = Field(..., description="Statistics by hash type")
