"""Pydantic schemas for the hash cracker tool."""

from pydantic import BaseModel, Field, model_validator
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Literal, Optional, Dict
from datetime import datetime

class HashCrackerInput(BaseToolInput):
    hash_value: str = Field(
        ...,
        description="Hash value to crack",
        json_schema_extra={"example": "5d41402abc4b2a76b9719d911017c592"},
    )
    # The algorithms and wordlists main.py implements. Another hash type
    # hashed every candidate to "" and so never cracked anything, and
    # "custom" without a list fell back to the common one (#611).
    hash_type: Literal["auto", "md5", "sha1", "sha256", "sha512"] = Field(
        default="auto", description="Hash type (auto, md5, sha1, sha256, sha512)", json_schema_extra={"example": "md5"}
    )
    wordlist_type: Literal["common", "rockyou", "custom"] = Field(
        default="common", description="Wordlist type (common, rockyou, custom)", json_schema_extra={"example": "common"}
    )
    custom_wordlist: Optional[List[str]] = Field(None, description="Custom wordlist, required if wordlist_type is 'custom'")
    max_attempts: int = Field(default=10000, description="Maximum crack attempts", ge=100, le=1000000)

    @model_validator(mode="after")
    def _custom_wordlist_given(self):
        if self.wordlist_type == "custom" and not self.custom_wordlist:
            raise ValueError("custom_wordlist is required when wordlist_type is 'custom'")
        return self

class HashResult(BaseModel):
    hash_value: str = Field(..., description="Original hash value")
    hash_type: str = Field(..., description="Detected/specified hash type")
    cracked: bool = Field(..., description="Whether hash was successfully cracked")
    plaintext: Optional[str] = Field(None, description="Cracked plaintext value")
    attempts: int = Field(..., description="Number of attempts made")
    time_taken: float = Field(..., description="Time taken in seconds")

class HashCrackerOutput(BaseToolOutput):
    timestamp: datetime = Field(..., description="Analysis timestamp")
    total_hashes: int = Field(..., description="Total hashes processed")
    successful_cracks: int = Field(..., description="Number of successfully cracked hashes")
    results: List[HashResult] = Field(..., description="Detailed results for each hash")
    statistics: Dict[str, int] = Field(..., description="Statistics by hash type")
