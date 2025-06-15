from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Union
from datetime import datetime

class CryptoAnalysisRequest(BaseModel):
    """Request model for cryptographic strength analysis"""
    analysis_type: str = Field(..., description="Type of analysis: algorithm, key, implementation, certificate, random")
    
    # For algorithm analysis
    algorithm_name: Optional[str] = Field(default=None, description="Cryptographic algorithm name (AES, RSA, SHA256, etc.)")
    key_size: Optional[int] = Field(default=None, description="Key size in bits")
    mode_of_operation: Optional[str] = Field(default=None, description="Mode of operation (CBC, GCM, ECB, etc.)")
    
    # For key analysis
    public_key: Optional[str] = Field(default=None, description="Public key in PEM format")
    private_key: Optional[str] = Field(default=None, description="Private key in PEM format (optional)")
    key_format: Optional[str] = Field(default="PEM", description="Key format: PEM, DER, JWK")
    
    # For implementation analysis
    code_snippet: Optional[str] = Field(default=None, description="Code snippet to analyze for crypto implementation")
    programming_language: Optional[str] = Field(default="python", description="Programming language of the code")
    
    # For certificate analysis
    certificate: Optional[str] = Field(default=None, description="X.509 certificate in PEM format")
    certificate_chain: Optional[List[str]] = Field(default=None, description="Certificate chain")
    
    # For randomness analysis
    random_data: Optional[str] = Field(default=None, description="Random data to analyze (hex or base64)")
    data_format: Optional[str] = Field(default="hex", description="Random data format: hex, base64, binary")
    
    # General options
    compliance_standards: List[str] = Field(
        default=["NIST", "FIPS", "OWASP"],
        description="Compliance standards to check against"
    )
    include_recommendations: bool = Field(default=True, description="Include security recommendations")

class AlgorithmAnalysis(BaseModel):
    """Algorithm strength analysis"""
    algorithm: str
    key_size: Optional[int]
    strength_rating: str  # Weak, Moderate, Strong, Very Strong
    security_level: int  # Equivalent security level in bits
    recommended_until: Optional[str]  # Year until which it's recommended
    vulnerabilities: List[str]
    compliance_status: Dict[str, bool]

class KeyAnalysis(BaseModel):
    """Key strength analysis"""
    key_type: str
    key_size: int
    strength_score: int  # 0-100
    entropy_estimate: float
    weakness_indicators: List[str]
    factorization_difficulty: Optional[str]
    elliptic_curve_security: Optional[Dict[str, str]]

class ImplementationAnalysis(BaseModel):
    """Implementation security analysis"""
    security_issues: List[Dict[str, str]]
    best_practices_score: int  # 0-100
    vulnerability_count: int
    secure_coding_violations: List[str]
    recommended_fixes: List[str]

class RandomnessAnalysis(BaseModel):
    """Randomness quality analysis"""
    entropy_score: float  # 0-8 bits per byte
    distribution_uniformity: float  # 0-1
    statistical_tests: Dict[str, Dict[str, Union[bool, float]]]
    predictability_risk: str  # Low, Medium, High
    recommended_improvements: List[str]

class CryptoStrengthResponse(BaseModel):
    """Response model for cryptographic strength analysis"""
    analysis_type: str
    overall_security_rating: str  # Critical, Weak, Moderate, Strong, Excellent
    security_score: int  # 0-100
    
    # Specific analyses
    algorithm_analysis: Optional[AlgorithmAnalysis]
    key_analysis: Optional[KeyAnalysis]
    implementation_analysis: Optional[ImplementationAnalysis]
    randomness_analysis: Optional[RandomnessAnalysis]
    
    # Compliance and standards
    compliance_results: Dict[str, Dict[str, bool]]
    standards_met: List[str]
    standards_failed: List[str]
    
    # Security assessment
    critical_issues: List[str]
    warnings: List[str]
    recommendations: List[str]
    
    # Risk assessment
    attack_vectors: List[str]
    time_to_break: Optional[str]
    quantum_resistance: bool
    
    # Metadata
    analysis_confidence: float  # 0-1
    timestamp: str
    processing_time_ms: int
