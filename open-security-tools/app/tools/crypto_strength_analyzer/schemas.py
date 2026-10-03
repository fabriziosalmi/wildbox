from pydantic import BaseModel, Field, model_validator
from typing import Dict, List, Literal, Optional, Union
from datetime import datetime
from ...standardized_schemas import BaseToolInput, BaseToolOutput, CaseInsensitiveChoice

# Compared regardless of case by main.py (#611).
AlgorithmName = CaseInsensitiveChoice("AES", "DES", "3DES", "RSA", "ECC", "MD5", "SHA1", "SHA256", "SHA512")


class CryptoStrengthAnalyzerInput(BaseToolInput):
    """Input schema for Crypto Strength Analyzer tool"""
    # The analyses main.py runs ("certificate" was listed and never ran);
    # each needs its own input field, checked below (#611).
    analysis_type: Literal["algorithm", "key", "implementation", "random", "all"] = Field(
        ..., description="Type of analysis: algorithm, key, implementation, random, or all"
    )
    
    # For algorithm analysis
    # The algorithms main.py rates; another name was rated "Unknown" (#611).
    algorithm_name: Optional[
        AlgorithmName
    ] = Field(default=None, description="Cryptographic algorithm name")
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
    data_format: Literal["hex", "base64", "binary"] = Field(
        default="hex", description="Random data format: hex, base64, or binary (the text as UTF-8 bytes)"
    )
    
    # General options
    # The standards main.py checks; another one always "failed" (#611).
    compliance_standards: List[Literal["NIST", "FIPS", "OWASP"]] = Field(
        default=["NIST", "FIPS", "OWASP"],
        description="Compliance standards to check against (NIST, FIPS, OWASP)"
    )
    include_recommendations: bool = Field(default=True, description="Include security recommendations")

    @model_validator(mode="after")
    def _the_analysed_input_given(self):
        # Without it the analysis was skipped, and an empty analysis met
        # every compliance standard (#611).
        needed = {
            "algorithm": ("algorithm_name",),
            "key": ("public_key",),
            "implementation": ("code_snippet",),
            "random": ("random_data",),
            "all": ("algorithm_name", "public_key", "code_snippet", "random_data"),
        }[self.analysis_type]
        if not any(getattr(self, name) for name in needed):
            raise ValueError(
                f"analysis_type '{self.analysis_type}' needs " + " or ".join(needed)
            )
        return self

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

class CryptoStrengthAnalyzerOutput(BaseToolOutput):
    """Output schema for Crypto Strength Analyzer tool"""
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

# Aliases for backward compatibility
CryptoAnalysisRequest = CryptoStrengthAnalyzerInput
CryptoStrengthResponse = CryptoStrengthAnalyzerOutput
