from pydantic import BaseModel, Field
from standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Optional, Dict, Any, Union

class BlockchainSecurityAnalyzerInput(BaseToolInput):
    """Input schema for Blockchain Security Analyzer tool"""
    contract_address: Optional[str] = Field(None, description="Smart contract address to analyze")
    contract_code: Optional[str] = Field(None, description="Smart contract source code (Solidity)")
    blockchain: str = Field(default="ethereum", description="Blockchain network (ethereum, bsc, polygon)")
    analysis_type: str = Field(default="comprehensive", description="Analysis type (comprehensive, quick, vulnerabilities)")
    check_reentrancy: bool = Field(default=True, description="Check for reentrancy vulnerabilities")
    check_overflow: bool = Field(default=True, description="Check for integer overflow/underflow")
    check_access_control: bool = Field(default=True, description="Check access control mechanisms")
    check_gas_optimization: bool = Field(default=True, description="Check gas optimization opportunities")
    api_key: Optional[str] = Field(None, description="Blockchain API key for enhanced analysis")

class SecurityVulnerability(BaseModel):
    severity: str  # Critical, High, Medium, Low, Info
    category: str
    title: str
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str
    cwe_id: Optional[str] = None

class GasOptimization(BaseModel):
    title: str
    description: str
    potential_savings: str
    line_number: Optional[int] = None
    recommendation: str

class BlockchainSecurityAnalyzerOutput(BaseToolOutput):
    """Output schema for Blockchain Security Analyzer tool"""
    contract_address: Optional[str]
    blockchain: str
    analysis_timestamp: str
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    vulnerabilities: List[SecurityVulnerability]
    gas_optimizations: List[GasOptimization]
    contract_balance: Optional[str]
    contract_verified: Optional[bool]
    proxy_contract: Optional[bool]
    security_score: float  # 0-100
    risk_level: str  # Low, Medium, High, Critical
    recommendations: List[str]
    execution_time: float

# Tool metadata

