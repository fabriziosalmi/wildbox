from pydantic import BaseModel, Field, model_validator
from ...standardized_schemas import BaseToolInput, BaseToolOutput
from typing import List, Literal, Optional, Dict, Any, Union

class BlockchainSecurityAnalyzerInput(BaseToolInput):
    """Input schema for Blockchain Security Analyzer tool"""
    contract_address: Optional[str] = Field(None, description="Smart contract address to analyze")
    contract_code: Optional[str] = Field(None, description="Smart contract source code (Solidity)")
    # The networks main.py has explorers for; another value fetched nothing
    # (#611).
    blockchain: Literal["ethereum", "bsc", "polygon"] = Field(default="ethereum", description="Blockchain network (ethereum, bsc, polygon)")
    analysis_type: str = Field(default="comprehensive", description="Analysis type (comprehensive, quick, vulnerabilities)")
    check_reentrancy: bool = Field(default=True, description="Check for reentrancy vulnerabilities")
    check_overflow: bool = Field(default=True, description="Check for integer overflow/underflow")
    check_access_control: bool = Field(default=True, description="Check access control mechanisms")
    check_gas_optimization: bool = Field(default=True, description="Check gas optimization opportunities")
    api_key: Optional[str] = Field(None, description="Blockchain explorer API key, required to fetch a contract by address")

    @model_validator(mode="after")
    def _a_contract_given(self):
        # Without source code, or an address and a key to fetch it with,
        # there is nothing to analyse (#611).
        if not self.contract_code and not (self.contract_address and self.api_key):
            raise ValueError("Provide contract_code, or contract_address with api_key")
        return self

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

