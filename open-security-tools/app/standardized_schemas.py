"""
Standardized Schema Validator for Security Tools
Blueprint Phase 1 - Output Standardization Implementation
"""

from typing import Dict, Any, Optional, List, Type, Union
from pydantic import BaseModel, Field, create_model, ValidationError
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ToolCategory(str, Enum):
    """Standard tool categories."""
    NETWORK_SCANNING = "network_scanning"
    WEB_SECURITY = "web_security"
    CRYPTO_ANALYSIS = "crypto_analysis"
    COMPLIANCE = "compliance"
    THREAT_INTELLIGENCE = "threat_intelligence"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    FORENSICS = "forensics"
    AUTOMATION = "automation"
    ANALYSIS = "analysis"
    UTILITY = "utility"


class ToolSeverity(str, Enum):
    """Standard severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BaseToolInput(BaseModel):
    """Base input schema that all tools should inherit from."""
    target: Optional[str] = Field(None, description="Primary target (URL, IP, domain, etc.)")
    timeout: int = Field(default=30, ge=1, le=300, description="Execution timeout in seconds")
    user_agent: Optional[str] = Field(None, description="Custom User-Agent string")
    proxy: Optional[str] = Field(None, description="Proxy URL (http://host:port)")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    max_retries: int = Field(default=3, ge=0, le=10, description="Maximum retry attempts")


class BaseToolOutput(BaseModel):
    """Base output schema that all tools should inherit from."""
    success: bool = Field(..., description="Whether the tool execution was successful")
    tool_name: str = Field(default="unknown", description="Name of the executed tool")
    tool_version: str = Field(default="1.0.0", description="Version of the tool")
    execution_time: float = Field(default=0.0, description="Execution time in seconds")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Execution timestamp")
    target: Optional[str] = Field(None, description="Target that was analyzed")
    summary: Optional[str] = Field(None, description="Brief summary of results")
    error_message: Optional[str] = Field(None, description="Error message if execution failed")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class SecurityFinding(BaseModel):
    """Standard security finding structure."""
    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed description")
    severity: ToolSeverity = Field(..., description="Severity level")
    category: str = Field(..., description="Finding category")
    location: Optional[str] = Field(None, description="Location where finding was detected")
    evidence: Optional[str] = Field(None, description="Evidence or proof of the finding")
    remediation: Optional[str] = Field(None, description="Suggested remediation")
    references: List[str] = Field(default_factory=list, description="External references")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score if applicable")
    cve_ids: List[str] = Field(default_factory=list, description="Related CVE identifiers")


class NetworkPort(BaseModel):
    """Standard network port information."""
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(..., description="Protocol (tcp/udp)")
    state: str = Field(..., description="Port state (open/closed/filtered)")
    service: Optional[str] = Field(None, description="Detected service")
    version: Optional[str] = Field(None, description="Service version")
    banner: Optional[str] = Field(None, description="Service banner")


class HttpHeader(BaseModel):
    """Standard HTTP header information."""
    name: str = Field(..., description="Header name")
    value: str = Field(..., description="Header value")
    security_impact: Optional[ToolSeverity] = Field(None, description="Security impact level")
    recommendation: Optional[str] = Field(None, description="Security recommendation")


class CertificateInfo(BaseModel):
    """Standard SSL certificate information."""
    subject: Dict[str, str] = Field(..., description="Certificate subject")
    issuer: Dict[str, str] = Field(..., description="Certificate issuer")
    serial_number: str = Field(..., description="Certificate serial number")
    not_before: datetime = Field(..., description="Certificate valid from")
    not_after: datetime = Field(..., description="Certificate valid until")
    days_until_expiry: int = Field(..., description="Days until expiration")
    signature_algorithm: str = Field(..., description="Signature algorithm")
    public_key_algorithm: str = Field(..., description="Public key algorithm")
    san_domains: List[str] = Field(default_factory=list, description="Subject Alternative Names")


class ToolMetadata(BaseModel):
    """Standard tool metadata."""
    name: str = Field(..., description="Tool name")
    version: str = Field(..., description="Tool version")
    category: ToolCategory = Field(..., description="Tool category")
    description: str = Field(..., description="Tool description")
    author: str = Field(..., description="Tool author")
    tags: List[str] = Field(default_factory=list, description="Tool tags")
    documentation_url: Optional[str] = Field(None, description="Documentation URL")
    source_url: Optional[str] = Field(None, description="Source code URL")


class StandardizedToolValidator:
    """
    Validator to ensure all tools use standardized schemas.
    Blueprint Phase 1 requirement for consistent JSON output.
    """
    
    def __init__(self):
        self.registered_tools: Dict[str, ToolMetadata] = {}
        self.input_schemas: Dict[str, Type[BaseModel]] = {}
        self.output_schemas: Dict[str, Type[BaseModel]] = {}
    
    def register_tool(self,
                      tool_name: str,
                      metadata: ToolMetadata,
                      input_schema: Type[BaseModel],
                      output_schema: Type[BaseModel]) -> None:
        """Register a tool with its schemas."""
        # Validate that schemas inherit from base schemas
        if not issubclass(input_schema, BaseToolInput):
            raise ValueError(f"Input schema for {tool_name} must inherit from BaseToolInput")
        
        if not issubclass(output_schema, BaseToolOutput):
            raise ValueError(f"Output schema for {tool_name} must inherit from BaseToolOutput")
        
        self.registered_tools[tool_name] = metadata
        self.input_schemas[tool_name] = input_schema
        self.output_schemas[tool_name] = output_schema
        
        logger.info(f"Registered tool {tool_name} with standardized schemas")
    
    def validate_input(self, tool_name: str, input_data: Dict[str, Any]) -> BaseModel:
        """Validate tool input against registered schema."""
        if tool_name not in self.input_schemas:
            raise ValueError(f"Tool {tool_name} not registered")
        
        schema = self.input_schemas[tool_name]
        try:
            return schema(**input_data)
        except ValidationError as e:
            logger.error(f"Input validation failed for {tool_name}: {e}")
            raise ValueError(f"Invalid input for {tool_name}: {e}")
    
    def validate_output(self, tool_name: str, output_data: Dict[str, Any]) -> BaseModel:
        """Validate tool output against registered schema."""
        if tool_name not in self.output_schemas:
            raise ValueError(f"Tool {tool_name} not registered")
        
        schema = self.output_schemas[tool_name]
        try:
            return schema(**output_data)
        except ValidationError as e:
            logger.error(f"Output validation failed for {tool_name}: {e}")
            raise ValueError(f"Invalid output for {tool_name}: {e}")
    
    def get_tool_metadata(self, tool_name: str) -> Optional[ToolMetadata]:
        """Get metadata for a registered tool."""
        return self.registered_tools.get(tool_name)
    
    def list_registered_tools(self) -> List[str]:
        """List all registered tool names."""
        return list(self.registered_tools.keys())
    
    def get_tool_schemas(self, tool_name: str) -> Dict[str, Type[BaseModel]]:
        """Get input and output schemas for a tool."""
        return {
            'input': self.input_schemas.get(tool_name),
            'output': self.output_schemas.get(tool_name)
        }
    
    def generate_openapi_schema(self, tool_name: str) -> Dict[str, Any]:
        """Generate OpenAPI schema for a tool."""
        if tool_name not in self.input_schemas:
            raise ValueError(f"Tool {tool_name} not registered")
        
        input_schema = self.input_schemas[tool_name]
        output_schema = self.output_schemas[tool_name]
        metadata = self.registered_tools[tool_name]
        
        return {
            'summary': metadata.description,
            'description': f"{metadata.description}\n\nCategory: {metadata.category.value}",
            'tags': [metadata.category.value],
            'requestBody': {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': input_schema.schema()
                    }
                }
            },
            'responses': {
                '200': {
                    'description': 'Successful tool execution',
                    'content': {
                        'application/json': {
                            'schema': output_schema.schema()
                        }
                    }
                },
                '400': {
                    'description': 'Invalid input'
                },
                '500': {
                    'description': 'Tool execution failed'
                }
            }
        }
    
    def audit_tool_compliance(self, tool_name: str) -> Dict[str, Any]:
        """Audit a tool for schema compliance."""
        compliance_report = {
            'tool_name': tool_name,
            'registered': tool_name in self.registered_tools,
            'has_input_schema': tool_name in self.input_schemas,
            'has_output_schema': tool_name in self.output_schemas,
            'compliance_score': 0,
            'issues': []
        }
        
        if not compliance_report['registered']:
            compliance_report['issues'].append("Tool not registered with validator")
            return compliance_report
        
        # Check schema inheritance
        input_schema = self.input_schemas[tool_name]
        output_schema = self.output_schemas[tool_name]
        
        if not issubclass(input_schema, BaseToolInput):
            compliance_report['issues'].append("Input schema doesn't inherit from BaseToolInput")
        
        if not issubclass(output_schema, BaseToolOutput):
            compliance_report['issues'].append("Output schema doesn't inherit from BaseToolOutput")
        
        # Calculate compliance score
        max_score = 4  # registered, input_schema, output_schema, proper_inheritance
        score = sum([
            compliance_report['registered'],
            compliance_report['has_input_schema'],
            compliance_report['has_output_schema'],
            len(compliance_report['issues']) == 0
        ])
        
        compliance_report['compliance_score'] = (score / max_score) * 100
        
        return compliance_report


# Global validator instance
tool_validator = StandardizedToolValidator()


# Example usage - Tool-specific schemas should inherit from base schemas
class PortScannerInput(BaseToolInput):
    """Port scanner specific input schema."""
    ports: Optional[List[int]] = Field(None, description="Specific ports to scan")
    scan_type: str = Field(default="tcp", description="Scan type (tcp/udp/syn)")


class PortScannerOutput(BaseToolOutput):
    """Port scanner specific output schema."""
    open_ports: List[NetworkPort] = Field(default_factory=list, description="Open ports found")
    closed_ports: int = Field(default=0, description="Number of closed ports")
    filtered_ports: int = Field(default=0, description="Number of filtered ports")
    scan_statistics: Dict[str, Any] = Field(default_factory=dict, description="Scan statistics")


# Auto-register some common tool schemas
def register_common_tools():
    """Register common tool schemas on import."""
    try:
        # Port scanner
        port_scanner_metadata = ToolMetadata(
            name="port_scanner",
            version="1.0.0",
            category=ToolCategory.NETWORK_SCANNING,
            description="Network port scanner for discovering open services",
            author="Wildbox Security",
            tags=["network", "scanning", "ports"]
        )
        
        tool_validator.register_tool(
            "port_scanner",
            port_scanner_metadata,
            PortScannerInput,
            PortScannerOutput
        )
        
        logger.info("Common tool schemas registered successfully")
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        logger.error(f"Failed to register common tools: {e}")


# Register tools on module import
register_common_tools()
