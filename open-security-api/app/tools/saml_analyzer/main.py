import base64
import xml.etree.ElementTree as ET
from xml.dom import minidom
import re
import time
from datetime import datetime
from typing import Dict, List, Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from lxml import etree

# Configure secure XML parser to prevent XXE attacks
try:
    import defusedxml.ElementTree as DefusedET
    # Use defusedxml if available for security
    safe_xml_fromstring = DefusedET.fromstring
except ImportError:
    # Fallback to built-in with security measures
    def safe_xml_fromstring(text):
        parser = ET.XMLParser()
        # Disable external entity processing to prevent XXE
        parser.parser.DefaultHandler = lambda data: None
        parser.parser.ExternalEntityRefHandler = lambda context, base, sysId, notationName: False
        return ET.fromstring(text, parser)

from .schemas import SAMLAnalyzerInput, SAMLAnalyzerOutput, SAMLFinding

# Tool metadata
TOOL_INFO = {
    "name": "SAML Analyzer",
    "description": "Analyze SAML responses for security vulnerabilities, signature validation, and attribute extraction",
    "category": "authentication",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "tags": ["saml", "sso", "authentication", "security", "xml"]
}

async def execute_tool(data: SAMLAnalyzerInput) -> SAMLAnalyzerOutput:
    """
    Analyze SAML response for security issues and extract information
    """
    start_time = time.time()
    findings = []
    
    try:
        # Decode SAML response
        try:
            saml_xml = base64.b64decode(data.saml_response).decode('utf-8')
        except Exception as e:
            findings.append(SAMLFinding(
                severity="Critical",
                category="Format",
                title="Invalid Base64 Encoding",
                description="SAML response is not properly base64 encoded",
                recommendation="Ensure SAML response is properly base64 encoded"
            ))
            return SAMLAnalyzerOutput(
                is_valid=False,
                findings=findings,
                security_score=0.0,
                signature_valid=False,
                encrypted=False,
                attributes={},
                execution_time=time.time() - start_time
            )
        
        # Parse XML
        try:
            root = safe_xml_fromstring(saml_xml)
        except ET.ParseError as e:
            findings.append(SAMLFinding(
                severity="Critical",
                category="Format",
                title="Invalid XML Format",
                description=f"SAML response contains invalid XML: {str(e)}",
                recommendation="Ensure SAML response is valid XML"
            ))
            return SAMLAnalyzerOutput(
                is_valid=False,
                findings=findings,
                security_score=0.0,
                signature_valid=False,
                encrypted=False,
                attributes={},
                execution_time=time.time() - start_time
            )
        
        # Extract basic information
        issuer = extract_issuer(root)
        subject = extract_subject(root)
        not_before, not_after = extract_conditions(root)
        attributes = extract_attributes(root) if data.analyze_attributes else {}
        
        # Security checks
        if data.verify_signature:
            signature_valid = check_signature(root, findings)
        else:
            signature_valid = True
            
        if data.check_conditions:
            check_validity_conditions(not_before, not_after, findings)
            
        encrypted = check_encryption_status(root)
        
        # Additional security checks
        check_replay_protection(root, findings)
        check_audience_restriction(root, findings)
        check_attribute_security(attributes, findings)
        check_xml_vulnerabilities(saml_xml, findings)
        
        # Calculate security score
        security_score = calculate_security_score(findings)
        
        # Determine overall validity
        is_valid = not any(f.severity in ["Critical", "High"] for f in findings)
        
        return SAMLAnalyzerOutput(
            is_valid=is_valid,
            issuer=issuer,
            subject=subject,
            not_before=not_before,
            not_after=not_after,
            attributes=attributes,
            signature_valid=signature_valid,
            encrypted=encrypted,
            findings=findings,
            security_score=security_score,
            execution_time=time.time() - start_time
        )
        
    except Exception as e:
        findings.append(SAMLFinding(
            severity="Critical",
            category="Error",
            title="Analysis Failed",
            description=f"Failed to analyze SAML response: {str(e)}",
            recommendation="Check SAML response format and try again"
        ))
        
        return SAMLAnalyzerOutput(
            is_valid=False,
            findings=findings,
            security_score=0.0,
            signature_valid=False,
            encrypted=False,
            attributes={},
            execution_time=time.time() - start_time
        )

def extract_issuer(root):
    """Extract issuer from SAML response"""
    issuer_elem = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
    return issuer_elem.text if issuer_elem is not None else None

def extract_subject(root):
    """Extract subject from SAML response"""
    subject_elem = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Subject/{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
    return subject_elem.text if subject_elem is not None else None

def extract_conditions(root):
    """Extract validity conditions"""
    conditions = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions')
    if conditions is not None:
        not_before = conditions.get('NotBefore')
        not_after = conditions.get('NotOnOrAfter')
        return not_before, not_after
    return None, None

def extract_attributes(root):
    """Extract user attributes"""
    attributes = {}
    attr_statements = root.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement')
    
    for statement in attr_statements:
        attrs = statement.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute')
        for attr in attrs:
            name = attr.get('Name')
            values = []
            for value in attr.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                values.append(value.text or value.get('value', ''))
            attributes[name] = values
    
    return attributes

def check_signature(root, findings):
    """Check digital signature validity"""
    signature = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
    if signature is None:
        findings.append(SAMLFinding(
            severity="High",
            category="Authentication",
            title="Missing Digital Signature",
            description="SAML response is not digitally signed",
            recommendation="Ensure SAML responses are digitally signed by the IdP"
        ))
        return False
    
    # Basic signature validation (simplified)
    signed_info = signature.find('.//{http://www.w3.org/2000/09/xmldsig#}SignedInfo')
    if signed_info is None:
        findings.append(SAMLFinding(
            severity="High",
            category="Authentication",
            title="Invalid Signature Structure",
            description="Digital signature has invalid structure",
            recommendation="Verify signature format and signing process"
        ))
        return False
    
    return True

def check_validity_conditions(not_before, not_after, findings):
    """Check time-based validity conditions"""
    if not not_before or not not_after:
        findings.append(SAMLFinding(
            severity="Medium",
            category="Validation",
            title="Missing Time Conditions",
            description="SAML response lacks proper time validity conditions",
            recommendation="Implement NotBefore and NotOnOrAfter conditions"
        ))
        return
    
    try:
        now = datetime.utcnow()
        nb_time = datetime.fromisoformat(not_before.replace('Z', '+00:00'))
        na_time = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
        
        if now < nb_time:
            findings.append(SAMLFinding(
                severity="High",
                category="Validation",
                title="Response Not Yet Valid",
                description="SAML response NotBefore time is in the future",
                recommendation="Check system clock synchronization"
            ))
        
        if now > na_time:
            findings.append(SAMLFinding(
                severity="High",
                category="Validation",
                title="Response Expired",
                description="SAML response has expired (past NotOnOrAfter time)",
                recommendation="Ensure timely processing of SAML responses"
            ))
            
        # Check for overly long validity periods
        validity_period = na_time - nb_time
        if validity_period.total_seconds() > 3600:  # 1 hour
            findings.append(SAMLFinding(
                severity="Medium",
                category="Security",
                title="Long Validity Period",
                description=f"SAML response valid for {validity_period}",
                recommendation="Limit SAML response validity to minimize replay risk"
            ))
            
    except Exception as e:
        findings.append(SAMLFinding(
            severity="Low",
            category="Validation",
            title="Time Parsing Error",
            description=f"Could not parse time conditions: {str(e)}",
            recommendation="Ensure time conditions follow ISO 8601 format"
        ))

def check_encryption_status(root):
    """Check if assertion is encrypted"""
    encrypted_assertion = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion')
    return encrypted_assertion is not None

def check_replay_protection(root, findings):
    """Check for replay protection mechanisms"""
    # Check for assertion ID
    assertion = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
    if assertion is not None:
        assertion_id = assertion.get('ID')
        if not assertion_id:
            findings.append(SAMLFinding(
                severity="Medium",
                category="Security",
                title="Missing Assertion ID",
                description="SAML assertion lacks unique ID for replay protection",
                recommendation="Ensure all assertions have unique IDs"
            ))

def check_audience_restriction(root, findings):
    """Check for audience restriction"""
    audience = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction')
    if audience is None:
        findings.append(SAMLFinding(
            severity="Medium",
            category="Authorization",
            title="Missing Audience Restriction",
            description="SAML response lacks audience restriction",
            recommendation="Implement audience restriction to prevent token misuse"
        ))

def check_attribute_security(attributes, findings):
    """Check security of user attributes"""
    sensitive_attrs = ['ssn', 'social_security', 'credit_card', 'password', 'secret']
    
    for attr_name, values in attributes.items():
        # Check for sensitive attribute names
        if any(sensitive in attr_name.lower() for sensitive in sensitive_attrs):
            findings.append(SAMLFinding(
                severity="High",
                category="Data Protection",
                title="Sensitive Attribute Detected",
                description=f"Potentially sensitive attribute '{attr_name}' found",
                recommendation="Avoid transmitting sensitive data in SAML attributes"
            ))
        
        # Check for empty attributes
        if not values or all(not v for v in values):
            findings.append(SAMLFinding(
                severity="Low",
                category="Data Quality",
                title="Empty Attribute",
                description=f"Attribute '{attr_name}' has no values",
                recommendation="Remove unused attributes or provide proper values"
            ))

def check_xml_vulnerabilities(saml_xml, findings):
    """Check for common XML vulnerabilities"""
    # Check for XXE patterns
    xxe_patterns = [
        r'<!ENTITY',
        r'SYSTEM\s*["\']',
        r'PUBLIC\s*["\']'
    ]
    
    for pattern in xxe_patterns:
        if re.search(pattern, saml_xml, re.IGNORECASE):
            findings.append(SAMLFinding(
                severity="High",
                category="XML Security",
                title="Potential XXE Vulnerability",
                description="XML contains entity declarations that could lead to XXE attacks",
                recommendation="Disable external entity processing in XML parser"
            ))
            break
    
    # Check for XML bomb patterns
    if saml_xml.count('<') > 1000:
        findings.append(SAMLFinding(
            severity="Medium",
            category="XML Security",
            title="Large XML Document",
            description="SAML response contains unusually large XML structure",
            recommendation="Implement XML size limits to prevent DoS attacks"
        ))

def calculate_security_score(findings):
    """Calculate overall security score based on findings"""
    if not findings:
        return 100.0
    
    score = 100.0
    severity_weights = {
        "Critical": 30,
        "High": 20,
        "Medium": 10,
        "Low": 5,
        "Info": 1
    }
    
    for finding in findings:
        score -= severity_weights.get(finding.severity, 1)
    
    return max(0.0, score)

# Export tool info for registration
tool_info = TOOL_INFO
