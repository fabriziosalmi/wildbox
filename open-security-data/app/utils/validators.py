"""
Validators for security indicators and data
"""

import re
import ipaddress
import hashlib
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

def validate_ip_address(value: str) -> bool:
    """Validate IP address (IPv4 or IPv6)"""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False

def validate_domain(value: str) -> bool:
    """Validate domain name"""
    if not value or len(value) > 253:
        return False
    
    # Basic domain regex
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_pattern.match(value.strip().lower()))

def validate_url(value: str) -> bool:
    """Validate URL"""
    try:
        result = urlparse(value.strip())
        return bool(result.scheme and result.netloc)
    except Exception:
        return False

def validate_file_hash(value: str, hash_type: Optional[str] = None) -> bool:
    """Validate file hash"""
    value = value.strip().lower()
    
    # Hash length validation
    hash_lengths = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
        'sha512': 128
    }
    
    # Check if it's a valid hex string
    if not re.match(r'^[a-f0-9]+$', value):
        return False
    
    # If hash type is specified, check length
    if hash_type:
        expected_length = hash_lengths.get(hash_type.lower())
        if expected_length and len(value) != expected_length:
            return False
    else:
        # Check if length matches any known hash type
        if len(value) not in hash_lengths.values():
            return False
    
    return True

def validate_email(value: str) -> bool:
    """Validate email address"""
    email_pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    return bool(email_pattern.match(value.strip().lower()))

def validate_asn(value: str) -> bool:
    """Validate ASN (Autonomous System Number)"""
    try:
        # Remove AS prefix if present
        if value.upper().startswith('AS'):
            value = value[2:]
        
        asn = int(value)
        return 1 <= asn <= 4294967295  # Valid ASN range
    except ValueError:
        return False

def validate_cve(value: str) -> bool:
    """Validate CVE identifier"""
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
    return bool(cve_pattern.match(value.strip()))

def validate_indicator(indicator_data: Dict[str, Any]) -> bool:
    """
    Validate a security indicator
    
    Args:
        indicator_data: Dictionary containing indicator information
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(indicator_data, dict):
        return False
    
    # Required fields
    required_fields = ['indicator_type', 'value']
    for field in required_fields:
        if field not in indicator_data:
            return False
    
    indicator_type = indicator_data['indicator_type'].lower()
    value = indicator_data['value']
    
    if not isinstance(value, str) or not value.strip():
        return False
    
    # Type-specific validation
    validators = {
        'ip_address': validate_ip_address,
        'domain': validate_domain,
        'url': validate_url,
        'file_hash': lambda v: validate_file_hash(v, indicator_data.get('hash_type')),
        'email': validate_email,
        'asn': validate_asn,
        'vulnerability': validate_cve,
    }
    
    validator = validators.get(indicator_type)
    if not validator:
        return False
    
    if not validator(value):
        return False
    
    # Validate optional fields
    if 'confidence' in indicator_data:
        valid_confidence = ['low', 'medium', 'high', 'verified']
        if indicator_data['confidence'].lower() not in valid_confidence:
            return False
    
    if 'severity' in indicator_data:
        try:
            severity = int(indicator_data['severity'])
            if not (1 <= severity <= 10):
                return False
        except (ValueError, TypeError):
            return False
    
    if 'threat_types' in indicator_data:
        if not isinstance(indicator_data['threat_types'], list):
            return False
        
        valid_threat_types = [
            'malware', 'phishing', 'spam', 'botnet', 'exploit',
            'vulnerability', 'certificate', 'dns', 'network_scan', 'suspicious'
        ]
        
        for threat_type in indicator_data['threat_types']:
            if threat_type.lower() not in valid_threat_types:
                return False
    
    if 'tags' in indicator_data:
        if not isinstance(indicator_data['tags'], list):
            return False
        
        # Validate tag format (alphanumeric, underscore, hyphen)
        tag_pattern = re.compile(r'^[a-zA-Z0-9_-]+$')
        for tag in indicator_data['tags']:
            if not isinstance(tag, str) or not tag_pattern.match(tag):
                return False
    
    return True

def sanitize_indicator_value(value: str, indicator_type: str) -> str:
    """
    Sanitize indicator value for storage
    
    Args:
        value: Raw indicator value
        indicator_type: Type of indicator
        
    Returns:
        Sanitized value
    """
    if not isinstance(value, str):
        return str(value)
    
    value = value.strip()
    
    # Type-specific sanitization
    if indicator_type.lower() in ['domain', 'email']:
        value = value.lower()
    elif indicator_type.lower() == 'file_hash':
        value = value.lower()
    elif indicator_type.lower() == 'url':
        # Remove fragments and trailing slashes for normalization
        parsed = urlparse(value)
        if parsed.fragment:
            value = value.replace(f'#{parsed.fragment}', '')
        if value.endswith('/') and len(value) > 1:
            value = value.rstrip('/')
    
    return value

def extract_indicators_from_text(text: str) -> List[Dict[str, Any]]:
    """
    Extract indicators from free text
    
    Args:
        text: Text to analyze
        
    Returns:
        List of extracted indicators
    """
    indicators = []
    
    # IP address pattern
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for match in ip_pattern.finditer(text):
        if validate_ip_address(match.group()):
            indicators.append({
                'indicator_type': 'ip_address',
                'value': match.group(),
                'position': match.span()
            })
    
    # Domain pattern
    domain_pattern = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b')
    for match in domain_pattern.finditer(text):
        if validate_domain(match.group()):
            indicators.append({
                'indicator_type': 'domain',
                'value': match.group(),
                'position': match.span()
            })
    
    # Hash patterns
    hash_patterns = {
        'md5': re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE),
        'sha1': re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE),
        'sha256': re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE),
    }
    
    for hash_type, pattern in hash_patterns.items():
        for match in pattern.finditer(text):
            indicators.append({
                'indicator_type': 'file_hash',
                'value': match.group().lower(),
                'hash_type': hash_type,
                'position': match.span()
            })
    
    # URL pattern
    url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
    for match in url_pattern.finditer(text):
        if validate_url(match.group()):
            indicators.append({
                'indicator_type': 'url',
                'value': match.group(),
                'position': match.span()
            })
    
    # Email pattern
    email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    for match in email_pattern.finditer(text):
        if validate_email(match.group()):
            indicators.append({
                'indicator_type': 'email',
                'value': match.group().lower(),
                'position': match.span()
            })
    
    # CVE pattern
    cve_pattern = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
    for match in cve_pattern.finditer(text):
        indicators.append({
            'indicator_type': 'vulnerability',
            'value': match.group().upper(),
            'position': match.span()
        })
    
    return indicators
