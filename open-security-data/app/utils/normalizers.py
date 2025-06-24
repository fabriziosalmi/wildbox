"""
Data normalizers for security indicators
"""

import re
import hashlib
import ipaddress
from typing import Dict, Any, Optional
from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone

def normalize_ip_address(value: str) -> str:
    """Normalize IP address"""
    try:
        ip = ipaddress.ip_address(value.strip())
        return str(ip)
    except ValueError:
        return value.strip()

def normalize_domain(value: str) -> str:
    """Normalize domain name"""
    domain = value.strip().lower()
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).netloc
    
    # Remove trailing dot
    domain = domain.rstrip('.')
    
    # Remove port if present
    if ':' in domain and not domain.startswith('['):  # Not IPv6
        domain = domain.split(':')[0]
    
    return domain

def normalize_url(value: str) -> str:
    """Normalize URL"""
    url = value.strip()
    
    try:
        parsed = urlparse(url)
        
        # Ensure scheme is present
        if not parsed.scheme:
            url = 'http://' + url
            parsed = urlparse(url)
        
        # Normalize scheme to lowercase
        scheme = parsed.scheme.lower()
        
        # Normalize netloc to lowercase
        netloc = parsed.netloc.lower()
        
        # Normalize path
        path = parsed.path
        if not path:
            path = '/'
        
        # Remove default ports
        if ':' in netloc:
            host, port = netloc.rsplit(':', 1)
            try:
                port_num = int(port)
                if (scheme == 'http' and port_num == 80) or (scheme == 'https' and port_num == 443):
                    netloc = host
            except ValueError:
                pass
        
        # Reconstruct URL
        normalized = urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            ''  # Remove fragment for normalization
        ))
        
        return normalized
        
    except Exception:
        return url

def normalize_file_hash(value: str, hash_type: Optional[str] = None) -> str:
    """Normalize file hash"""
    hash_value = value.strip().lower()
    
    # Remove common prefixes
    prefixes = ['md5:', 'sha1:', 'sha256:', 'sha512:']
    for prefix in prefixes:
        if hash_value.startswith(prefix):
            hash_value = hash_value[len(prefix):]
            if not hash_type:
                hash_type = prefix[:-1]  # Remove the colon
            break
    
    # Validate hex characters
    if re.match(r'^[a-f0-9]+$', hash_value):
        return hash_value
    else:
        return value.strip()

def normalize_email(value: str) -> str:
    """Normalize email address"""
    return value.strip().lower()

def normalize_asn(value: str) -> str:
    """Normalize ASN"""
    asn = value.strip().upper()
    
    # Ensure AS prefix
    if not asn.startswith('AS'):
        asn = 'AS' + asn
    
    return asn

def normalize_cve(value: str) -> str:
    """Normalize CVE identifier"""
    return value.strip().upper()

def normalize_indicator(indicator_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize indicator data
    
    Args:
        indicator_data: Raw indicator data
        
    Returns:
        Normalized indicator data
    """
    normalized = indicator_data.copy()
    
    indicator_type = normalized.get('indicator_type', '').lower()
    value = normalized.get('value', '')
    
    # Normalize the value based on type
    normalizers = {
        'ip_address': normalize_ip_address,
        'domain': normalize_domain,
        'url': normalize_url,
        'file_hash': lambda v: normalize_file_hash(v, normalized.get('hash_type')),
        'email': normalize_email,
        'asn': normalize_asn,
        'vulnerability': normalize_cve,
    }
    
    normalizer = normalizers.get(indicator_type)
    if normalizer:
        normalized_value = normalizer(value)
        normalized['normalized_value'] = normalized_value
        
        # Update the original value if it was significantly changed
        if indicator_type in ['domain', 'email', 'file_hash', 'asn', 'vulnerability']:
            normalized['value'] = normalized_value
    else:
        normalized['normalized_value'] = value.strip()
    
    # Normalize other fields
    if 'confidence' in normalized:
        normalized['confidence'] = normalized['confidence'].lower()
    
    if 'threat_types' in normalized:
        if isinstance(normalized['threat_types'], list):
            normalized['threat_types'] = [t.lower() for t in normalized['threat_types']]
        elif isinstance(normalized['threat_types'], str):
            normalized['threat_types'] = [normalized['threat_types'].lower()]
        else:
            normalized['threat_types'] = []
    
    if 'tags' in normalized:
        if isinstance(normalized['tags'], list):
            normalized['tags'] = [tag.lower().strip() for tag in normalized['tags'] if tag]
        elif isinstance(normalized['tags'], str):
            # Split comma-separated tags
            normalized['tags'] = [tag.lower().strip() for tag in normalized['tags'].split(',') if tag.strip()]
        else:
            normalized['tags'] = []
    
    # Ensure severity is an integer
    if 'severity' in normalized:
        try:
            normalized['severity'] = int(normalized['severity'])
        except (ValueError, TypeError):
            normalized['severity'] = 5  # Default severity
    
    # Normalize timestamps
    timestamp_fields = ['first_seen', 'last_seen', 'expires_at']
    for field in timestamp_fields:
        if field in normalized and normalized[field]:
            normalized[field] = normalize_timestamp(normalized[field])
    
    return normalized

def normalize_timestamp(timestamp: Any) -> Optional[datetime]:
    """
    Normalize timestamp to datetime object
    
    Args:
        timestamp: Timestamp in various formats
        
    Returns:
        Normalized datetime object or None
    """
    if isinstance(timestamp, datetime):
        # Ensure timezone awareness
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp
    
    if isinstance(timestamp, str):
        timestamp = timestamp.strip()
        if not timestamp:
            return None
        
        # Common timestamp formats
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%d',
            '%d/%m/%Y %H:%M:%S',
            '%d/%m/%Y',
            '%m/%d/%Y %H:%M:%S',
            '%m/%d/%Y',
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp, fmt)
                # Add UTC timezone if not present
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        
        # Try parsing Unix timestamp
        try:
            unix_timestamp = float(timestamp)
            return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
        except ValueError:
            pass
    
    elif isinstance(timestamp, (int, float)):
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            pass
    
    return None

def create_fingerprint(indicator_data: Dict[str, Any]) -> str:
    """
    Create a fingerprint for deduplication
    
    Args:
        indicator_data: Indicator data
        
    Returns:
        Fingerprint string
    """
    # Use normalized values for fingerprinting
    key_parts = [
        indicator_data.get('indicator_type', ''),
        indicator_data.get('normalized_value', ''),
        indicator_data.get('source_id', ''),
    ]
    
    # Create deterministic fingerprint
    fingerprint_string = '|'.join(str(part) for part in key_parts)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]

def merge_indicators(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two indicator records intelligently
    
    Args:
        existing: Existing indicator data
        new: New indicator data
        
    Returns:
        Merged indicator data
    """
    merged = existing.copy()
    
    # Update last_seen to the most recent
    if 'last_seen' in new and new['last_seen']:
        new_last_seen = normalize_timestamp(new['last_seen'])
        existing_last_seen = normalize_timestamp(existing.get('last_seen'))
        
        if new_last_seen and (not existing_last_seen or new_last_seen > existing_last_seen):
            merged['last_seen'] = new_last_seen
    
    # Keep the earliest first_seen
    if 'first_seen' in new and new['first_seen']:
        new_first_seen = normalize_timestamp(new['first_seen'])
        existing_first_seen = normalize_timestamp(existing.get('first_seen'))
        
        if new_first_seen and (not existing_first_seen or new_first_seen < existing_first_seen):
            merged['first_seen'] = new_first_seen
    
    # Merge threat types
    existing_threats = set(existing.get('threat_types', []))
    new_threats = set(new.get('threat_types', []))
    merged['threat_types'] = list(existing_threats | new_threats)
    
    # Merge tags
    existing_tags = set(existing.get('tags', []))
    new_tags = set(new.get('tags', []))
    merged['tags'] = list(existing_tags | new_tags)
    
    # Use higher confidence level
    confidence_levels = {'low': 1, 'medium': 2, 'high': 3, 'verified': 4}
    existing_conf = confidence_levels.get(existing.get('confidence', 'medium'), 2)
    new_conf = confidence_levels.get(new.get('confidence', 'medium'), 2)
    
    if new_conf > existing_conf:
        merged['confidence'] = new['confidence']
    
    # Use higher severity
    existing_severity = existing.get('severity', 5)
    new_severity = new.get('severity', 5)
    merged['severity'] = max(existing_severity, new_severity)
    
    # Update description if new one is longer or existing is empty
    if 'description' in new and new['description']:
        if not existing.get('description') or len(new['description']) > len(existing['description']):
            merged['description'] = new['description']
    
    # Merge metadata
    existing_metadata = existing.get('metadata', {})
    new_metadata = new.get('metadata', {})
    merged['metadata'] = {**existing_metadata, **new_metadata}
    
    return merged
