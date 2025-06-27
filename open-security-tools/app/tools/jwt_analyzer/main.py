"""JWT Analyzer Tool - Analyzes JWT tokens for security vulnerabilities."""

import base64
import json
import hmac
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
try:
    from schemas import JWTAnalyzerInput, JWTAnalyzerOutput, JWTVulnerability, JWTClaim
except ImportError:
    from schemas import JWTAnalyzerInput, JWTAnalyzerOutput, JWTVulnerability, JWTClaim

# Configure logging
logger = logging.getLogger(__name__)

def load_jwt_secrets() -> List[str]:
    """Load JWT secrets from secure configuration file."""
    try:
        # Load from environment-specified file
        secrets_file = os.getenv('JWT_SECRETS_FILE')
        if secrets_file and os.path.exists(secrets_file):
            with open(secrets_file, 'r') as f:
                secrets = [line.strip() for line in f if line.strip()]
                logger.info(f"Loaded {len(secrets)} JWT secrets from configuration")
                return secrets
        else:
            logger.warning("JWT secrets file not configured or not found. Brute force disabled.")
            return []
    except Exception as e:
        logger.error(f"Failed to load JWT secrets: {e}")
        return []

def get_common_secrets() -> List[str]:
    """Get common secrets for JWT analysis with rate limiting."""
    # Only return a minimal set for security analysis
    return ["secret", "password", "test", ""]  # Minimal safe set

def base64url_decode(data: str) -> bytes:
    """Decode base64url encoded data."""
    # Add padding if necessary
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    
    # Replace URL-safe characters
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)

def base64url_encode(data: bytes) -> str:
    """Encode data as base64url."""
    encoded = base64.b64encode(data).decode()
    return encoded.replace('+', '-').replace('/', '_').rstrip('=')

def parse_jwt(token: str) -> Tuple[Optional[Dict], Optional[Dict], str]:
    """Parse JWT token into header, payload, and signature."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, ""
        
        header_data = base64url_decode(parts[0])
        header = json.loads(header_data.decode())
        
        payload_data = base64url_decode(parts[1])
        payload = json.loads(payload_data.decode())
        
        signature = parts[2]
        
        return header, payload, signature
    except Exception:
        return None, None, ""

def verify_signature(header: Dict, payload: Dict, signature: str, secret: str) -> bool:
    """Verify JWT signature with given secret."""
    try:
        alg = header.get('alg', '').upper()
        
        if alg == 'NONE':
            return signature == ""
        
        # Create the signing input
        header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        signing_input = f"{header_encoded}.{payload_encoded}"
        
        if alg == 'HS256':
            expected_signature = hmac.new(
                secret.encode(),
                signing_input.encode(),
                hashlib.sha256
            ).digest()
        elif alg == 'HS384':
            expected_signature = hmac.new(
                secret.encode(),
                signing_input.encode(),
                hashlib.sha384
            ).digest()
        elif alg == 'HS512':
            expected_signature = hmac.new(
                secret.encode(),
                signing_input.encode(),
                hashlib.sha512
            ).digest()
        else:
            return False  # Unsupported algorithm
        
        expected_signature_b64 = base64url_encode(expected_signature)
        return expected_signature_b64 == signature
    
    except Exception:
        return False

def crack_secret(header: Dict, payload: Dict, signature: str, wordlist: List[str]) -> Optional[str]:
    """Attempt to crack JWT secret using wordlist."""
    for secret in wordlist:
        if verify_signature(header, payload, signature, secret):
            return secret
    return None

def analyze_vulnerabilities(header: Dict, payload: Dict) -> List[JWTVulnerability]:
    """Analyze JWT for common vulnerabilities."""
    vulnerabilities = []
    
    # Check for 'none' algorithm
    alg = header.get('alg', '').lower()
    if alg == 'none':
        vulnerabilities.append(JWTVulnerability(
            name="None Algorithm",
            severity="critical",
            description="JWT uses 'none' algorithm, allowing unsigned tokens",
            recommendation="Use a proper signing algorithm like HS256, RS256, or ES256"
        ))
    
    # Check for weak algorithms
    if alg in ['hs256', 'hs384', 'hs512']:
        vulnerabilities.append(JWTVulnerability(
            name="HMAC Algorithm",
            severity="medium",
            description="JWT uses HMAC algorithm which requires shared secret",
            recommendation="Consider using asymmetric algorithms (RS256, ES256) for better security"
        ))
    
    # Check expiration
    exp = payload.get('exp')
    if exp is None:
        vulnerabilities.append(JWTVulnerability(
            name="No Expiration",
            severity="high",
            description="JWT does not have an expiration time (exp claim)",
            recommendation="Always include 'exp' claim with reasonable expiration time"
        ))
    elif isinstance(exp, (int, float)):
        exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        if exp_time < now:
            vulnerabilities.append(JWTVulnerability(
                name="Expired Token",
                severity="medium",
                description="JWT token has expired",
                recommendation="Refresh the token or request a new one"
            ))
        elif (exp_time - now).days > 365:
            vulnerabilities.append(JWTVulnerability(
                name="Long Expiration",
                severity="medium",
                description="JWT token has very long expiration time (>1 year)",
                recommendation="Use shorter expiration times for better security"
            ))
    
    # Check issued at
    iat = payload.get('iat')
    if iat is None:
        vulnerabilities.append(JWTVulnerability(
            name="No Issued At",
            severity="low",
            description="JWT does not have an issued at time (iat claim)",
            recommendation="Include 'iat' claim for better token tracking"
        ))
    
    # Check for sensitive data in payload
    sensitive_keys = ['password', 'secret', 'private_key', 'api_key', 'ssn', 'credit_card']
    for key in payload.keys():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            vulnerabilities.append(JWTVulnerability(
                name="Sensitive Data in Payload",
                severity="high",
                description=f"Potentially sensitive data found in claim: {key}",
                recommendation="Avoid storing sensitive data in JWT payload as it's only base64 encoded"
            ))
    
    # Check for empty or default issuer
    iss = payload.get('iss')
    if iss in [None, "", "test", "localhost", "example.com"]:
        vulnerabilities.append(JWTVulnerability(
            name="Weak Issuer",
            severity="low",
            description="JWT has weak or missing issuer (iss claim)",
            recommendation="Use a proper issuer identifier in production"
        ))
    
    return vulnerabilities

def analyze_claims(payload: Dict) -> List[JWTClaim]:
    """Analyze JWT claims."""
    claims = []
    
    # Standard claims with descriptions
    standard_claims = {
        'iss': 'Issuer - identifies the principal that issued the JWT',
        'sub': 'Subject - identifies the principal that is the subject of the JWT',
        'aud': 'Audience - identifies the recipients that the JWT is intended for',
        'exp': 'Expiration Time - identifies the expiration time on or after which the JWT must not be accepted',
        'nbf': 'Not Before - identifies the time before which the JWT must not be accepted',
        'iat': 'Issued At - identifies the time at which the JWT was issued',
        'jti': 'JWT ID - provides a unique identifier for the JWT'
    }
    
    for key, value in payload.items():
        description = standard_claims.get(key, "Custom claim")
        
        # Format timestamp claims
        if key in ['exp', 'nbf', 'iat'] and isinstance(value, (int, float)):
            try:
                timestamp = datetime.fromtimestamp(value, tz=timezone.utc)
                formatted_value = f"{value} ({timestamp.isoformat()})"
            except (ValueError, OSError, OverflowError) as e:
                logger.debug(f"Error formatting timestamp {value}: {e}")
                formatted_value = value
        else:
            formatted_value = value
        
        claims.append(JWTClaim(
            key=key,
            value=formatted_value,
            description=description
        ))
    
    return claims

def execute_tool(input_data: JWTAnalyzerInput) -> JWTAnalyzerOutput:
    """Execute the JWT analyzer tool."""
    timestamp = datetime.now()
    
    # Parse JWT
    header, payload, signature = parse_jwt(input_data.jwt_token)
    
    if header is None or payload is None:
        return JWTAnalyzerOutput(
            timestamp=timestamp,
            valid_format=False,
            header=None,
            payload=None,
            signature_verified=None,
            cracked_secret=None,
            vulnerabilities=[],
            claims=[],
            recommendations=["Invalid JWT format - check token structure"]
        )
    
    # Analyze vulnerabilities
    vulnerabilities = analyze_vulnerabilities(header, payload)
    
    # Analyze claims
    claims = analyze_claims(payload)
    
    # Attempt signature verification and secret cracking
    signature_verified = None
    cracked_secret = None
    
    if input_data.verify_signature:
        # Use custom wordlist or load from configuration
        wordlist = input_data.secret_wordlist or load_jwt_secrets()
        if not wordlist:
            wordlist = get_common_secrets()  # Minimal fallback
        
        # Try to crack the secret
        cracked_secret = crack_secret(header, payload, signature, wordlist)
        
        if cracked_secret:
            signature_verified = True
            vulnerabilities.append(JWTVulnerability(
                name="Weak Secret",
                severity="critical",
                description=f"JWT secret cracked: '{cracked_secret}'",
                recommendation="Use a strong, random secret key (at least 256 bits)"
            ))
        else:
            # Try empty secret for 'none' algorithm
            if header.get('alg', '').lower() == 'none':
                signature_verified = signature == ""
            else:
                signature_verified = False
    
    # Generate recommendations
    recommendations = [
        "Use strong, random secret keys for HMAC algorithms",
        "Consider using asymmetric algorithms (RS256, ES256) for better security",
        "Always include expiration (exp) and issued at (iat) claims",
        "Avoid storing sensitive data in JWT payload",
        "Implement proper token validation on the server side",
        "Use HTTPS to prevent token interception"
    ]
    
    if vulnerabilities:
        recommendations.insert(0, "Address identified vulnerabilities immediately")
    
    return JWTAnalyzerOutput(
        timestamp=timestamp,
        valid_format=True,
        header=header,
        payload=payload,
        signature_verified=signature_verified,
        cracked_secret=cracked_secret,
        vulnerabilities=vulnerabilities,
        claims=claims,
        recommendations=recommendations
    )

# Tool metadata
TOOL_INFO = {
    "name": "jwt_analyzer",
    "display_name": "JWT Token Analyzer",
    "description": "Analyzes JWT tokens for security vulnerabilities and attempts secret cracking",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "cryptography"
}
