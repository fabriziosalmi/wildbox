"""
JWT Decoder Tool

This tool decodes and analyzes JSON Web Tokens (JWTs) with comprehensive
security analysis and validation capabilities.
"""

import json
import base64
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
import re

try:
    from .schemas import (
        JWTDecoderInput, JWTDecoderOutput, JWTHeader, JWTPayload, 
        JWTSecurityAnalysis
    )
except ImportError:
    from schemas import (
        JWTDecoderInput, JWTDecoderOutput, JWTHeader, JWTPayload, 
        JWTSecurityAnalysis
    )


class JWTDecoder:
    """JWT decoder and analyzer with security assessment"""
    
    # Algorithm security classifications
    ALGORITHM_SECURITY = {
        "none": "insecure",
        "HS256": "good",
        "HS384": "good", 
        "HS512": "good",
        "RS256": "excellent",
        "RS384": "excellent",
        "RS512": "excellent",
        "ES256": "excellent",
        "ES384": "excellent",
        "ES512": "excellent",
        "PS256": "excellent",
        "PS384": "excellent",
        "PS512": "excellent"
    }
    
    # Deprecated or weak algorithms
    WEAK_ALGORITHMS = ["none", "HS256"]
    
    # Standard JWT claims
    STANDARD_CLAIMS = {
        "iss": "issuer",
        "sub": "subject", 
        "aud": "audience",
        "exp": "expiration",
        "nbf": "not_before",
        "iat": "issued_at",
        "jti": "jwt_id"
    }
    
    def __init__(self):
        pass
    
    def base64url_decode(self, data: str) -> bytes:
        """Decode base64url encoded data"""
        # Add padding if necessary
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        
        # Replace URL-safe characters
        data = data.replace('-', '+').replace('_', '/')
        
        try:
            return base64.b64decode(data)
        except Exception as e:
            raise ValueError(f"Invalid base64url encoding: {str(e)}")
    
    def decode_jwt_part(self, part: str) -> Dict[str, Any]:
        """Decode a JWT part (header or payload)"""
        try:
            decoded_bytes = self.base64url_decode(part)
            decoded_str = decoded_bytes.decode('utf-8')
            return json.loads(decoded_str)
        except Exception as e:
            raise ValueError(f"Failed to decode JWT part: {str(e)}")
    
    def parse_timestamp(self, timestamp: int) -> datetime:
        """Convert Unix timestamp to datetime"""
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (ValueError, OSError) as e:
            raise ValueError(f"Invalid timestamp: {timestamp}")
    
    def analyze_header(self, header_data: Dict[str, Any]) -> JWTHeader:
        """Analyze JWT header"""
        algorithm = header_data.get("alg", "unknown")
        token_type = header_data.get("typ", "unknown")
        key_id = header_data.get("kid")
        
        return JWTHeader(
            algorithm=algorithm,
            type=token_type,
            key_id=key_id,
            raw_header=header_data
        )
    
    def analyze_payload(self, payload_data: Dict[str, Any]) -> JWTPayload:
        """Analyze JWT payload"""
        # Extract standard claims
        issuer = payload_data.get("iss")
        subject = payload_data.get("sub")
        audience = payload_data.get("aud")
        jwt_id = payload_data.get("jti")
        
        # Parse timestamps
        expiration = None
        not_before = None
        issued_at = None
        
        if "exp" in payload_data:
            try:
                expiration = self.parse_timestamp(payload_data["exp"])
            except ValueError:
                pass
        
        if "nbf" in payload_data:
            try:
                not_before = self.parse_timestamp(payload_data["nbf"])
            except ValueError:
                pass
        
        if "iat" in payload_data:
            try:
                issued_at = self.parse_timestamp(payload_data["iat"])
            except ValueError:
                pass
        
        # Extract custom claims (non-standard claims)
        custom_claims = {
            k: v for k, v in payload_data.items() 
            if k not in self.STANDARD_CLAIMS
        }
        
        return JWTPayload(
            issuer=issuer,
            subject=subject,
            audience=audience,
            expiration=expiration,
            not_before=not_before,
            issued_at=issued_at,
            jwt_id=jwt_id,
            custom_claims=custom_claims,
            raw_payload=payload_data
        )
    
    def verify_hmac_signature(self, token: str, secret: str, algorithm: str) -> bool:
        """Verify HMAC signature"""
        try:
            # Split token
            parts = token.split('.')
            if len(parts) != 3:
                return False
            
            header_payload = f"{parts[0]}.{parts[1]}"
            signature = parts[2]
            
            # Determine hash function
            if algorithm == "HS256":
                hash_func = hashlib.sha256
            elif algorithm == "HS384":
                hash_func = hashlib.sha384
            elif algorithm == "HS512":
                hash_func = hashlib.sha512
            else:
                return False
            
            # Calculate expected signature
            expected_signature = hmac.new(
                secret.encode('utf-8'),
                header_payload.encode('utf-8'),
                hash_func
            ).digest()
            
            # Encode as base64url
            expected_b64 = base64.urlsafe_b64encode(expected_signature).decode('utf-8').rstrip('=')
            
            # Compare signatures
            return hmac.compare_digest(signature, expected_b64)
            
        except Exception:
            return False
    
    def analyze_security(self, header: JWTHeader, payload: JWTPayload, 
                        token: str, verify_signature: bool = False, 
                        secret_key: Optional[str] = None) -> JWTSecurityAnalysis:
        """Perform comprehensive security analysis"""
        
        issues = []
        recommendations = []
        algorithm_security = self.ALGORITHM_SECURITY.get(header.algorithm, "unknown")
        
        # Algorithm analysis
        if header.algorithm == "none":
            issues.append("Algorithm 'none' allows unsigned tokens")
            recommendations.append("Use a proper signing algorithm (RS256, ES256, etc.)")
        elif header.algorithm in self.WEAK_ALGORITHMS:
            issues.append(f"Algorithm '{header.algorithm}' has known vulnerabilities")
            recommendations.append("Consider using RS256 or ES256 for better security")
        
        # Header analysis
        if not header.key_id and header.algorithm.startswith(("RS", "ES", "PS")):
            recommendations.append("Consider using 'kid' claim for key identification")
        
        # Payload analysis
        current_time = datetime.now(timezone.utc)
        is_expired = False
        is_premature = False
        
        if payload.expiration:
            is_expired = current_time > payload.expiration
            if is_expired:
                issues.append("Token is expired")
        else:
            issues.append("Token has no expiration time (exp claim)")
            recommendations.append("Always include expiration time for security")
        
        if payload.not_before:
            is_premature = current_time < payload.not_before
            if is_premature:
                issues.append("Token is not yet valid (nbf claim)")
        
        if not payload.issuer:
            recommendations.append("Consider including issuer (iss claim) for validation")
        
        if not payload.audience:
            recommendations.append("Consider including audience (aud claim) for validation")
        
        if not payload.issued_at:
            recommendations.append("Consider including issued at (iat claim) for tracking")
        
        # Token structure analysis
        if len(token) > 8192:  # Very long token
            issues.append("Token is unusually long, may indicate excessive claims")
            recommendations.append("Minimize token size for better performance")
        
        # Custom claims analysis
        sensitive_patterns = [
            r'password', r'secret', r'key', r'token', r'credential',
            r'ssn', r'social.*security', r'credit.*card', r'bank.*account'
        ]
        
        for claim_name, claim_value in payload.custom_claims.items():
            claim_str = f"{claim_name}:{str(claim_value)}".lower()
            for pattern in sensitive_patterns:
                if re.search(pattern, claim_str, re.IGNORECASE):
                    issues.append(f"Potentially sensitive information in claim: {claim_name}")
                    recommendations.append("Avoid storing sensitive data in JWT claims")
                    break
        
        # Signature verification
        signature_valid = None
        if verify_signature and secret_key and header.algorithm.startswith("HS"):
            signature_valid = self.verify_hmac_signature(token, secret_key, header.algorithm)
            if not signature_valid:
                issues.append("JWT signature verification failed")
        
        # General recommendations
        if not issues:
            recommendations.append("JWT appears to follow security best practices")
        else:
            recommendations.append("Review and address identified security issues")
        
        return JWTSecurityAnalysis(
            algorithm_security=algorithm_security,
            security_issues=issues,
            recommendations=recommendations,
            is_expired=is_expired,
            is_premature=is_premature,
            signature_valid=signature_valid
        )
    
    async def decode_jwt(self, token: str, verify_signature: bool = False,
                        secret_key: Optional[str] = None, 
                        public_key: Optional[str] = None) -> Dict[str, Any]:
        """Decode and analyze a JWT token"""
        
        # Validate token format
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
        
        header_part, payload_part, signature_part = parts
        
        # Decode header
        try:
            header_data = self.decode_jwt_part(header_part)
            header = self.analyze_header(header_data)
        except Exception as e:
            raise ValueError(f"Failed to decode JWT header: {str(e)}")
        
        # Decode payload
        try:
            payload_data = self.decode_jwt_part(payload_part)
            payload = self.analyze_payload(payload_data)
        except Exception as e:
            raise ValueError(f"Failed to decode JWT payload: {str(e)}")
        
        # Analyze security
        security_analysis = self.analyze_security(
            header, payload, token, verify_signature, secret_key
        )
        
        return {
            "header": header,
            "payload": payload,
            "signature": signature_part,
            "security_analysis": security_analysis,
            "is_valid": True
        }


async def execute_tool(input_data: JWTDecoderInput) -> JWTDecoderOutput:
    """Execute the JWT decoder tool"""
    
    try:
        decoder = JWTDecoder()
        
        # Basic validation
        token = input_data.jwt_token.strip()
        parts = token.split('.')
        
        if len(parts) != 3:
            return JWTDecoderOutput(
                success=False,
                is_valid_jwt=False,
                header=None,
                payload=None,
                signature=None,
                security_analysis=None,
                token_length=len(token),
                parts_count=len(parts),
                error=f"Invalid JWT format: expected 3 parts separated by dots, got {len(parts)}"
            )
        
        # Decode JWT
        result = await decoder.decode_jwt(
            token,
            input_data.verify_signature,
            input_data.secret_key,
            input_data.public_key
        )
        
        return JWTDecoderOutput(
            success=True,
            is_valid_jwt=True,
            header=result["header"],
            payload=result["payload"],
            signature=result["signature"],
            security_analysis=result["security_analysis"],
            token_length=len(token),
            parts_count=len(parts)
        )
        
    except Exception as e:
        return JWTDecoderOutput(
            success=False,
            is_valid_jwt=False,
            header=None,
            payload=None,
            signature=None,
            security_analysis=None,
            token_length=len(input_data.jwt_token) if input_data.jwt_token else 0,
            parts_count=len(input_data.jwt_token.split('.')) if input_data.jwt_token else 0,
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "jwt_decoder",
    "display_name": "JWT Decoder & Analyzer",
    "description": "Decode and analyze JSON Web Tokens with comprehensive security assessment",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "authentication"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        # Create a sample JWT for testing
        import base64
        import json
        
        # Sample header and payload
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "name": "John Doe", 
            "iat": 1516239022,
            "exp": 1516242622,
            "iss": "test-issuer"
        }
        
        # Encode without signature for testing
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        test_jwt = f"{header_b64}.{payload_b64}.fake_signature"
        
        test_input = JWTDecoderInput(
            jwt_token=test_jwt,
            verify_signature=False,
            check_expiration=True,
            check_security=True
        )
        
        result = await execute_tool(test_input)
        print(f"JWT Decoding Success: {result.success}")
        print(f"Is Valid JWT: {result.is_valid_jwt}")
        if result.header:
            print(f"Algorithm: {result.header.algorithm}")
            print(f"Type: {result.header.type}")
        if result.payload:
            print(f"Subject: {result.payload.subject}")
            print(f"Issuer: {result.payload.issuer}")
            print(f"Expired: {result.security_analysis.is_expired if result.security_analysis else 'Unknown'}")
        if result.security_analysis:
            print(f"Security Issues: {len(result.security_analysis.security_issues)}")
            print(f"Algorithm Security: {result.security_analysis.algorithm_security}")
    
    asyncio.run(test())
