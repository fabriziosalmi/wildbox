import asyncio
import logging
import os
import time
import urllib.parse
import base64
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)

# A WAF-bypass tester sends attack payloads to a live target. It only runs
# against hosts the operator has explicitly authorised: the built-in list
# below (safe public test endpoints) plus anything in the
# WAF_BYPASS_AUTHORIZED_DOMAINS environment variable (comma-separated). This
# is not security theatre — without it the tool is an attack proxy.
_ENV_AUTHORIZED = [
    d.strip().lower()
    for d in os.getenv("WAF_BYPASS_AUTHORIZED_DOMAINS", "").split(",")
    if d.strip()
]

# Requests that carry a WAF block are commonly one of these, in addition to
# any response matched by the signature/pattern detector.
_BLOCK_STATUS_CODES = {403, 406, 429, 501, 503}

# Cap the real request volume: the payload x encoding x obfuscation grid can
# be large, and this hits a live host.
_MAX_REQUESTS = 200
_CONCURRENCY = 5

try:
    from schemas import (
        WAFBypassRequest, WAFBypassResponse, WAFBypassPayload, 
        WAFBypassTechnique
    )
except ImportError:
    from schemas import (
        WAFBypassRequest, WAFBypassResponse, WAFBypassPayload, 
        WAFBypassTechnique
    )

# Tool metadata
TOOL_INFO = {
    "name": "web_application_firewall_bypass",
    "display_name": "WAF Bypass Tester",
    "description": (
        "Sends real encoded/obfuscated attack payloads to a target and reports "
        "which get through its WAF, based on the actual HTTP responses. Only "
        "runs against authorised hosts (built-in test endpoints plus "
        "WAF_BYPASS_AUTHORIZED_DOMAINS)."
    ),
    "category": "web_security",
    "author": "Wildbox Security",
    "version": "2.0.0",
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
        # SAFE, non-destructive test payloads for security testing
        self.base_payloads = {
            "sql_injection": [
                "' OR '1'='1",  # Basic boolean injection test
                "1 UNION SELECT null",  # Structure test only
                "admin'--",  # Comment injection test
                "' OR 1=1--",  # Basic OR condition
                "1' AND 1=1--"  # Basic AND condition
            ],
            "xss": [
                "<img src=x>",  # Basic HTML tag test
                "javascript:void(0)",  # Safe JavaScript test
                "<svg>test</svg>",  # SVG tag test
                "'><script>void(0)</script>",  # Safe script test
                "alert(String.fromCharCode(88,83,83))"  # Encoded alert test
            ],
            "command_injection": [
                "; echo test",  # Safe echo command
                "| echo test",  # Safe pipe test
                "&& echo test",  # Safe AND test
                "`echo test`",  # Safe backtick test
                "$(echo test)"  # Safe subshell test
            ],
            "path_traversal": [
                "../test.txt",  # Basic traversal test
                "..\\test.txt",  # Windows traversal test
                "%2e%2e%2ftest.txt",  # Encoded traversal test
                "....//test.txt"  # Double-dot test
            ],
            "xxe": [
                "<?xml version='1.0'?><!DOCTYPE test [<!ENTITY test 'safe'>]><test>&test;</test>",
                "<!DOCTYPE test [<!ENTITY % test SYSTEM 'http://safe.example.com/test.dtd'> %test;]>"
            ],
            "ssrf": [
                "http://httpbin.org/get",  # Safe public test endpoint
                "http://127.0.0.1:80",  # Safe localhost test
                "http://169.254.169.254/",  # Metadata service test (safe check)
                "file:///dev/null"  # Safe file test
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
    
        # Add target authorization validation
        self.authorized_domains = [
            "httpbin.org", "example.com", "safe.example.com",
            "localhost", "127.0.0.1", "test.local"
        ]

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
    
    async def _send_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict:
        """Send the payload to the real target as a query parameter.

        Returns the real status code, headers, body and size — or an error
        string if the request could not be completed. WAFs inspect the query
        string, so injecting the payload there is the standard way to test
        whether it gets through.
        """
        parsed = urllib.parse.urlparse(url)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        query["q"] = payload
        target = parsed._replace(query=urllib.parse.urlencode(query)).geturl()

        request_headers = {
            "User-Agent": "Wildbox-WAF-Bypass-Tester/2.0",
            **(headers or {}),
        }

        try:
            async with session.get(
                target, headers=request_headers, allow_redirects=False
            ) as response:
                body = await response.text(errors="replace")
                return {
                    "status_code": response.status,
                    "headers": {k.lower(): v for k, v in response.headers.items()},
                    "body": body,
                    "size": len(body),
                    "error": None,
                }
        except asyncio.TimeoutError:
            return {"status_code": 0, "headers": {}, "body": "", "size": 0,
                    "error": "request timed out"}
        except aiohttp.ClientError as exc:
            return {"status_code": 0, "headers": {}, "body": "", "size": 0,
                    "error": f"request failed: {exc}"}

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

    def _validate_target_authorization(self, url: str) -> bool:
        """Validate that target URL is authorized for testing"""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check against authorized domains (built-in + operator-supplied)
            for authorized in self.authorized_domains + _ENV_AUTHORIZED:
                if domain == authorized or domain.endswith(f".{authorized}"):
                    return True
            
            # Additional checks for explicit testing consent
            # Could check for special headers or domain patterns
            if domain.endswith('.test') or domain.endswith('.local'):
                return True
                
            return False
            
        except Exception:
            return False

async def execute_tool(request: WAFBypassRequest) -> WAFBypassResponse:
    """Execute WAF bypass testing"""
    start_time = time.time()
    
    tester = WAFBypassTester()
    
    # CRITICAL: Validate target authorization before testing
    if not tester._validate_target_authorization(request.target_url):
        return WAFBypassResponse(
            target_url=request.target_url,
            waf_detected=False,
            waf_type=None,
            waf_version=None,
            total_payloads_tested=0,
            successful_bypasses=0,
            bypass_success_rate=0.0,
            techniques_tested=[],
            most_effective_technique=None,
            payload_results=[],
            blocked_patterns=[],
            allowed_patterns=[],
            filtering_rules=["UNAUTHORIZED TARGET - Testing blocked for security"],
            risk_level="Critical",
            vulnerability_summary="Target not authorized for security testing",
            bypass_recommendations=["Only test against authorized targets"],
            waf_improvement_suggestions=["Ensure proper authorization before testing"],
            timestamp=datetime.now().isoformat(),
            processing_time_ms=int((time.time() - start_time) * 1000),
            success=False,
            summary="Target not authorised for WAF bypass testing",
        )
    
    # Build the full payload grid up front so it can be capped and run with
    # bounded concurrency against the live target.
    jobs = []
    for payload_type in request.payload_types:
        if payload_type not in tester.base_payloads:
            continue
        for base_payload in tester.base_payloads[payload_type]:
            for encoding in request.encoding_techniques:
                for obfuscation in request.obfuscation_methods:
                    modified = tester._encode_payload(base_payload, encoding)
                    modified = tester._obfuscate_payload(modified, obfuscation)
                    jobs.append((payload_type, base_payload, encoding, obfuscation, modified))

    truncated = len(jobs) > _MAX_REQUESTS
    jobs = jobs[:_MAX_REQUESTS]

    payload_results: List[WAFBypassPayload] = []
    timeout = aiohttp.ClientTimeout(total=request.timeout)
    connector = aiohttp.TCPConnector(ssl=request.verify_ssl)
    semaphore = asyncio.Semaphore(_CONCURRENCY)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:

        async def run_job(job):
            payload_type, base_payload, encoding, obfuscation, modified = job
            async with semaphore:
                response = await tester._send_request(
                    session, request.target_url, modified, request.custom_headers
                )
            waf_triggered, _ = tester._detect_waf(response["headers"], response["body"])

            # A bypass means the attack payload reached the app without being
            # blocked: a real 2xx/3xx AND no WAF block signature. A failed
            # request (error / status 0) is never counted as a bypass.
            blocked = (
                response["error"] is not None
                or response["status_code"] in _BLOCK_STATUS_CODES
                or response["status_code"] == 0
                or waf_triggered
            )
            bypass_success = (not blocked) and 200 <= response["status_code"] < 400

            detection_signatures = []
            if waf_triggered:
                headers_str = str(response["headers"]).lower()
                for waf_name, signatures in tester.waf_signatures.items():
                    for sig in signatures:
                        if sig.lower() in headers_str:
                            detection_signatures.append(f"{waf_name}:{sig}")

            return WAFBypassPayload(
                original_payload=base_payload,
                modified_payload=modified,
                technique=payload_type,
                encoding=encoding,
                obfuscation=obfuscation,
                bypass_success=bypass_success,
                response_code=response["status_code"],
                response_size=response["size"],
                waf_triggered=waf_triggered,
                detection_signatures=detection_signatures,
            )

        payload_results = await asyncio.gather(*(run_job(j) for j in jobs))

    # Analyze results
    successful_bypasses = sum(1 for p in payload_results if p.bypass_success)
    total_payloads = len(payload_results)
    bypass_rate = successful_bypasses / total_payloads if total_payloads > 0 else 0
    
    # Detect the WAF from a clean baseline request to the real target.
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=request.timeout),
        connector=aiohttp.TCPConnector(ssl=request.verify_ssl),
    ) as session:
        baseline = await tester._send_request(session, request.target_url, "wildbox-baseline")
    waf_detected, waf_type = tester._detect_waf(baseline["headers"], baseline["body"])
    
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
    if truncated:
        vulnerability_summary += (
            f"Note: the payload grid was capped at {_MAX_REQUESTS} requests. "
        )
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
        filtering_rules=sorted({
            f"{p.technique} payloads blocked ({p.encoding}/{p.obfuscation})"
            for p in payload_results
            if p.waf_triggered or p.response_code in _BLOCK_STATUS_CODES
        }) or ["No payloads were blocked by the target"],
        risk_level=risk_level,
        vulnerability_summary=vulnerability_summary,
        bypass_recommendations=bypass_recommendations,
        waf_improvement_suggestions=waf_improvements,
        timestamp=datetime.now().isoformat(),
        processing_time_ms=processing_time,
        success=True,
        summary=(
            f"Tested {total_payloads} payloads against {request.target_url}: "
            f"{successful_bypasses} reached the application"
        )
    )
