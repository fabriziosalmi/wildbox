"""XSS Scanner Tool - Tests for Cross-Site Scripting vulnerabilities."""

import time
import requests
import re
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode
try:
    from .schemas import XSSScannerInput, XSSScannerOutput, XSSResult
except ImportError:
    from schemas import XSSScannerInput, XSSScannerOutput, XSSResult

# XSS payloads for different types
REFLECTED_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror='alert(\"XSS\")'>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=\"javascript:alert('XSS')\">",
    "<body onload=alert('XSS')>",
    "<div onmouseover=alert('XSS')>test</div>"
]

STORED_XSS_PAYLOADS = [
    "<script>alert('StoredXSS')</script>",
    "<img src=x onerror=alert('StoredXSS')>",
    "<svg onload=alert('StoredXSS')>",
    "<iframe src='javascript:alert(\"StoredXSS\")'></iframe>",
    "<input onfocus=alert('StoredXSS') autofocus>",
    "<video><source onerror='alert(\"StoredXSS\")'>",
    "<audio src=x onerror=alert('StoredXSS')>",
    "<details open ontoggle=alert('StoredXSS')>",
    "'\"><script>alert('StoredXSS')</script>",
    "\"><script>alert('StoredXSS')</script>",
    "'><script>alert('StoredXSS')</script>"
]

DOM_XSS_PAYLOADS = [
    "#<script>alert('DOMXSS')</script>",
    "#<img src=x onerror=alert('DOMXSS')>",
    "#<svg onload=alert('DOMXSS')>",
    "javascript:alert('DOMXSS')",
    "#'\"><script>alert('DOMXSS')</script>",
    "#\"><script>alert('DOMXSS')</script>",
    "#'><script>alert('DOMXSS')</script>",
    "?test=<script>alert('DOMXSS')</script>",
    "&param=<script>alert('DOMXSS')</script>"
]

# Patterns that indicate successful XSS
XSS_INDICATORS = [
    r"<script[^>]*>.*?alert\s*\([^)]*\).*?</script>",
    r"<img[^>]*onerror\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"<svg[^>]*onload\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"<iframe[^>]*src\s*=\s*['\"]?javascript:",
    r"<input[^>]*onfocus\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"<video[^>]*>.*?<source[^>]*onerror\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"<audio[^>]*onerror\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"<details[^>]*ontoggle\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"<marquee[^>]*onstart\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"<body[^>]*onload\s*=\s*['\"]?alert\s*\([^)]*\)",
    r"<div[^>]*onmouseover\s*=\s*['\"]?alert\s*\([^)]*\)"
]

def get_payloads(payload_type: str) -> List[tuple]:
    """Get XSS payloads based on type."""
    payloads = []
    
    if payload_type in ["all", "reflected"]:
        payloads.extend([(p, "reflected") for p in REFLECTED_XSS_PAYLOADS])
    
    if payload_type in ["all", "stored"]:
        payloads.extend([(p, "stored") for p in STORED_XSS_PAYLOADS])
    
    if payload_type in ["all", "dom"]:
        payloads.extend([(p, "dom") for p in DOM_XSS_PAYLOADS])
    
    return payloads

def detect_xss(response_text: str, payload: str) -> tuple:
    """Detect if XSS payload was successfully executed."""
    # Check if payload appears unescaped in response
    if payload in response_text:
        return True, "high", f"Payload appears unescaped: {payload[:50]}..."
    
    # Check for XSS indicators using regex
    for pattern in XSS_INDICATORS:
        matches = re.finditer(pattern, response_text, re.IGNORECASE | re.DOTALL)
        for match in matches:
            if any(keyword in match.group().lower() for keyword in ['alert', 'prompt', 'confirm']):
                return True, "high", f"XSS pattern detected: {match.group()[:100]}..."
    
    # Check for partial payload reflection
    payload_parts = payload.split()
    reflected_parts = sum(1 for part in payload_parts if part in response_text)
    
    if reflected_parts > len(payload_parts) * 0.7:  # 70% of payload reflected
        return True, "medium", f"Partial payload reflection detected"
    elif reflected_parts > 0:
        return True, "low", f"Some payload parts reflected"
    
    return False, "none", None

def test_xss_payload(url: str, method: str, param_name: str, payload: str, xss_type: str, headers: Dict, timeout: int) -> XSSResult:
    """Test a single XSS payload."""
    start_time = time.time()
    
    try:
        if method.upper() == "GET":
            # Parse URL and modify parameter
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            response = requests.get(test_url, headers=headers, timeout=timeout)
        else:
            # POST request
            data = {param_name: payload}
            response = requests.post(url, data=data, headers=headers, timeout=timeout)
        
        response_time = time.time() - start_time
        
        # Detect XSS
        vulnerable, confidence, evidence = detect_xss(response.text, payload)
        
        return XSSResult(
            parameter=param_name,
            payload=payload,
            xss_type=xss_type,
            vulnerable=vulnerable,
            evidence=evidence,
            response_time=response_time,
            confidence=confidence
        )
        
    except Exception as e:
        response_time = time.time() - start_time
        return XSSResult(
            parameter=param_name,
            payload=payload,
            xss_type=xss_type,
            vulnerable=False,
            evidence=f"Request failed: {str(e)}",
            response_time=response_time,
            confidence="none"
        )

def execute_tool(input_data: XSSScannerInput) -> XSSScannerOutput:
    """Execute the XSS scanner tool."""
    timestamp = datetime.now()
    results = []
    
    # Default headers
    headers = input_data.headers or {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Extract parameters from URL if not provided
    parameters = input_data.parameters or {}
    if not parameters and "?" in input_data.target_url:
        parsed_url = urlparse(input_data.target_url)
        parameters = dict(parse_qs(parsed_url.query))
        # Convert list values to single values
        parameters = {k: v[0] if isinstance(v, list) else v for k, v in parameters.items()}
    
    # If no parameters found, create a default test parameter
    if not parameters:
        parameters = {"q": "test"}
    
    # Get payloads based on type
    payloads = get_payloads(input_data.payload_type)
    
    # Test each parameter with each payload
    for param_name, param_value in parameters.items():
        for payload, xss_type in payloads:
            result = test_xss_payload(
                input_data.target_url,
                input_data.method,
                param_name,
                payload,
                xss_type,
                headers,
                input_data.timeout
            )
            results.append(result)
    
    # Count vulnerabilities
    vulnerabilities_found = sum(1 for result in results if result.vulnerable)
    
    # Generate recommendations
    recommendations = [
        "Implement proper input validation and output encoding",
        "Use Content Security Policy (CSP) headers",
        "Sanitize user input on both client and server side",
        "Use HTTP-only and Secure flags for cookies",
        "Implement proper escaping for different contexts (HTML, JavaScript, CSS)",
        "Regular security code reviews and penetration testing"
    ]
    
    if vulnerabilities_found > 0:
        recommendations.insert(0, "CRITICAL: XSS vulnerabilities detected - fix immediately!")
        recommendations.insert(1, "Review all user input handling and output encoding")
    
    return XSSScannerOutput(
        target_url=input_data.target_url,
        timestamp=timestamp,
        total_tests=len(results),
        vulnerabilities_found=vulnerabilities_found,
        results=results,
        recommendations=recommendations
    )

# Tool metadata
TOOL_INFO = {
    "name": "xss_scanner",
    "display_name": "XSS Scanner",
    "description": "Tests web applications for Cross-Site Scripting (XSS) vulnerabilities",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "web_security"
}
