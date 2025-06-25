"""File Upload Scanner Tool - Tests file upload security vulnerabilities."""

import requests
import io
from datetime import datetime
from typing import List, Dict, Tuple
try:
    from schemas import FileUploadScannerInput, FileUploadScannerOutput, FileUploadResult
except ImportError:
    from schemas import FileUploadScannerInput, FileUploadScannerOutput, FileUploadResult

# Test file configurations
TEST_FILES = {
    # Extension bypass tests
    "php_extension": {
        "filename": "test.php",
        "content": "<?php echo 'PHP Code Execution Test'; ?>",
        "content_type": "application/x-php"
    },
    "php_double_ext": {
        "filename": "test.jpg.php",
        "content": "<?php echo 'PHP Code Execution Test'; ?>",
        "content_type": "image/jpeg"
    },
    "php_null_byte": {
        "filename": "test.php\x00.jpg",
        "content": "<?php echo 'PHP Code Execution Test'; ?>",
        "content_type": "image/jpeg"
    },
    "jsp_extension": {
        "filename": "test.jsp",
        "content": "<%out.print(\"JSP Code Execution Test\");%>",
        "content_type": "application/x-jsp"
    },
    "asp_extension": {
        "filename": "test.asp",
        "content": "<%Response.Write(\"ASP Code Execution Test\")%>",
        "content_type": "application/x-asp"
    },
    "aspx_extension": {
        "filename": "test.aspx",
        "content": "<%Response.Write(\"ASPX Code Execution Test\");%>",
        "content_type": "application/x-aspx"
    },
    
    # Content-Type bypass tests
    "php_image_type": {
        "filename": "test.php",
        "content": "<?php echo 'PHP Code Execution Test'; ?>",
        "content_type": "image/jpeg"
    },
    "php_text_type": {
        "filename": "test.php",
        "content": "<?php echo 'PHP Code Execution Test'; ?>",
        "content_type": "text/plain"
    },
    
    # Magic bytes bypass tests
    "php_with_gif_header": {
        "filename": "test.php",
        "content": "GIF89a<?php echo 'PHP Code Execution Test'; ?>",
        "content_type": "image/gif"
    },
    "php_with_jpeg_header": {
        "filename": "test.php",
        "content": "\xFF\xD8\xFF\xE0<?php echo 'PHP Code Execution Test'; ?>",
        "content_type": "image/jpeg"
    },
    "php_with_png_header": {
        "filename": "test.php",
        "content": "\x89PNG\r\n\x1a\n<?php echo 'PHP Code Execution Test'; ?>",
        "content_type": "image/png"
    },
    
    # Path traversal tests
    "path_traversal": {
        "filename": "../../../test.php",
        "content": "<?php echo 'Path Traversal Test'; ?>",
        "content_type": "application/x-php"
    },
    "windows_path_traversal": {
        "filename": "..\\..\\..\\test.php",
        "content": "<?php echo 'Windows Path Traversal Test'; ?>",
        "content_type": "application/x-php"
    },
    
    # Large file test
    "large_file": {
        "filename": "large.txt",
        "content": "A" * (10 * 1024 * 1024),  # 10MB file
        "content_type": "text/plain"
    },
    
    # Executable file tests
    "exe_file": {
        "filename": "test.exe",
        "content": "MZ\x90\x00" + "A" * 100,  # Fake PE header
        "content_type": "application/octet-stream"
    },
    "script_file": {
        "filename": "test.sh",
        "content": "#!/bin/bash\necho 'Script execution test'",
        "content_type": "application/x-sh"
    }
}

def analyze_response(response: requests.Response, test_file: Dict) -> Tuple[bool, str, str]:
    """Analyze response to detect vulnerabilities."""
    vulnerability_detected = False
    evidence = ""
    risk_level = "low"
    
    # Check if upload was successful (status codes that might indicate success)
    upload_successful = response.status_code in [200, 201, 202, 204, 302, 303]
    
    if upload_successful:
        # Check for code execution indicators
        if any(lang in test_file["filename"] for lang in [".php", ".jsp", ".asp", ".aspx"]):
            if "execution test" in response.text.lower():
                vulnerability_detected = True
                evidence = "Code execution detected in response"
                risk_level = "critical"
            elif response.status_code == 200:
                vulnerability_detected = True
                evidence = "Potential code file uploaded successfully"
                risk_level = "high"
        
        # Check for path traversal success
        if "../" in test_file["filename"] or "..\\" in test_file["filename"]:
            vulnerability_detected = True
            evidence = "Path traversal filename accepted"
            risk_level = "high"
        
        # Check for executable file upload
        if test_file["filename"].endswith((".exe", ".sh", ".bat", ".cmd")):
            vulnerability_detected = True
            evidence = "Executable file uploaded successfully"
            risk_level = "high"
        
        # Check for large file acceptance (potential DoS)
        if len(test_file["content"]) > 5 * 1024 * 1024:  # 5MB+
            vulnerability_detected = True
            evidence = "Large file upload accepted (potential DoS)"
            risk_level = "medium"
        
        # Generic upload success for dangerous extensions
        if not vulnerability_detected and any(ext in test_file["filename"] for ext in [".php", ".jsp", ".asp", ".aspx", ".sh", ".bat"]):
            vulnerability_detected = True
            evidence = "Dangerous file extension uploaded successfully"
            risk_level = "medium"
    
    return vulnerability_detected, evidence, risk_level

def test_file_upload(url: str, file_param: str, test_name: str, test_file: Dict, additional_params: Dict, timeout: int) -> FileUploadResult:
    """Test a single file upload scenario."""
    
    try:
        # Prepare file data
        files = {
            file_param: (
                test_file["filename"],
                io.BytesIO(test_file["content"].encode() if isinstance(test_file["content"], str) else test_file["content"]),
                test_file["content_type"]
            )
        }
        
        # Prepare additional form data
        data = additional_params or {}
        
        # Make request
        response = requests.post(url, files=files, data=data, timeout=timeout)
        
        # Analyze response
        vulnerability_detected, evidence, risk_level = analyze_response(response, test_file)
        
        upload_successful = response.status_code in [200, 201, 202, 204, 302, 303]
        
        return FileUploadResult(
            test_type=test_name,
            filename=test_file["filename"],
            content_type=test_file["content_type"],
            file_content=test_file["content"][:100] + "..." if len(test_file["content"]) > 100 else test_file["content"],
            upload_successful=upload_successful,
            response_status=response.status_code,
            vulnerability_detected=vulnerability_detected,
            evidence=evidence,
            risk_level=risk_level
        )
        
    except Exception as e:
        return FileUploadResult(
            test_type=test_name,
            filename=test_file["filename"],
            content_type=test_file["content_type"],
            file_content=test_file["content"][:100] + "..." if len(test_file["content"]) > 100 else test_file["content"],
            upload_successful=False,
            response_status=0,
            vulnerability_detected=False,
            evidence=f"Request failed: {str(e)}",
            risk_level="low"
        )

def execute_tool(input_data: FileUploadScannerInput) -> FileUploadScannerOutput:
    """Execute the file upload scanner tool."""
    timestamp = datetime.now()
    results = []
    
    # Determine which tests to run
    test_types = input_data.test_types
    
    # Map test types to actual test files
    test_mapping = {
        "extension": ["php_extension", "jsp_extension", "asp_extension", "aspx_extension", "php_double_ext", "php_null_byte"],
        "content_type": ["php_image_type", "php_text_type"],
        "magic_bytes": ["php_with_gif_header", "php_with_jpeg_header", "php_with_png_header"],
        "path_traversal": ["path_traversal", "windows_path_traversal"],
        "large_file": ["large_file"],
        "executable": ["exe_file", "script_file"]
    }
    
    # Collect tests to run
    tests_to_run = []
    for test_type in test_types:
        if test_type in test_mapping:
            tests_to_run.extend(test_mapping[test_type])
        elif test_type == "all":
            for test_list in test_mapping.values():
                tests_to_run.extend(test_list)
    
    # Remove duplicates
    tests_to_run = list(set(tests_to_run))
    
    # Run tests
    for test_name in tests_to_run:
        if test_name in TEST_FILES:
            result = test_file_upload(
                input_data.target_url,
                input_data.file_param,
                test_name,
                TEST_FILES[test_name],
                input_data.additional_params,
                input_data.timeout
            )
            results.append(result)
    
    # Count vulnerabilities
    vulnerabilities_found = sum(1 for result in results if result.vulnerability_detected)
    
    # Generate recommendations
    recommendations = [
        "Implement strict file type validation (whitelist approach)",
        "Validate file extensions on server-side",
        "Check file magic bytes/signatures",
        "Limit file upload size",
        "Store uploaded files outside web root",
        "Use antivirus scanning for uploaded files",
        "Implement proper file naming and sanitization",
        "Set appropriate file permissions",
        "Regular security audits of upload functionality"
    ]
    
    if vulnerabilities_found > 0:
        recommendations.insert(0, "CRITICAL: File upload vulnerabilities detected - fix immediately!")
        recommendations.insert(1, "Review file upload validation and storage mechanisms")
    
    return FileUploadScannerOutput(
        target_url=input_data.target_url,
        timestamp=timestamp,
        total_tests=len(results),
        vulnerabilities_found=vulnerabilities_found,
        results=results,
        recommendations=recommendations
    )

# Tool metadata
TOOL_INFO = {
    "name": "file_upload_scanner",
    "display_name": "File Upload Scanner",
    "description": "Tests file upload functionality for security vulnerabilities",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "web_security"
}
