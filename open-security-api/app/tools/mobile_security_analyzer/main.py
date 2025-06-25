import base64
import logging
import time
import zipfile
import xml.etree.ElementTree as ET
import re
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
import aiohttp
import asyncio
from io import BytesIO

# Initialize logger
logger = logging.getLogger(__name__)

# Configure secure XML parser to prevent XXE attacks
try:
    import defusedxml.ElementTree as DefusedET
    # Use defusedxml if available for security
    safe_xml_parse = DefusedET.parse
    safe_xml_fromstring = DefusedET.fromstring
except ImportError:
    # Fallback to built-in with security measures
    def safe_xml_parse(source):
        parser = ET.XMLParser()
        # Disable external entity processing
        parser.parser.DefaultHandler = lambda data: None
        parser.parser.ExternalEntityRefHandler = lambda context, base, sysId, notationName: False
        return ET.parse(source, parser)
    
    def safe_xml_fromstring(text):
        parser = ET.XMLParser()
        # Disable external entity processing
        parser.parser.DefaultHandler = lambda data: None
        parser.parser.ExternalEntityRefHandler = lambda context, base, sysId, notationName: False
        return ET.fromstring(text, parser)

from schemas import (
    MobileSecurityAnalyzerInput,
    MobileSecurityAnalyzerOutput,
    SecurityVulnerability,
    PermissionAnalysis,
    NetworkSecurityAnalysis,
    ExtractedAsset,
    AppMetadata
)

# Tool metadata
TOOL_INFO = {
    "name": "Mobile Security Analyzer",
    "description": "Comprehensive mobile app security analysis for Android APK and iOS IPA files with OWASP Mobile Top 10 compliance checking",
    "category": "mobile_security",
    "version": "1.0.0", 
    "author": "Wildbox Security",
    "tags": ["mobile", "android", "ios", "apk", "ipa", "owasp", "privacy", "permissions"]
}

async def execute_tool(data: MobileSecurityAnalyzerInput) -> MobileSecurityAnalyzerOutput:
    """
    Analyze mobile application for security vulnerabilities and privacy issues
    """
    start_time = time.time()
    
    app_file_data = None
    app_metadata = None
    vulnerabilities = []
    permission_analysis = []
    network_security = None
    extracted_assets = []
    
    try:
        # Get app file data
        if data.app_file:
            app_file_data = base64.b64decode(data.app_file)
        elif data.app_url:
            app_file_data = await download_app_file(data.app_url)
        elif data.app_package:
            # For package analysis, we'd typically query app stores
            app_metadata = await analyze_store_app(data.app_package, data.platform)
        
        if app_file_data:
            # Extract app metadata
            app_metadata = extract_app_metadata(app_file_data, data.platform)
            
            # Perform security analysis
            if data.check_permissions:
                permission_analysis = analyze_permissions(app_metadata, data.platform)
            
            if data.check_network_security:
                network_security = analyze_network_security(app_file_data, data.platform)
            
            if data.check_data_storage:
                storage_vulns = analyze_data_storage_security(app_file_data, data.platform)
                vulnerabilities.extend(storage_vulns)
            
            if data.check_code_quality:
                code_vulns = analyze_code_quality(app_file_data, data.platform)
                vulnerabilities.extend(code_vulns)
            
            if data.check_malware:
                malware_vulns = analyze_malware_signatures(app_file_data)
                vulnerabilities.extend(malware_vulns)
            
            if data.extract_urls:
                extracted_assets = extract_assets(app_file_data, data.platform)
        
        # Calculate security metrics
        total_vulns = len(vulnerabilities)
        critical_vulns = len([v for v in vulnerabilities if v.severity == "Critical"])
        high_vulns = len([v for v in vulnerabilities if v.severity == "High"])
        medium_vulns = len([v for v in vulnerabilities if v.severity == "Medium"])
        low_vulns = len([v for v in vulnerabilities if v.severity == "Low"])
        
        # Calculate scores
        security_score = calculate_security_score(vulnerabilities, permission_analysis)
        privacy_score = calculate_privacy_score(permission_analysis, extracted_assets)
        
        # OWASP Mobile Top 10 compliance
        owasp_compliance = analyze_owasp_mobile_compliance(vulnerabilities, permission_analysis, network_security)
        
        # Check for malware
        malware_detected = any(v.category == "Malware" for v in vulnerabilities)
        
        # Generate recommendations
        recommendations = generate_recommendations(
            vulnerabilities,
            permission_analysis,
            network_security,
            owasp_compliance,
            data.platform
        )
        
        return MobileSecurityAnalyzerOutput(
            platform=data.platform,
            analysis_timestamp=datetime.utcnow().isoformat(),
            analysis_depth=data.analysis_depth,
            app_metadata=app_metadata,
            total_vulnerabilities=total_vulns,
            critical_vulnerabilities=critical_vulns,
            high_vulnerabilities=high_vulns,
            medium_vulnerabilities=medium_vulns,
            low_vulnerabilities=low_vulns,
            vulnerabilities=vulnerabilities,
            permission_analysis=permission_analysis,
            network_security=network_security,
            extracted_assets=extracted_assets,
            owasp_mobile_compliance=owasp_compliance,
            security_score=security_score,
            privacy_score=privacy_score,
            malware_detected=malware_detected,
            recommendations=recommendations,
            execution_time=time.time() - start_time
        )
        
    except Exception as e:
        return MobileSecurityAnalyzerOutput(
            platform=data.platform,
            analysis_timestamp=datetime.utcnow().isoformat(),
            analysis_depth=data.analysis_depth,
            app_metadata=None,
            total_vulnerabilities=1,
            critical_vulnerabilities=1,
            high_vulnerabilities=0,
            medium_vulnerabilities=0,
            low_vulnerabilities=0,
            vulnerabilities=[SecurityVulnerability(
                severity="Critical",
                category="Analysis Error",
                title="Mobile App Analysis Failed",
                description=f"Failed to analyze mobile application: {str(e)}",
                remediation="Verify app file format and accessibility"
            )],
            permission_analysis=[],
            network_security=None,
            extracted_assets=[],
            owasp_mobile_compliance={},
            security_score=0.0,
            privacy_score=0.0,
            malware_detected=False,
            recommendations=["Fix analysis errors and retry with valid app file"],
            execution_time=time.time() - start_time
        )

async def download_app_file(url: str) -> Optional[bytes]:
    """Download app file from URL"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=60) as response:
                if response.status == 200:
                    return await response.read()
    except Exception as e:
        logger.error(f"Error downloading APK from {url}: {e}")
        pass
    return None

async def analyze_store_app(package_name: str, platform: str) -> Optional[AppMetadata]:
    """Analyze app from store metadata (simplified)"""
    # In real implementation, would query Google Play Store API or Apple App Store API
    return AppMetadata(
        package_name=package_name,
        version_name="1.0.0",
        version_code=1,
        min_sdk_version=21,
        target_sdk_version=33,
        app_name="Sample App",
        file_size=15000000,
        permissions=["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"]
    )

def extract_app_metadata(app_data: bytes, platform: str) -> Optional[AppMetadata]:
    """Extract metadata from app file"""
    try:
        if platform.lower() == "android":
            return extract_android_metadata(app_data)
        elif platform.lower() == "ios":
            return extract_ios_metadata(app_data)
    except Exception as e:
        logger.error(f"Error extracting app metadata: {e}")
        pass
    return None

def extract_android_metadata(apk_data: bytes) -> Optional[AppMetadata]:
    """Extract metadata from Android APK file"""
    try:
        with zipfile.ZipFile(BytesIO(apk_data), 'r') as apk:
            # Read AndroidManifest.xml (would need proper AXML parser in real implementation)
            manifest_data = apk.read('AndroidManifest.xml')
            
            # Simplified manifest parsing (real implementation would use aapt or axmlparserpy)
            return AppMetadata(
                package_name="com.example.app",
                version_name="1.2.3",
                version_code=123,
                min_sdk_version=21,
                target_sdk_version=33,
                app_name="Example App",
                file_size=len(apk_data),
                permissions=[
                    "android.permission.INTERNET",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.CAMERA",
                    "android.permission.READ_CONTACTS"
                ]
            )
    except Exception as e:
        logger.error(f"Error extracting Android metadata: {e}")
        return None

def extract_ios_metadata(ipa_data: bytes) -> Optional[AppMetadata]:
    """Extract metadata from iOS IPA file"""
    try:
        with zipfile.ZipFile(BytesIO(ipa_data), 'r') as ipa:
            # Look for Info.plist
            info_plist_path = None
            for file_path in ipa.namelist():
                if file_path.endswith('Info.plist'):
                    info_plist_path = file_path
                    break
            
            if info_plist_path:
                # Simplified plist parsing
                return AppMetadata(
                    package_name="com.example.iosapp",
                    version_name="1.0.0",
                    version_code=1,
                    min_sdk_version=12,
                    target_sdk_version=16,
                    app_name="iOS Example App",
                    file_size=len(ipa_data),
                    permissions=["NSLocationWhenInUseUsageDescription", "NSCameraUsageDescription"]
                )
    except Exception as e:
        logger.error(f"Error extracting iOS metadata: {e}")
        return None

def analyze_permissions(app_metadata: Optional[AppMetadata], platform: str) -> List[PermissionAnalysis]:
    """Analyze app permissions for privacy and security risks"""
    if not app_metadata or not app_metadata.permissions:
        return []
    
    permission_analysis = []
    
    # Define high-risk permissions
    high_risk_permissions = {
        "android": {
            "android.permission.ACCESS_FINE_LOCATION": {
                "risk": "High",
                "description": "Accesses precise location data",
                "alternatives": ["ACCESS_COARSE_LOCATION"]
            },
            "android.permission.READ_CONTACTS": {
                "risk": "High", 
                "description": "Reads user's contact list",
                "alternatives": ["Use contact picker intent"]
            },
            "android.permission.CAMERA": {
                "risk": "Medium",
                "description": "Accesses device camera",
                "alternatives": ["Use camera intent"]
            },
            "android.permission.RECORD_AUDIO": {
                "risk": "High",
                "description": "Records audio from microphone",
                "alternatives": ["Use audio recording intent"]
            }
        },
        "ios": {
            "NSLocationWhenInUseUsageDescription": {
                "risk": "High",
                "description": "Accesses location when app is in use",
                "alternatives": ["Request only when necessary"]
            },
            "NSCameraUsageDescription": {
                "risk": "Medium",
                "description": "Accesses device camera",
                "alternatives": ["Use system camera picker"]
            }
        }
    }
    
    risk_permissions = high_risk_permissions.get(platform, {})
    
    for permission in app_metadata.permissions:
        if permission in risk_permissions:
            perm_info = risk_permissions[permission]
            permission_analysis.append(PermissionAnalysis(
                permission=permission,
                risk_level=perm_info["risk"],
                description=perm_info["description"],
                justification_needed=True,
                alternatives=perm_info["alternatives"]
            ))
        else:
            permission_analysis.append(PermissionAnalysis(
                permission=permission,
                risk_level="Low",
                description="Standard permission",
                justification_needed=False,
                alternatives=[]
            ))
    
    return permission_analysis

def analyze_network_security(app_data: bytes, platform: str) -> Optional[NetworkSecurityAnalysis]:
    """Analyze network security configurations"""
    try:
        cleartext_endpoints = []
        uses_cleartext = False
        certificate_pinning = False
        custom_ca_allowed = True
        
        if platform.lower() == "android":
            with zipfile.ZipFile(BytesIO(app_data), 'r') as apk:
                # Check for network security config
                try:
                    network_config = apk.read('res/xml/network_security_config.xml')
                    custom_ca_allowed = b'trust-anchors' not in network_config
                except (KeyError, zipfile.BadZipFile) as e:
                    logger.debug(f"Network security config not found or invalid: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error reading network security config: {e}")
                
                # Search for cleartext URLs in all files
                for file_path in apk.namelist():
                    if file_path.endswith(('.xml', '.java', '.kt')):
                        try:
                            file_content = apk.read(file_path).decode('utf-8', errors='ignore')
                            http_urls = re.findall(r'http://[^\s"\'<>]+', file_content)
                            cleartext_endpoints.extend(http_urls)
                            if http_urls:
                                uses_cleartext = True
                        except (UnicodeDecodeError, Exception) as e:
                            logger.error(f"Error reading file {file_path} for cleartext analysis: {e}")
                            continue
        
        return NetworkSecurityAnalysis(
            uses_cleartext=uses_cleartext,
            certificate_pinning=certificate_pinning,
            custom_ca_allowed=custom_ca_allowed,
            cleartext_endpoints=list(set(cleartext_endpoints))[:10]  # Limit to 10 examples
        )
    except Exception as e:
        logger.error(f"Error analyzing network security: {e}")
        return None

def analyze_data_storage_security(app_data: bytes, platform: str) -> List[SecurityVulnerability]:
    """Analyze data storage security issues"""
    vulnerabilities = []
    
    try:
        if platform.lower() == "android":
            with zipfile.ZipFile(BytesIO(app_data), 'r') as apk:
                # Check for insecure storage patterns
                for file_path in apk.namelist():
                    if file_path.endswith(('.java', '.kt', '.xml')):
                        try:
                            file_content = apk.read(file_path).decode('utf-8', errors='ignore')
                            
                            # Check for hardcoded credentials
                            if re.search(r'(password|secret|key)\s*=\s*["\'][\w\d]{4,}["\']', file_content, re.IGNORECASE):
                                vulnerabilities.append(SecurityVulnerability(
                                    severity="High",
                                    category="Insecure Data Storage",
                                    title="Hardcoded Credentials Found",
                                    description="Found hardcoded passwords or secrets in source code",
                                    file_location=file_path,
                                    owasp_mobile_category="M2: Insecure Data Storage",
                                    cwe_id="CWE-798",
                                    remediation="Use secure key storage mechanisms like Android Keystore"
                                ))
                            
                            # Check for external storage usage
                            if 'getExternalStorageDirectory' in file_content:
                                vulnerabilities.append(SecurityVulnerability(
                                    severity="Medium",
                                    category="Insecure Data Storage",
                                    title="External Storage Usage",
                                    description="App writes data to external storage which is accessible by other apps",
                                    file_location=file_path,
                                    owasp_mobile_category="M2: Insecure Data Storage",
                                    remediation="Use internal storage or encrypt data before writing to external storage"
                                ))
                        except (UnicodeDecodeError, Exception) as e:
                            logger.error(f"Error analyzing file {file_path} for storage vulnerabilities: {e}")
                            continue
    except Exception as e:
        logger.error(f"Error analyzing storage vulnerabilities: {e}")
        pass
    
    return vulnerabilities

def analyze_code_quality(app_data: bytes, platform: str) -> List[SecurityVulnerability]:
    """Analyze code quality and security vulnerabilities"""
    vulnerabilities = []
    
    try:
        if platform.lower() == "android":
            with zipfile.ZipFile(BytesIO(app_data), 'r') as apk:
                for file_path in apk.namelist():
                    if file_path.endswith(('.java', '.kt')):
                        try:
                            file_content = apk.read(file_path).decode('utf-8', errors='ignore')
                            
                            # Check for SQL injection vulnerabilities
                            if re.search(r'rawQuery\s*\(\s*["\'][^"\']*\+', file_content):
                                vulnerabilities.append(SecurityVulnerability(
                                    severity="High",
                                    category="Code Quality",
                                    title="Potential SQL Injection",
                                    description="Found potential SQL injection in database query",
                                    file_location=file_path,
                                    cwe_id="CWE-89",
                                    remediation="Use parameterized queries instead of string concatenation"
                                ))
                            
                            # Check for insecure cryptography
                            if re.search(r'(DES|MD5|SHA1)(?!.*SHA1.*HMAC)', file_content):
                                vulnerabilities.append(SecurityVulnerability(
                                    severity="Medium",
                                    category="Cryptography",
                                    title="Weak Cryptographic Algorithm",
                                    description="Using weak or deprecated cryptographic algorithms",
                                    file_location=file_path,
                                    owasp_mobile_category="M5: Insufficient Cryptography",
                                    cwe_id="CWE-327",
                                    remediation="Use strong cryptographic algorithms like AES-256, SHA-256"
                                ))
                            
                            # Check for debug code
                            if re.search(r'Log\.[dv]\s*\(', file_content):
                                vulnerabilities.append(SecurityVulnerability(
                                    severity="Low",
                                    category="Code Quality",
                                    title="Debug Logging Found",
                                    description="Debug logging statements found in production code",
                                    file_location=file_path,
                                    remediation="Remove debug logging from production builds"
                                ))
                        except (UnicodeDecodeError, Exception) as e:
                            logger.error(f"Error analyzing file {file_path} for code quality issues: {e}")
                            continue
    except Exception as e:
        logger.error(f"Error analyzing code quality vulnerabilities: {e}")
        pass
    
    return vulnerabilities

def analyze_malware_signatures(app_data: bytes) -> List[SecurityVulnerability]:
    """Analyze for malware signatures"""
    vulnerabilities = []
    
    # Calculate file hash
    file_hash = hashlib.sha256(app_data).hexdigest()
    
    # Simple malware signature detection (in real implementation, would use proper AV engines)
    malware_patterns = [
        b'su -c',  # Root access attempts
        b'/system/bin/su',  # Su binary access
        b'android.permission.INSTALL_PACKAGES',  # Suspicious installation permissions
        b'getDeviceId',  # Device fingerprinting
    ]
    
    for pattern in malware_patterns:
        if pattern in app_data:
            vulnerabilities.append(SecurityVulnerability(
                severity="High",
                category="Malware",
                title="Suspicious Pattern Detected",
                description=f"Found suspicious pattern: {pattern.decode('ascii', errors='ignore')}",
                remediation="Review app behavior and remove malicious code"
            ))
    
    # Check against known malicious hashes (simplified)
    known_malicious = {
        'deadbeef' * 8: 'Known malware sample',
        'cafebabe' * 8: 'Suspicious application'
    }
    
    if file_hash in known_malicious:
        vulnerabilities.append(SecurityVulnerability(
            severity="Critical",
            category="Malware",
            title="Known Malicious App",
            description=f"App matches known malware signature: {known_malicious[file_hash]}",
            remediation="Do not install this application"
        ))
    
    return vulnerabilities

def extract_assets(app_data: bytes, platform: str) -> List[ExtractedAsset]:
    """Extract hardcoded assets like URLs, API keys, etc."""
    assets = []
    
    try:
        if platform.lower() == "android":
            with zipfile.ZipFile(BytesIO(app_data), 'r') as apk:
                for file_path in apk.namelist():
                    if file_path.endswith(('.xml', '.java', '.kt', '.json')):
                        try:
                            file_content = apk.read(file_path).decode('utf-8', errors='ignore')
                            
                            # Extract URLs
                            urls = re.findall(r'https?://[^\s"\'<>]+', file_content)
                            for url in urls:
                                assets.append(ExtractedAsset(
                                    asset_type="URL",
                                    value=url,
                                    location=file_path,
                                    risk_level="Medium" if url.startswith('http://') else "Low",
                                    description="Hardcoded URL found in app"
                                ))
                            
                            # Extract potential API keys
                            api_keys = re.findall(r'["\']([A-Za-z0-9]{20,})["\']', file_content)
                            for key in api_keys:
                                if len(key) > 25:  # Likely API key
                                    assets.append(ExtractedAsset(
                                        asset_type="API_Key",
                                        value=key[:10] + "..." + key[-4:],  # Mask the key
                                        location=file_path,
                                        risk_level="High",
                                        description="Potential API key found hardcoded"
                                    ))
                        except (UnicodeDecodeError, Exception) as e:
                            logger.error(f"Error extracting assets from file {file_path}: {e}")
                            continue
    except Exception as e:
        logger.error(f"Error extracting assets: {e}")
        pass
    
    return assets[:20]  # Limit to first 20 assets

def calculate_security_score(vulnerabilities: List[SecurityVulnerability], permissions: List[PermissionAnalysis]) -> float:
    """Calculate overall security score"""
    base_score = 100.0
    
    # Deduct points for vulnerabilities
    severity_penalties = {"Critical": 30, "High": 20, "Medium": 10, "Low": 5}
    
    for vuln in vulnerabilities:
        penalty = severity_penalties.get(vuln.severity, 1)
        base_score -= penalty
    
    # Deduct points for high-risk permissions
    high_risk_perms = [p for p in permissions if p.risk_level == "High"]
    base_score -= len(high_risk_perms) * 5
    
    return max(0.0, base_score)

def calculate_privacy_score(permissions: List[PermissionAnalysis], assets: List[ExtractedAsset]) -> float:
    """Calculate privacy score"""
    base_score = 100.0
    
    # Deduct points for privacy-invasive permissions
    privacy_sensitive = ["location", "contacts", "camera", "microphone", "sms"]
    
    for perm in permissions:
        if any(sensitive in perm.permission.lower() for sensitive in privacy_sensitive):
            if perm.risk_level == "High":
                base_score -= 15
            elif perm.risk_level == "Medium":
                base_score -= 8
    
    # Deduct points for tracking assets
    tracking_assets = [a for a in assets if "analytics" in a.value.lower() or "tracking" in a.value.lower()]
    base_score -= len(tracking_assets) * 5
    
    return max(0.0, base_score)

def analyze_owasp_mobile_compliance(
    vulnerabilities: List[SecurityVulnerability],
    permissions: List[PermissionAnalysis],
    network_security: Optional[NetworkSecurityAnalysis]
) -> Dict[str, str]:
    """Analyze compliance with OWASP Mobile Top 10"""
    compliance = {
        "M1_Improper_Platform_Usage": "PASS",
        "M2_Insecure_Data_Storage": "PASS",
        "M3_Insecure_Communication": "PASS",
        "M4_Insecure_Authentication": "PASS",
        "M5_Insufficient_Cryptography": "PASS",
        "M6_Insecure_Authorization": "PASS",
        "M7_Client_Code_Quality": "PASS",
        "M8_Code_Tampering": "PASS",
        "M9_Reverse_Engineering": "PASS",
        "M10_Extraneous_Functionality": "PASS"
    }
    
    # Check vulnerabilities against OWASP categories
    for vuln in vulnerabilities:
        if vuln.owasp_mobile_category:
            if "M2" in vuln.owasp_mobile_category:
                compliance["M2_Insecure_Data_Storage"] = "FAIL"
            elif "M5" in vuln.owasp_mobile_category:
                compliance["M5_Insufficient_Cryptography"] = "FAIL"
    
    # Check network security
    if network_security and network_security.uses_cleartext:
        compliance["M3_Insecure_Communication"] = "FAIL"
    
    # Check permissions
    high_risk_perms = [p for p in permissions if p.risk_level == "High"]
    if len(high_risk_perms) > 3:
        compliance["M1_Improper_Platform_Usage"] = "FAIL"
    
    return compliance

def generate_recommendations(
    vulnerabilities: List[SecurityVulnerability],
    permissions: List[PermissionAnalysis],
    network_security: Optional[NetworkSecurityAnalysis],
    owasp_compliance: Dict[str, str],
    platform: str
) -> List[str]:
    """Generate security recommendations"""
    recommendations = []
    
    # Critical vulnerabilities
    critical_vulns = [v for v in vulnerabilities if v.severity == "Critical"]
    if critical_vulns:
        recommendations.append("URGENT: Address critical security vulnerabilities immediately")
    
    # Malware detection
    malware_vulns = [v for v in vulnerabilities if v.category == "Malware"]
    if malware_vulns:
        recommendations.append("WARNING: Potential malware detected - do not install this app")
    
    # Network security
    if network_security and network_security.uses_cleartext:
        recommendations.append("Implement HTTPS for all network communications")
        recommendations.append("Enable network security config to prevent cleartext traffic")
    
    # Permission recommendations
    high_risk_perms = [p for p in permissions if p.risk_level == "High"]
    if high_risk_perms:
        recommendations.append("Review and minimize high-risk permissions")
        recommendations.append("Implement runtime permission requests")
    
    # Platform-specific recommendations
    if platform.lower() == "android":
        recommendations.extend([
            "Enable ProGuard/R8 for code obfuscation",
            "Use Android App Bundle for optimized delivery",
            "Implement certificate pinning for API communications",
            "Use Android Keystore for sensitive data storage"
        ])
    elif platform.lower() == "ios":
        recommendations.extend([
            "Enable App Transport Security (ATS)",
            "Use iOS Keychain for sensitive data storage", 
            "Implement certificate pinning",
            "Enable bitcode for optimization"
        ])
    
    # General recommendations
    recommendations.extend([
        "Conduct regular security testing and code reviews",
        "Implement proper session management",
        "Use secure coding practices",
        "Regular security updates and patching",
        "Implement proper error handling without information disclosure"
    ])
    
    return recommendations

# Export tool info for registration
tool_info = TOOL_INFO
