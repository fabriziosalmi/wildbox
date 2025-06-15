import asyncio
import time
import re
import math
import base64
import binascii
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
from collections import Counter
from schemas import (
    CryptoAnalysisRequest, CryptoStrengthResponse, AlgorithmAnalysis,
    KeyAnalysis, ImplementationAnalysis, RandomnessAnalysis
)

# Tool metadata
TOOL_INFO = {
    "name": "crypto_strength_analyzer",
    "display_name": "Cryptographic Strength Analyzer",
    "description": "Analyzes cryptographic algorithms, keys, implementations, and randomness for security strength",
    "category": "cryptography",
    "author": "Wildbox Security",
    "version": "1.0.0",
    "input_schema": CryptoAnalysisRequest.model_json_schema(),
    "output_schema": CryptoStrengthResponse.model_json_schema(),
    "requires_api_key": False,
    "rate_limit": {
        "requests_per_minute": 20,
        "requests_per_hour": 200
    }
}

class CryptoStrengthAnalyzer:
    """Cryptographic Strength Analyzer"""
    
    def __init__(self):
        # Algorithm strength database
        self.algorithm_db = {
            # Symmetric encryption
            "AES": {
                128: {"strength": "Strong", "security_level": 128, "until": "2030"},
                192: {"strength": "Very Strong", "security_level": 192, "until": "2040"},
                256: {"strength": "Very Strong", "security_level": 256, "until": "2050"}
            },
            "DES": {
                56: {"strength": "Weak", "security_level": 56, "until": "1990"}
            },
            "3DES": {
                112: {"strength": "Moderate", "security_level": 112, "until": "2025"}
            },
            
            # Asymmetric encryption
            "RSA": {
                1024: {"strength": "Weak", "security_level": 80, "until": "2010"},
                2048: {"strength": "Strong", "security_level": 112, "until": "2030"},
                3072: {"strength": "Very Strong", "security_level": 128, "until": "2040"},
                4096: {"strength": "Very Strong", "security_level": 152, "until": "2050"}
            },
            "ECC": {
                160: {"strength": "Weak", "security_level": 80, "until": "2010"},
                224: {"strength": "Strong", "security_level": 112, "until": "2030"},
                256: {"strength": "Very Strong", "security_level": 128, "until": "2040"},
                384: {"strength": "Very Strong", "security_level": 192, "until": "2050"}
            },
            
            # Hash functions
            "MD5": {
                128: {"strength": "Weak", "security_level": 64, "until": "2005"}
            },
            "SHA1": {
                160: {"strength": "Weak", "security_level": 80, "until": "2015"}
            },
            "SHA256": {
                256: {"strength": "Very Strong", "security_level": 128, "until": "2040"}
            },
            "SHA512": {
                512: {"strength": "Very Strong", "security_level": 256, "until": "2050"}
            }
        }
        
        # Weak mode patterns
        self.weak_modes = {
            "ECB": "Electronic Codebook mode is insecure for most applications",
            "CBC": "Requires proper IV handling to be secure",
            "CFB": "Requires proper IV handling to be secure",
            "OFB": "Requires proper IV handling to be secure"
        }
        
        # Implementation vulnerability patterns
        self.vuln_patterns = {
            "hardcoded_key": [
                r"key\s*=\s*['\"][a-fA-F0-9]{16,}['\"]",
                r"password\s*=\s*['\"][^'\"]{8,}['\"]",
                r"secret\s*=\s*['\"][^'\"]{8,}['\"]"
            ],
            "weak_random": [
                r"random\.random\(\)",
                r"Math\.random\(\)",
                r"rand\(\)",
                r"srand\("
            ],
            "improper_iv": [
                r"iv\s*=\s*['\"]0+['\"]",
                r"iv\s*=\s*b['\"]\\x00+['\"]",
                r"iv\s*=\s*None"
            ],
            "timing_attack": [
                r"==.*password",
                r"password.*==",
                r"if.*hash.*=="
            ]
        }
    
    def _analyze_algorithm(self, algorithm: str, key_size: Optional[int], 
                          mode: Optional[str]) -> AlgorithmAnalysis:
        """Analyze cryptographic algorithm strength"""
        algorithm_upper = algorithm.upper()
        
        # Get algorithm data
        algo_data = self.algorithm_db.get(algorithm_upper, {})
        
        if not algo_data:
            return AlgorithmAnalysis(
                algorithm=algorithm,
                key_size=key_size,
                strength_rating="Unknown",
                security_level=0,
                recommended_until=None,
                vulnerabilities=["Unknown algorithm"],
                compliance_status={"NIST": False, "FIPS": False, "OWASP": False}
            )
        
        # Find closest key size
        if key_size:
            closest_key = min(algo_data.keys(), key=lambda x: abs(x - key_size))
            strength_data = algo_data[closest_key]
        else:
            # Use default/maximum key size
            max_key = max(algo_data.keys())
            strength_data = algo_data[max_key]
            key_size = max_key
        
        # Analyze vulnerabilities
        vulnerabilities = []
        
        if algorithm_upper in ["MD5", "SHA1"]:
            vulnerabilities.append("Cryptographically broken - collision attacks possible")
        
        if algorithm_upper == "DES":
            vulnerabilities.append("Key length too short - brute force attacks feasible")
        
        if algorithm_upper == "3DES":
            vulnerabilities.append("Legacy algorithm - planned deprecation")
        
        if mode and mode.upper() in self.weak_modes:
            vulnerabilities.append(self.weak_modes[mode.upper()])
        
        # Compliance status
        compliance = {
            "NIST": strength_data["strength"] in ["Strong", "Very Strong"],
            "FIPS": algorithm_upper in ["AES", "SHA256", "SHA512", "RSA"] and 
                   strength_data["strength"] in ["Strong", "Very Strong"],
            "OWASP": strength_data["strength"] in ["Strong", "Very Strong"]
        }
        
        return AlgorithmAnalysis(
            algorithm=algorithm,
            key_size=key_size,
            strength_rating=strength_data["strength"],
            security_level=strength_data["security_level"],
            recommended_until=strength_data.get("until"),
            vulnerabilities=vulnerabilities,
            compliance_status=compliance
        )
    
    def _analyze_key(self, key_data: str, key_type: str) -> KeyAnalysis:
        """Analyze cryptographic key strength"""
        # Simulate key analysis (in reality, would parse actual key)
        key_length = len(key_data)
        
        # Estimate key size based on data length
        if "RSA" in key_type.upper():
            # RSA keys are typically much longer in PEM format
            if key_length > 3000:
                key_size = 4096
            elif key_length > 2000:
                key_size = 2048
            elif key_length > 1000:
                key_size = 1024
            else:
                key_size = 512
        elif "EC" in key_type.upper() or "ECDSA" in key_type.upper():
            # ECC keys are shorter
            if key_length > 1000:
                key_size = 384
            elif key_length > 500:
                key_size = 256
            else:
                key_size = 160
        else:
            # Symmetric key
            key_size = key_length * 4  # Rough estimate
        
        # Calculate strength score
        strength_score = min(100, max(0, (key_size - 512) // 20))
        
        # Estimate entropy (simplified)
        unique_chars = len(set(key_data))
        max_entropy = math.log2(256)  # 8 bits per byte
        entropy_estimate = (unique_chars / 256) * max_entropy
        
        # Check for weaknesses
        weakness_indicators = []
        
        if key_size < 2048 and "RSA" in key_type.upper():
            weakness_indicators.append("RSA key size below recommended 2048 bits")
        
        if key_size < 256 and "EC" in key_type.upper():
            weakness_indicators.append("ECC key size below recommended 256 bits")
        
        # Check for patterns in key
        if re.search(r"(.)\1{10,}", key_data):
            weakness_indicators.append("Repetitive patterns detected in key")
        
        if len(set(key_data)) < len(key_data) / 4:
            weakness_indicators.append("Low character diversity in key")
        
        # Factorization difficulty assessment
        if "RSA" in key_type.upper():
            if key_size >= 2048:
                factorization_difficulty = "Computationally infeasible"
            elif key_size >= 1024:
                factorization_difficulty = "Difficult but possible"
            else:
                factorization_difficulty = "Feasible with current technology"
        else:
            factorization_difficulty = None
        
        # ECC security assessment
        ecc_security = None
        if "EC" in key_type.upper():
            ecc_security = {
                "curve_strength": "Strong" if key_size >= 256 else "Weak",
                "discrete_log_difficulty": "High" if key_size >= 256 else "Low"
            }
        
        return KeyAnalysis(
            key_type=key_type,
            key_size=key_size,
            strength_score=strength_score,
            entropy_estimate=entropy_estimate,
            weakness_indicators=weakness_indicators,
            factorization_difficulty=factorization_difficulty,
            elliptic_curve_security=ecc_security
        )
    
    def _analyze_implementation(self, code: str, language: str) -> ImplementationAnalysis:
        """Analyze cryptographic implementation security"""
        security_issues = []
        violations = []
        score = 100
        
        # Check for vulnerability patterns
        for vuln_type, patterns in self.vuln_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, code, re.IGNORECASE)
                if matches:
                    issue = {
                        "type": vuln_type,
                        "description": self._get_vuln_description(vuln_type),
                        "line_count": len(matches),
                        "severity": self._get_vuln_severity(vuln_type)
                    }
                    security_issues.append(issue)
                    violations.append(f"{vuln_type}: {issue['description']}")
                    score -= self._get_vuln_penalty(vuln_type)
        
        # Language-specific checks
        if language.lower() == "python":
            if "pycrypto" in code.lower():
                violations.append("Using deprecated pycrypto library")
                score -= 15
            
            if "md5" in code.lower() and "hashlib" in code.lower():
                violations.append("Using weak MD5 hash function")
                score -= 20
        
        elif language.lower() == "javascript":
            if "crypto-js" in code.lower():
                violations.append("Using crypto-js library - consider native crypto")
                score -= 10
        
        # General security checks
        if "todo" in code.lower() or "fixme" in code.lower():
            violations.append("Code contains TODO/FIXME comments in crypto section")
            score -= 5
        
        if not re.search(r"try\s*:\s*.*except", code, re.IGNORECASE | re.DOTALL):
            violations.append("Missing proper error handling")
            score -= 10
        
        # Generate recommendations
        recommendations = []
        
        if any("hardcoded" in issue["type"] for issue in security_issues):
            recommendations.append("Use secure key management systems")
            recommendations.append("Store secrets in environment variables or key vaults")
        
        if any("weak_random" in issue["type"] for issue in security_issues):
            recommendations.append("Use cryptographically secure random number generators")
            recommendations.append("Consider os.urandom() or secrets module in Python")
        
        if any("timing" in issue["type"] for issue in security_issues):
            recommendations.append("Use constant-time comparison functions")
            recommendations.append("Implement proper authentication mechanisms")
        
        recommendations.extend([
            "Regularly update cryptographic libraries",
            "Follow secure coding best practices",
            "Implement proper input validation",
            "Use established cryptographic libraries"
        ])
        
        score = max(0, min(100, score))
        
        return ImplementationAnalysis(
            security_issues=security_issues,
            best_practices_score=score,
            vulnerability_count=len(security_issues),
            secure_coding_violations=violations,
            recommended_fixes=recommendations
        )
    
    def _analyze_randomness(self, data: str, data_format: str) -> RandomnessAnalysis:
        """Analyze randomness quality of data"""
        # Convert data to bytes
        try:
            if data_format == "hex":
                byte_data = bytes.fromhex(data)
            elif data_format == "base64":
                byte_data = base64.b64decode(data)
            else:
                byte_data = data.encode()
        except Exception:
            return RandomnessAnalysis(
                entropy_score=0.0,
                distribution_uniformity=0.0,
                statistical_tests={},
                predictability_risk="High",
                recommended_improvements=["Invalid data format"]
            )
        
        if len(byte_data) == 0:
            return RandomnessAnalysis(
                entropy_score=0.0,
                distribution_uniformity=0.0,
                statistical_tests={},
                predictability_risk="High",
                recommended_improvements=["No data provided"]
            )
        
        # Calculate entropy
        byte_counts = Counter(byte_data)
        entropy = 0.0
        
        for count in byte_counts.values():
            probability = count / len(byte_data)
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Calculate distribution uniformity
        expected_count = len(byte_data) / 256
        chi_square = sum(
            (count - expected_count) ** 2 / expected_count
            for count in byte_counts.values()
        )
        
        # Rough uniformity score (0-1)
        uniformity = max(0, 1 - (chi_square / (256 * len(byte_data))))
        
        # Statistical tests
        statistical_tests = {
            "entropy_test": {
                "passed": entropy > 7.0,
                "score": entropy,
                "threshold": 7.0
            },
            "frequency_test": {
                "passed": uniformity > 0.8,
                "score": uniformity,
                "threshold": 0.8
            },
            "runs_test": {
                "passed": self._runs_test(byte_data),
                "score": 0.85,  # Simulated
                "threshold": 0.8
            },
            "longest_run_test": {
                "passed": self._longest_run_test(byte_data),
                "score": 0.9,  # Simulated
                "threshold": 0.8
            }
        }
        
        # Assess predictability risk
        if entropy < 6.0:
            predictability_risk = "High"
        elif entropy < 7.0:
            predictability_risk = "Medium"
        else:
            predictability_risk = "Low"
        
        # Generate recommendations
        recommendations = []
        
        if entropy < 7.0:
            recommendations.append("Increase entropy by using better random sources")
        
        if uniformity < 0.8:
            recommendations.append("Improve byte distribution uniformity")
        
        if not statistical_tests["runs_test"]["passed"]:
            recommendations.append("Address runs test failure - check for patterns")
        
        recommendations.extend([
            "Use hardware random number generators when available",
            "Consider post-processing with cryptographic hash functions",
            "Regularly test randomness quality in production",
            "Monitor for entropy degradation over time"
        ])
        
        return RandomnessAnalysis(
            entropy_score=entropy,
            distribution_uniformity=uniformity,
            statistical_tests=statistical_tests,
            predictability_risk=predictability_risk,
            recommended_improvements=recommendations
        )
    
    def _runs_test(self, data: bytes) -> bool:
        """Simplified runs test for randomness"""
        # Convert to binary string
        binary = ''.join(format(byte, '08b') for byte in data)
        
        if len(binary) < 100:
            return True  # Not enough data for meaningful test
        
        # Count runs
        runs = 1
        for i in range(1, len(binary)):
            if binary[i] != binary[i-1]:
                runs += 1
        
        # Expected runs for random data
        ones = binary.count('1')
        zeros = binary.count('0')
        expected_runs = (2 * ones * zeros) / len(binary) + 1
        
        # Simple threshold check
        return abs(runs - expected_runs) < expected_runs * 0.2
    
    def _longest_run_test(self, data: bytes) -> bool:
        """Simplified longest run test"""
        binary = ''.join(format(byte, '08b') for byte in data)
        
        if len(binary) < 100:
            return True
        
        # Find longest run of consecutive bits
        max_run = 1
        current_run = 1
        
        for i in range(1, len(binary)):
            if binary[i] == binary[i-1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1
        
        # For random data, longest run shouldn't be too long
        threshold = max(20, len(binary) // 20)
        return max_run < threshold
    
    def _get_vuln_description(self, vuln_type: str) -> str:
        """Get vulnerability description"""
        descriptions = {
            "hardcoded_key": "Hardcoded cryptographic keys or secrets",
            "weak_random": "Weak random number generation",
            "improper_iv": "Improper initialization vector handling",
            "timing_attack": "Potential timing attack vulnerability"
        }
        return descriptions.get(vuln_type, "Unknown vulnerability")
    
    def _get_vuln_severity(self, vuln_type: str) -> str:
        """Get vulnerability severity"""
        severities = {
            "hardcoded_key": "Critical",
            "weak_random": "High",
            "improper_iv": "Medium",
            "timing_attack": "Medium"
        }
        return severities.get(vuln_type, "Low")
    
    def _get_vuln_penalty(self, vuln_type: str) -> int:
        """Get score penalty for vulnerability"""
        penalties = {
            "hardcoded_key": 30,
            "weak_random": 25,
            "improper_iv": 15,
            "timing_attack": 10
        }
        return penalties.get(vuln_type, 5)
    
    def _calculate_overall_rating(self, analyses: Dict) -> Tuple[str, int]:
        """Calculate overall security rating and score"""
        scores = []
        critical_issues = []
        
        if analyses.get("algorithm"):
            algo = analyses["algorithm"]
            if algo.strength_rating == "Very Strong":
                scores.append(95)
            elif algo.strength_rating == "Strong":
                scores.append(80)
            elif algo.strength_rating == "Moderate":
                scores.append(60)
            else:
                scores.append(30)
                critical_issues.append("Weak cryptographic algorithm")
        
        if analyses.get("key"):
            scores.append(analyses["key"].strength_score)
            if analyses["key"].strength_score < 50:
                critical_issues.append("Weak cryptographic key")
        
        if analyses.get("implementation"):
            scores.append(analyses["implementation"].best_practices_score)
            if analyses["implementation"].best_practices_score < 50:
                critical_issues.append("Insecure implementation")
        
        if analyses.get("randomness"):
            randomness_score = int(analyses["randomness"].entropy_score * 12.5)  # Convert to 0-100
            scores.append(randomness_score)
            if randomness_score < 50:
                critical_issues.append("Poor randomness quality")
        
        # Calculate average score
        overall_score = int(sum(scores) / len(scores)) if scores else 0
        
        # Determine rating
        if overall_score >= 90:
            rating = "Excellent"
        elif overall_score >= 75:
            rating = "Strong"
        elif overall_score >= 60:
            rating = "Moderate"
        elif overall_score >= 40:
            rating = "Weak"
        else:
            rating = "Critical"
        
        return rating, overall_score

async def execute_tool(request: CryptoAnalysisRequest) -> CryptoStrengthResponse:
    """Execute cryptographic strength analysis"""
    start_time = time.time()
    
    analyzer = CryptoStrengthAnalyzer()
    analyses = {}
    
    # Perform requested analyses
    if request.analysis_type in ["algorithm", "all"]:
        if request.algorithm_name:
            analyses["algorithm"] = analyzer._analyze_algorithm(
                request.algorithm_name, 
                request.key_size, 
                request.mode_of_operation
            )
    
    if request.analysis_type in ["key", "all"]:
        if request.public_key:
            # Determine key type from PEM header or format
            key_type = "RSA"  # Default, would need actual parsing
            if "EC" in request.public_key or "ECDSA" in request.public_key:
                key_type = "ECC"
            
            analyses["key"] = analyzer._analyze_key(request.public_key, key_type)
    
    if request.analysis_type in ["implementation", "all"]:
        if request.code_snippet:
            analyses["implementation"] = analyzer._analyze_implementation(
                request.code_snippet, 
                request.programming_language
            )
    
    if request.analysis_type in ["random", "randomness", "all"]:
        if request.random_data:
            analyses["randomness"] = analyzer._analyze_randomness(
                request.random_data, 
                request.data_format
            )
    
    # Add small delay to simulate analysis
    await asyncio.sleep(0.1)
    
    # Calculate overall assessment
    overall_rating, security_score = analyzer._calculate_overall_rating(analyses)
    
    # Compile compliance results
    compliance_results = {}
    for standard in request.compliance_standards:
        compliance_results[standard] = {}
        
        if analyses.get("algorithm"):
            compliance_results[standard]["algorithm"] = analyses["algorithm"].compliance_status.get(standard, False)
        
        if analyses.get("key"):
            compliance_results[standard]["key_strength"] = analyses["key"].strength_score > 70
        
        if analyses.get("implementation"):
            compliance_results[standard]["implementation"] = analyses["implementation"].best_practices_score > 70
    
    # Determine standards met/failed
    standards_met = []
    standards_failed = []
    
    for standard, results in compliance_results.items():
        if all(results.values()):
            standards_met.append(standard)
        else:
            standards_failed.append(standard)
    
    # Compile critical issues and recommendations
    critical_issues = []
    warnings = []
    recommendations = []
    
    if analyses.get("algorithm"):
        critical_issues.extend([v for v in analyses["algorithm"].vulnerabilities if "broken" in v.lower()])
        warnings.extend([v for v in analyses["algorithm"].vulnerabilities if "broken" not in v.lower()])
    
    if analyses.get("key"):
        warnings.extend(analyses["key"].weakness_indicators)
    
    if analyses.get("implementation"):
        critical_issues.extend([
            issue["description"] for issue in analyses["implementation"].security_issues 
            if issue["severity"] == "Critical"
        ])
        recommendations.extend(analyses["implementation"].recommended_fixes)
    
    if analyses.get("randomness"):
        if analyses["randomness"].predictability_risk == "High":
            critical_issues.append("High randomness predictability risk")
        recommendations.extend(analyses["randomness"].recommended_improvements)
    
    # General recommendations
    recommendations.extend([
        "Regularly update cryptographic libraries and algorithms",
        "Implement proper key management practices",
        "Conduct regular security audits of cryptographic implementations",
        "Follow current cryptographic best practices and standards"
    ])
    
    # Attack vectors and quantum resistance
    attack_vectors = []
    quantum_resistant = True
    
    if analyses.get("algorithm"):
        algo = analyses["algorithm"]
        if algo.algorithm.upper() in ["RSA", "ECC", "DH"]:
            attack_vectors.append("Quantum computer attacks (Shor's algorithm)")
            quantum_resistant = False
        if algo.strength_rating in ["Weak", "Moderate"]:
            attack_vectors.append("Brute force attacks")
    
    if analyses.get("key"):
        if analyses["key"].strength_score < 70:
            attack_vectors.append("Key-based attacks")
    
    # Estimate time to break
    time_to_break = None
    if analyses.get("algorithm"):
        if analyses["algorithm"].security_level >= 128:
            time_to_break = "Computationally infeasible"
        elif analyses["algorithm"].security_level >= 80:
            time_to_break = "Decades with current technology"
        else:
            time_to_break = "Feasible with current resources"
    
    processing_time = int((time.time() - start_time) * 1000)
    
    return CryptoStrengthResponse(
        analysis_type=request.analysis_type,
        overall_security_rating=overall_rating,
        security_score=security_score,
        algorithm_analysis=analyses.get("algorithm"),
        key_analysis=analyses.get("key"),
        implementation_analysis=analyses.get("implementation"),
        randomness_analysis=analyses.get("randomness"),
        compliance_results=compliance_results,
        standards_met=standards_met,
        standards_failed=standards_failed,
        critical_issues=critical_issues,
        warnings=warnings,
        recommendations=recommendations[:10],  # Limit recommendations
        attack_vectors=attack_vectors,
        time_to_break=time_to_break,
        quantum_resistance=quantum_resistant,
        analysis_confidence=0.85,  # Simulated confidence level
        timestamp=datetime.now().isoformat(),
        processing_time_ms=processing_time
    )
