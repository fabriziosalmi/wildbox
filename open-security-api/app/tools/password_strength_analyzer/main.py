"""
Password Strength Analyzer Tool

This tool analyzes password strength, checks for common patterns,
and provides security recommendations.
"""

import re
import math
import secrets
import string
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import hashlib

try:
    from .schemas import PasswordStrengthInput, PasswordStrengthOutput, PasswordAnalysis, PasswordRecommendations
except ImportError:
    from schemas import PasswordStrengthInput, PasswordStrengthOutput, PasswordAnalysis, PasswordRecommendations

# Configure logging
logger = logging.getLogger(__name__)


class PasswordStrengthAnalyzer:
    """Password strength analyzer with comprehensive security assessment"""
    
    # Common weak passwords (subset for demo)
    COMMON_PASSWORDS = {
        "password", "123456", "password123", "admin", "qwerty", "letmein",
        "welcome", "monkey", "1234567890", "abc123", "password1", "123456789",
        "welcome123", "admin123", "root", "toor", "pass", "test", "guest",
        "user", "login", "changeme", "default", "temp", "temporary"
    }
    
    # Keyboard patterns
    KEYBOARD_PATTERNS = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
        "qwerty", "asdf", "zxcv", "1234", "abcd"
    ]
    
    # Common sequences
    SEQUENCES = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "!@#$%^&*()"
    ]
    
    # Password policies
    POLICIES = {
        "nist_2017": {
            "min_length": 8,
            "max_length": 64,
            "require_uppercase": False,
            "require_lowercase": False,
            "require_digits": False,
            "require_special": False,
            "prohibit_common": True,
            "prohibit_context": True
        },
        "owasp": {
            "min_length": 10,
            "max_length": 128,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special": True,
            "prohibit_common": True,
            "prohibit_context": True
        },
        "pci_dss": {
            "min_length": 7,
            "max_length": None,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special": False,
            "prohibit_common": True,
            "prohibit_context": False
        }
    }
    
    def __init__(self):
        pass
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        
        # Count character set size
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            charset_size += 32
        if re.search(r'[\s]', password):
            charset_size += 1
        
        # Additional characters
        unique_chars = set(password)
        additional_chars = len(unique_chars) - sum([
            len([c for c in unique_chars if c.islower()]),
            len([c for c in unique_chars if c.isupper()]),
            len([c for c in unique_chars if c.isdigit()]),
            len([c for c in unique_chars if c in '!@#$%^&*()_+-=[]{};\':"\\|,.<>/?']),
            len([c for c in unique_chars if c.isspace()])
        ])
        
        if additional_chars > 0:
            charset_size += additional_chars
        
        if charset_size == 0:
            return 0.0
        
        return len(password) * math.log2(charset_size)
    
    def estimate_crack_times(self, password: str, entropy: float) -> Dict[str, str]:
        """Estimate crack times for different attack scenarios"""
        
        # Assumptions:
        # - Online attack: 1000 attempts/sec (with rate limiting)
        # - Offline attack (slow): 1 billion attempts/sec
        # - Offline attack (fast): 100 billion attempts/sec
        
        combinations = 2 ** entropy
        
        scenarios = {
            "online_throttled": combinations / (2 * 1000),  # 1000 attempts/sec, average case
            "offline_slow": combinations / (2 * 1e9),       # 1 billion attempts/sec
            "offline_fast": combinations / (2 * 1e11)       # 100 billion attempts/sec
        }
        
        def format_time(seconds):
            if seconds < 60:
                return f"{seconds:.1f} seconds"
            elif seconds < 3600:
                return f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                return f"{seconds/3600:.1f} hours"
            elif seconds < 31536000:
                return f"{seconds/86400:.1f} days"
            elif seconds < 31536000000:
                return f"{seconds/31536000:.1f} years"
            else:
                return "centuries"
        
        return {
            "online_attack": format_time(scenarios["online_throttled"]),
            "offline_slow_hash": format_time(scenarios["offline_slow"]),
            "offline_fast_hash": format_time(scenarios["offline_fast"])
        }
    
    def check_patterns(self, password: str) -> List[str]:
        """Check for common patterns in password"""
        patterns = []
        password_lower = password.lower()
        
        # Check for keyboard patterns
        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in password_lower or pattern[::-1] in password_lower:
                patterns.append(f"Keyboard pattern detected: {pattern}")
        
        # Check for sequences
        for sequence in self.SEQUENCES:
            for i in range(len(sequence) - 2):
                substring = sequence[i:i+3]
                if substring in password_lower or substring[::-1] in password_lower:
                    patterns.append(f"Character sequence detected: {substring}")
        
        # Check for repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                patterns.append(f"Repeated character pattern: {password[i]*3}")
        
        # Check for number patterns
        if re.search(r'\d{4,}', password):
            patterns.append("Sequential numbers detected")
        
        # Check for common substitutions
        substitutions = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
        }
        for char, sub in substitutions.items():
            if sub in password and char not in password.lower():
                patterns.append(f"Common substitution detected: {char} -> {sub}")
        
        return patterns
    
    def check_policy_compliance(self, password: str, policy_name: str) -> Dict[str, bool]:
        """Check compliance with specific password policy"""
        if policy_name not in self.POLICIES:
            return {}
        
        policy = self.POLICIES[policy_name]
        compliance = {}
        
        # Length requirements
        if policy.get("min_length"):
            compliance["min_length"] = len(password) >= policy["min_length"]
        if policy.get("max_length"):
            compliance["max_length"] = len(password) <= policy["max_length"]
        
        # Character requirements
        if policy.get("require_uppercase"):
            compliance["has_uppercase"] = bool(re.search(r'[A-Z]', password))
        if policy.get("require_lowercase"):
            compliance["has_lowercase"] = bool(re.search(r'[a-z]', password))
        if policy.get("require_digits"):
            compliance["has_digits"] = bool(re.search(r'\d', password))
        if policy.get("require_special"):
            compliance["has_special"] = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))
        
        # Prohibition checks
        if policy.get("prohibit_common"):
            compliance["not_common"] = password.lower() not in self.COMMON_PASSWORDS
        
        return compliance
    
    def calculate_strength_score(self, password: str, entropy: float, patterns: List[str], 
                                is_common: bool) -> tuple[float, str]:
        """Calculate overall strength score and level"""
        score = 0
        
        # Base score from entropy
        if entropy >= 60:
            score += 40
        elif entropy >= 40:
            score += 30
        elif entropy >= 25:
            score += 20
        else:
            score += entropy / 2
        
        # Length bonus
        if len(password) >= 12:
            score += 20
        elif len(password) >= 8:
            score += 10
        elif len(password) >= 6:
            score += 5
        
        # Character diversity bonus
        char_types = 0
        if re.search(r'[a-z]', password):
            char_types += 1
        if re.search(r'[A-Z]', password):
            char_types += 1
        if re.search(r'\d', password):
            char_types += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            char_types += 1
        
        score += char_types * 5
        
        # Penalties
        if is_common:
            score -= 50
        score -= len(patterns) * 5
        
        # Cap score
        score = max(0, min(100, score))
        
        # Determine level
        if score >= 90:
            level = "very strong"
        elif score >= 75:
            level = "strong"
        elif score >= 60:
            level = "good"
        elif score >= 40:
            level = "fair"
        elif score >= 20:
            level = "weak"
        else:
            level = "very weak"
        
        return score, level
    
    def generate_recommendations(self, password: str, analysis: PasswordAnalysis) -> PasswordRecommendations:
        """Generate improvement recommendations"""
        suggestions = []
        
        # Length recommendations
        if analysis.length < 12:
            suggestions.append("Increase password length to at least 12 characters")
        
        # Character diversity
        if analysis.character_sets.get("lowercase", 0) == 0:
            suggestions.append("Add lowercase letters")
        if analysis.character_sets.get("uppercase", 0) == 0:
            suggestions.append("Add uppercase letters")
        if analysis.character_sets.get("digits", 0) == 0:
            suggestions.append("Add numbers")
        if analysis.character_sets.get("special", 0) == 0:
            suggestions.append("Add special characters (!@#$%^&*)")
        
        # Pattern recommendations
        if analysis.patterns_found:
            suggestions.append("Avoid common patterns and keyboard sequences")
        
        # Common password
        if analysis.common_password_match:
            suggestions.append("Use a unique password, not a common one")
        
        # Entropy recommendation
        if analysis.entropy < 50:
            suggestions.append("Increase password complexity for better security")
        
        # Generate example strong password
        example_password = self.generate_strong_password()
        
        # Policy compliance
        policy_compliance = {
            "nist_2017": all(self.check_policy_compliance(password, "nist_2017").values()),
            "owasp": all(self.check_policy_compliance(password, "owasp").values()),
            "pci_dss": all(self.check_policy_compliance(password, "pci_dss").values())
        }
        
        return PasswordRecommendations(
            suggestions=suggestions,
            example_strong_password=example_password,
            policy_compliance=policy_compliance
        )
    
    def generate_strong_password(self, length: int = 16) -> str:
        """Generate a strong password example"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        # Ensure it has all character types
        if not re.search(r'[a-z]', password):
            password = password[:-1] + secrets.choice(string.ascii_lowercase)
        if not re.search(r'[A-Z]', password):
            password = password[:-1] + secrets.choice(string.ascii_uppercase)
        if not re.search(r'\d', password):
            password = password[:-1] + secrets.choice(string.digits)
        if not re.search(r'[!@#$%^&*]', password):
            password = password[:-1] + secrets.choice("!@#$%^&*")
        
        return password
    
    async def analyze_password(self, password: str, check_common: bool = True, 
                              check_patterns: bool = True) -> Dict[str, Any]:
        """Perform comprehensive password analysis"""
        
        # Character set analysis
        character_sets = {
            "lowercase": len([c for c in password if c.islower()]),
            "uppercase": len([c for c in password if c.isupper()]),
            "digits": len([c for c in password if c.isdigit()]),
            "special": len([c for c in password if c in '!@#$%^&*()_+-=[]{};\':"\\|,.<>/?']),
            "spaces": len([c for c in password if c.isspace()]),
            "other": len([c for c in password if not (c.isalnum() or c in '!@#$%^&*()_+-=[]{};\':"\\|,.<>/? ')])
        }
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Check for patterns
        patterns = []
        if check_patterns:
            patterns = self.check_patterns(password)
        
        # Check if common password
        common_match = None
        if check_common and password.lower() in self.COMMON_PASSWORDS:
            common_match = "Found in common password list"
        
        # Estimate crack times
        crack_times = self.estimate_crack_times(password, entropy)
        
        return {
            "character_sets": character_sets,
            "entropy": entropy,
            "patterns": patterns,
            "common_match": common_match,
            "crack_times": crack_times
        }


async def execute_tool(input_data: PasswordStrengthInput) -> PasswordStrengthOutput:
    """Execute the password strength analysis tool"""
    
    try:
        analyzer = PasswordStrengthAnalyzer()
        
        # Perform analysis
        analysis_data = await analyzer.analyze_password(
            input_data.password,
            input_data.check_common,
            input_data.check_patterns
        )
        
        # Create analysis object
        analysis = PasswordAnalysis(
            length=len(input_data.password),
            character_sets=analysis_data["character_sets"],
            entropy=analysis_data["entropy"],
            estimated_crack_time=analysis_data["crack_times"],
            patterns_found=analysis_data["patterns"],
            common_password_match=analysis_data["common_match"]
        )
        
        # Calculate strength score
        score, level = analyzer.calculate_strength_score(
            input_data.password,
            analysis.entropy,
            analysis.patterns_found,
            bool(analysis.common_password_match)
        )
        
        # Generate recommendations
        recommendations = analyzer.generate_recommendations(input_data.password, analysis)
        
        # Check policy compliance
        meets_standards = {
            "nist_2017": all(analyzer.check_policy_compliance(input_data.password, "nist_2017").values()),
            "owasp": all(analyzer.check_policy_compliance(input_data.password, "owasp").values()),
            "pci_dss": all(analyzer.check_policy_compliance(input_data.password, "pci_dss").values())
        }
        
        # Check if password is potentially compromised (simplified check)
        is_compromised = bool(analysis.common_password_match) or len(analysis.patterns_found) > 3
        
        return PasswordStrengthOutput(
            success=True,
            password_length=len(input_data.password),
            strength_score=score,
            strength_level=level,
            analysis=analysis,
            recommendations=recommendations,
            is_compromised=is_compromised,
            meets_standards=meets_standards
        )
        
    except Exception as e:
        return PasswordStrengthOutput(
            success=False,
            password_length=len(input_data.password) if input_data.password else 0,
            strength_score=0.0,
            strength_level="unknown",
            analysis=PasswordAnalysis(
                length=0,
                character_sets={},
                entropy=0.0,
                estimated_crack_time={},
                patterns_found=[],
                common_password_match=None
            ),
            recommendations=PasswordRecommendations(
                suggestions=[],
                example_strong_password="",
                policy_compliance={}
            ),
            is_compromised=False,
            meets_standards={},
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "password_strength_analyzer",
    "display_name": "Password Strength Analyzer",
    "description": "Comprehensive password strength analysis with security recommendations",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "authentication"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        # Test weak password (using example for testing only)
        weak_test_password = "example123"  # Example password for testing
        test_input = PasswordStrengthInput(
            password=weak_test_password,
            check_common=True,
            check_patterns=True
        )
        result = await execute_tool(test_input)
        print(f"Weak Password Analysis:")
        print(f"Success: {result.success}")
        print(f"Score: {result.strength_score}")
        print(f"Level: {result.strength_level}")
        print(f"Entropy: {result.analysis.entropy:.2f} bits")
        print(f"Recommendations: {len(result.recommendations.suggestions)}")
        print()
        
        # Test strong password (using example for testing only)
        strong_test_password = "ExampleStr0ng!Pass#2024"  # Example password for testing
        test_input2 = PasswordStrengthInput(
            password=strong_test_password,
            check_common=True,
            check_patterns=True
        )
        result2 = await execute_tool(test_input2)
        print(f"Strong Password Analysis:")
        print(f"Success: {result2.success}")
        print(f"Score: {result2.strength_score}")
        print(f"Level: {result2.strength_level}")
        print(f"Entropy: {result2.analysis.entropy:.2f} bits")
        print(f"NIST Compliant: {result2.meets_standards.get('nist_2017', False)}")
    
    asyncio.run(test())
