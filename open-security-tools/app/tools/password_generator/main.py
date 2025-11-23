"""
Password Generator Tool

This tool generates secure passwords with customizable options and provides
strength analysis for the generated passwords.
"""

import secrets
import string
import math
import re
from typing import List, Dict, Set, Tuple

try:
    from schemas import PasswordGeneratorInput, PasswordGeneratorOutput, PasswordStrengthAnalysis
except ImportError:
    from schemas import PasswordGeneratorInput, PasswordGeneratorOutput, PasswordStrengthAnalysis


# Tool metadata
TOOL_INFO = {
    "name": "password_generator",
    "display_name": "Secure Password Generator",
    "description": "Generates secure passwords with customizable options and strength analysis",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "cryptography"
}


class PasswordGenerator:
    """Secure password generator with strength analysis"""
    
    # Default character sets
    UPPERCASE = string.ascii_uppercase
    LOWERCASE = string.ascii_lowercase
    NUMBERS = string.digits
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ambiguous characters to potentially exclude
    AMBIGUOUS = "0Ol1I"
    
    # Common weak patterns
    COMMON_PATTERNS = [
        r'(.)\1{2,}',  # Repeating characters
        r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
        r'(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)',  # Keyboard patterns
    ]
    
    def __init__(self):
        pass
    
    def generate_passwords(
        self,
        length: int,
        include_uppercase: bool,
        include_lowercase: bool,
        include_numbers: bool,
        include_symbols: bool,
        exclude_ambiguous: bool,
        custom_symbols: str = None,
        count: int = 1,
        require_all_types: bool = True
    ) -> Tuple[List[str], List[str], str]:
        """Generate secure passwords"""
        
        # Build character set
        charset = ""
        character_sets_used = []
        
        if include_uppercase:
            chars = self.UPPERCASE
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            charset += chars
            character_sets_used.append("Uppercase letters")
        
        if include_lowercase:
            chars = self.LOWERCASE
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            charset += chars
            character_sets_used.append("Lowercase letters")
        
        if include_numbers:
            chars = self.NUMBERS
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            charset += chars
            character_sets_used.append("Numbers")
        
        if include_symbols:
            chars = custom_symbols if custom_symbols else self.SYMBOLS
            charset += chars
            character_sets_used.append("Symbols")
        
        if not charset:
            raise ValueError("At least one character type must be selected")
        
        # Calculate total possible combinations
        total_combinations = str(len(charset) ** length)
        
        # Generate passwords
        passwords = []
        for _ in range(count):
            if require_all_types and sum([include_uppercase, include_lowercase, include_numbers, include_symbols]) > 1:
                password = self._generate_password_with_requirements(
                    length, charset, include_uppercase, include_lowercase,
                    include_numbers, include_symbols, exclude_ambiguous, custom_symbols
                )
            else:
                password = ''.join(secrets.choice(charset) for _ in range(length))
            
            passwords.append(password)
        
        return passwords, character_sets_used, total_combinations
    
    def _generate_password_with_requirements(
        self,
        length: int,
        charset: str,
        include_uppercase: bool,
        include_lowercase: bool,
        include_numbers: bool,
        include_symbols: bool,
        exclude_ambiguous: bool,
        custom_symbols: str = None
    ) -> str:
        """Generate password ensuring at least one character from each required type"""
        
        required_chars = []
        
        # Add at least one character from each required type
        if include_uppercase:
            chars = self.UPPERCASE
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            required_chars.append(secrets.choice(chars))
        
        if include_lowercase:
            chars = self.LOWERCASE
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            required_chars.append(secrets.choice(chars))
        
        if include_numbers:
            chars = self.NUMBERS
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            required_chars.append(secrets.choice(chars))
        
        if include_symbols:
            chars = custom_symbols if custom_symbols else self.SYMBOLS
            required_chars.append(secrets.choice(chars))
        
        # Fill the rest with random characters from the full charset
        remaining_length = length - len(required_chars)
        if remaining_length > 0:
            random_chars = [secrets.choice(charset) for _ in range(remaining_length)]
        else:
            random_chars = []
        
        # Combine and shuffle
        all_chars = required_chars + random_chars
        
        # If we have more required chars than length, just use the required ones
        if len(all_chars) > length:
            all_chars = all_chars[:length]
        
        # Shuffle the password
        for i in range(len(all_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            all_chars[i], all_chars[j] = all_chars[j], all_chars[i]
        
        return ''.join(all_chars)
    
    def analyze_password_strength(self, password: str) -> PasswordStrengthAnalysis:
        """Analyze password strength and provide feedback"""
        
        # Calculate entropy
        charset_size = self._estimate_charset_size(password)
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        
        # Base score from entropy
        score = min(100, int(entropy * 2.5))
        
        feedback = []
        
        # Length analysis
        if len(password) < 8:
            score -= 30
            feedback.append("Password is too short (minimum 8 characters recommended)")
        elif len(password) < 12:
            score -= 10
            feedback.append("Consider using a longer password (12+ characters)")
        
        # Character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        char_types = sum([has_upper, has_lower, has_digit, has_symbol])
        
        if char_types < 2:
            score -= 25
            feedback.append("Use multiple character types (uppercase, lowercase, numbers, symbols)")
        elif char_types < 3:
            score -= 10
            feedback.append("Consider adding more character types for better security")
        
        # Check for common weak patterns
        for pattern in self.COMMON_PATTERNS:
            if re.search(pattern, password.lower()):
                score -= 15
                feedback.append("Avoid common patterns and sequences")
                break
        
        # Check for repeated characters
        if len(set(password)) < len(password) * 0.7:
            score -= 10
            feedback.append("Avoid too many repeated characters")
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        
        # Determine strength level
        if score >= 90:
            strength_level = "Excellent"
        elif score >= 70:
            strength_level = "Strong"
        elif score >= 50:
            strength_level = "Good"
        elif score >= 30:
            strength_level = "Fair"
        else:
            strength_level = "Weak"
        
        # Estimate crack time
        crack_time = self._estimate_crack_time(entropy)
        
        # Add positive feedback for strong passwords
        if score >= 70:
            feedback.append("This is a strong password!")
        if len(password) >= 16:
            feedback.append("Excellent length for maximum security")
        if char_types == 4:
            feedback.append("Great character diversity")
        
        return PasswordStrengthAnalysis(
            score=score,
            strength_level=strength_level,
            entropy=round(entropy, 2),
            estimated_crack_time=crack_time,
            feedback=feedback
        )
    
    def _estimate_charset_size(self, password: str) -> int:
        """Estimate the character set size used in the password"""
        charset_size = 0
        
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(not c.isalnum() for c in password):
            # Estimate symbol count
            unique_symbols = len(set(c for c in password if not c.isalnum()))
            charset_size += min(unique_symbols * 3, 32)  # Conservative estimate
        
        return charset_size
    
    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack password based on entropy"""
        # Assume 1 billion guesses per second
        guesses_per_second = 1e9
        
        # Average case: need to try half the keyspace
        combinations = 2 ** (entropy - 1)
        seconds = combinations / guesses_per_second
        
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds/86400)} days"
        elif seconds < 31536000000:
            return f"{int(seconds/31536000)} years"
        else:
            return "Centuries"


async def execute_tool(params: PasswordGeneratorInput) -> PasswordGeneratorOutput:
    """Main entry point for the password generator tool"""
    generator = PasswordGenerator()
    
    try:
        # Generate passwords
        passwords, character_sets_used, total_combinations = generator.generate_passwords(
            length=params.length,
            include_uppercase=params.include_uppercase,
            include_lowercase=params.include_lowercase,
            include_numbers=params.include_numbers,
            include_symbols=params.include_symbols,
            exclude_ambiguous=params.exclude_ambiguous,
            custom_symbols=params.custom_symbols,
            count=params.count,
            require_all_types=params.require_all_types
        )
        
        # Analyze strength of each password
        strength_analyses = []
        for password in passwords:
            analysis = generator.analyze_password_strength(password)
            strength_analyses.append(analysis)
        
        return PasswordGeneratorOutput(
            success=True,
            passwords=passwords,
            strength_analysis=strength_analyses,
            character_sets_used=character_sets_used,
            total_possible_combinations=total_combinations,
            error=None
        )
        
    except (ValueError, KeyError, TypeError, ConnectionError, TimeoutError) as e:
        return PasswordGeneratorOutput(
            success=False,
            passwords=[],
            strength_analysis=[],
            character_sets_used=[],
            total_possible_combinations="0",
            error=str(e)
        )


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        test_input = PasswordGeneratorInput(
            length=16,
            include_uppercase=True,
            include_lowercase=True,
            include_numbers=True,
            include_symbols=True,
            count=3
        )
        result = await execute_tool(test_input)
        print(f"Success: {result.success}")
        if result.success:
            for i, password in enumerate(result.passwords):
                print(f"Password {i+1}: {password}")
                print(f"Strength: {result.strength_analysis[i].strength_level} ({result.strength_analysis[i].score}/100)")
                print(f"Entropy: {result.strength_analysis[i].entropy} bits")
                print()
        else:
            print(f"Error: {result.error}")
    
    asyncio.run(test())
