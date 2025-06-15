"""
Hash Generator Tool

This tool generates various types of cryptographic hashes with support for
salting, multiple iterations, and security analysis.
"""

import hashlib
import secrets
import base64
import time
import math
from typing import Dict, List, Any, Optional
from datetime import datetime
import hmac

try:
    from .schemas import HashGeneratorInput, HashGeneratorOutput, HashResult, HashAnalysis
except ImportError:
    from schemas import HashGeneratorInput, HashGeneratorOutput, HashResult, HashAnalysis


class HashGenerator:
    """Cryptographic Hash Generator and Analyzer"""
    
    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s,
    }
    
    # Security ratings for hash algorithms
    SECURITY_RATINGS = {
        'md5': 'weak',
        'sha1': 'weak',
        'sha224': 'acceptable',
        'sha256': 'strong',
        'sha384': 'strong',
        'sha512': 'strong',
        'blake2b': 'strong',
        'blake2s': 'strong',
    }
    
    # Collision resistance information
    COLLISION_RESISTANCE = {
        'md5': 'broken',
        'sha1': 'broken',
        'sha224': 'good',
        'sha256': 'excellent',
        'sha384': 'excellent',
        'sha512': 'excellent',
        'blake2b': 'excellent',
        'blake2s': 'excellent',
    }
    
    # Deprecated algorithms
    DEPRECATED = ['md5', 'sha1']
    
    # Recommended algorithms
    RECOMMENDED = ['sha256', 'sha512', 'blake2b', 'blake2s']
    
    def __init__(self):
        pass
    
    async def generate_hashes(self, input_text: str, hash_types: List[str],
                             include_salted: bool = False, salt: str = None,
                             iterations: int = 1, output_format: str = "hex") -> Dict[str, Any]:
        """Generate hashes for input text"""
        
        total_start_time = time.time()
        hash_results = []
        
        # Validate hash types
        valid_hash_types = [ht for ht in hash_types if ht in self.SUPPORTED_ALGORITHMS]
        invalid_hash_types = [ht for ht in hash_types if ht not in self.SUPPORTED_ALGORITHMS]
        
        if invalid_hash_types:
            raise ValueError(f"Unsupported hash types: {', '.join(invalid_hash_types)}")
        
        # Generate salt if needed
        if include_salted and not salt:
            salt = secrets.token_hex(16)
        
        # Convert input to bytes
        input_bytes = input_text.encode('utf-8')
        
        # Generate hashes
        for hash_type in valid_hash_types:
            start_time = time.time()
            
            if include_salted:
                # Generate salted hash using PBKDF2
                hash_value = self._generate_salted_hash(
                    input_bytes, salt, hash_type, iterations, output_format
                )
                result = HashResult(
                    algorithm=f"{hash_type}_pbkdf2",
                    hash_value=hash_value,
                    salt_used=salt,
                    iterations=iterations,
                    execution_time=round((time.time() - start_time) * 1000, 3)
                )
            else:
                # Generate regular hash
                hash_value = self._generate_regular_hash(
                    input_bytes, hash_type, output_format
                )
                result = HashResult(
                    algorithm=hash_type,
                    hash_value=hash_value,
                    salt_used=None,
                    iterations=None,
                    execution_time=round((time.time() - start_time) * 1000, 3)
                )
            
            hash_results.append(result)
        
        # Perform analysis
        analysis = self._analyze_hashes(input_text, valid_hash_types)
        
        total_execution_time = round((time.time() - total_start_time) * 1000, 3)
        
        return {
            'hash_results': hash_results,
            'analysis': analysis,
            'total_execution_time': total_execution_time
        }
    
    def _generate_regular_hash(self, input_bytes: bytes, hash_type: str, output_format: str) -> str:
        """Generate a regular hash"""
        hash_func = self.SUPPORTED_ALGORITHMS[hash_type]
        hash_obj = hash_func(input_bytes)
        
        if output_format == "hex":
            return hash_obj.hexdigest()
        elif output_format == "base64":
            return base64.b64encode(hash_obj.digest()).decode('utf-8')
        elif output_format == "raw":
            return hash_obj.digest().hex()  # Return hex representation of raw bytes
        else:
            return hash_obj.hexdigest()  # Default to hex
    
    def _generate_salted_hash(self, input_bytes: bytes, salt: str, hash_type: str,
                             iterations: int, output_format: str) -> str:
        """Generate a salted hash using PBKDF2"""
        salt_bytes = salt.encode('utf-8')
        
        # Use PBKDF2 with the specified hash algorithm
        if hash_type in ['sha256', 'sha384', 'sha512']:
            hash_name = hash_type.upper()
        else:
            hash_name = 'SHA256'  # Default for unsupported algorithms in PBKDF2
        
        # Generate PBKDF2 hash
        pbkdf2_hash = hashlib.pbkdf2_hmac(
            hash_name.lower().replace('sha', 'sha'),
            input_bytes,
            salt_bytes,
            iterations
        )
        
        if output_format == "hex":
            return pbkdf2_hash.hex()
        elif output_format == "base64":
            return base64.b64encode(pbkdf2_hash).decode('utf-8')
        elif output_format == "raw":
            return pbkdf2_hash.hex()
        else:
            return pbkdf2_hash.hex()
    
    def _analyze_hashes(self, input_text: str, hash_types: List[str]) -> HashAnalysis:
        """Analyze the input and hash types for security"""
        
        # Calculate input entropy
        entropy = self._calculate_entropy(input_text)
        
        # Analyze strength of each hash type
        strength_analysis = {}
        for hash_type in hash_types:
            strength_analysis[hash_type] = self.SECURITY_RATINGS.get(hash_type, 'unknown')
        
        # Get collision resistance information
        collision_resistance = {}
        for hash_type in hash_types:
            collision_resistance[hash_type] = self.COLLISION_RESISTANCE.get(hash_type, 'unknown')
        
        # Identify deprecated algorithms
        deprecated_found = [ht for ht in hash_types if ht in self.DEPRECATED]
        
        # Filter recommended algorithms
        recommended_available = [ht for ht in hash_types if ht in self.RECOMMENDED]
        
        return HashAnalysis(
            input_length=len(input_text),
            entropy=round(entropy, 2),
            strength_analysis=strength_analysis,
            collision_resistance=collision_resistance,
            recommended_algorithms=recommended_available,
            deprecated_algorithms=deprecated_found
        )
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of input text"""
        if not text:
            return 0.0
        
        # Count frequency of each character
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        
        for count in freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def generate_hash_comparison(self, hash_results: List[HashResult]) -> Dict[str, Any]:
        """Generate comparison information between different hashes"""
        
        comparison = {
            'algorithms_used': [result.algorithm for result in hash_results],
            'hash_lengths': {result.algorithm: len(result.hash_value) for result in hash_results},
            'execution_times': {result.algorithm: result.execution_time for result in hash_results},
            'fastest_algorithm': min(hash_results, key=lambda x: x.execution_time).algorithm if hash_results else None,
            'slowest_algorithm': max(hash_results, key=lambda x: x.execution_time).algorithm if hash_results else None
        }
        
        return comparison


async def execute_tool(params: HashGeneratorInput) -> HashGeneratorOutput:
    """Main entry point for the hash generator tool"""
    generator = HashGenerator()
    
    try:
        # Generate hashes
        result = await generator.generate_hashes(
            input_text=params.input_text,
            hash_types=params.hash_types,
            include_salted=params.include_salted,
            salt=params.salt,
            iterations=params.iterations,
            output_format=params.output_format
        )
        
        return HashGeneratorOutput(
            success=True,
            input_text=params.input_text,
            hash_results=result['hash_results'],
            analysis=result['analysis'],
            total_execution_time=result['total_execution_time'],
            timestamp=datetime.now(),
            error=None
        )
        
    except Exception as e:
        return HashGeneratorOutput(
            success=False,
            input_text=params.input_text,
            hash_results=[],
            analysis=HashAnalysis(
                input_length=len(params.input_text),
                entropy=0.0,
                strength_analysis={},
                collision_resistance={},
                recommended_algorithms=[],
                deprecated_algorithms=[]
            ),
            total_execution_time=0.0,
            timestamp=datetime.now(),
            error=str(e)
        )


# Tool metadata
TOOL_INFO = {
    "name": "hash_generator",
    "display_name": "Hash Generator",
    "description": "Generate and analyze various cryptographic hashes with security recommendations",
    "version": "1.0.0",
    "author": "Wildbox Security Team",
    "category": "cryptography"
}


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        test_input = HashGeneratorInput(
            input_text="Hello, World!",
            hash_types=["md5", "sha256", "sha512"],
            include_salted=True,
            iterations=1000
        )
        result = await execute_tool(test_input)
        print(f"Success: {result.success}")
        if result.success:
            for hash_result in result.hash_results:
                print(f"{hash_result.algorithm}: {hash_result.hash_value}")
            print(f"Input Entropy: {result.analysis.entropy}")
            print(f"Deprecated Algorithms: {result.analysis.deprecated_algorithms}")
        else:
            print(f"Error: {result.error}")
    
    asyncio.run(test())
