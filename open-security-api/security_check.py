#!/usr/bin/env python3
"""
Security configuration validation script for Wildbox Security API.
Run this script before deploying to production to check for security issues.
"""

import os
import sys
import re
import secrets
from pathlib import Path
from typing import List, Tuple


class SecurityValidator:
    """Validates security configuration and settings."""
    
    def __init__(self):
        self.warnings = []
        self.errors = []
        self.info = []
    
    def validate_env_file(self, env_path: str = ".env") -> bool:
        """Validate environment configuration file."""
        if not os.path.exists(env_path):
            self.errors.append(f"Environment file {env_path} not found")
            return False
        
        with open(env_path, 'r') as f:
            content = f.read()
        
        # Check for API key configuration
        if "API_KEY=" not in content:
            self.errors.append("API_KEY not configured in environment file")
        elif 'API_KEY="your-secure-api-key-here' in content:
            self.errors.append("API_KEY is not set (still using placeholder)")
        elif 'API_KEY="wildbox-security-api-key-2025"' in content:
            self.errors.append("Using default API key - CRITICAL security issue!")
        else:
            # Extract and validate API key
            api_key_match = re.search(r'API_KEY="([^"]*)"', content)
            if api_key_match:
                api_key = api_key_match.group(1)
                self._validate_api_key(api_key)
        
        # Check debug mode
        if 'DEBUG=true' in content:
            self.warnings.append("Debug mode is enabled - disable for production")
        
        # Check CORS configuration
        if '"*"' in content and 'CORS_ORIGINS' in content:
            self.warnings.append("CORS allows all origins (*) - restrict for production")
        
        # Check environment setting
        if 'ENVIRONMENT="development"' in content:
            self.info.append("Environment is set to development")
        elif 'ENVIRONMENT="production"' in content:
            self.info.append("Environment is set to production")
        
        return len(self.errors) == 0
    
    def _validate_api_key(self, api_key: str) -> None:
        """Validate API key strength."""
        if len(api_key) < 32:
            self.warnings.append(f"API key is too short ({len(api_key)} chars, recommended: 32+)")
        
        # Check for weak patterns
        weak_patterns = [
            'password', 'secret', 'key', 'admin', 'test', 'demo', 
            '123', 'abc', 'default', 'wildbox', 'api-key'
        ]
        
        api_key_lower = api_key.lower()
        for pattern in weak_patterns:
            if pattern in api_key_lower:
                self.warnings.append(f"API key contains weak pattern: {pattern}")
        
        # Check entropy
        unique_chars = len(set(api_key))
        if unique_chars < 16:
            self.warnings.append(f"API key has low entropy ({unique_chars} unique chars)")
    
    def validate_file_permissions(self) -> None:
        """Check file permissions for sensitive files."""
        sensitive_files = ['.env', 'app/config.py']
        
        for file_path in sensitive_files:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                mode = oct(stat.st_mode)[-3:]
                
                # Check if file is readable by others
                if mode.endswith('4') or mode.endswith('5') or mode.endswith('6') or mode.endswith('7'):
                    self.warnings.append(f"{file_path} is readable by others (permissions: {mode})")
    
    def check_dependencies(self) -> None:
        """Check for security-related dependencies."""
        requirements_file = "requirements.txt"
        if os.path.exists(requirements_file):
            with open(requirements_file, 'r') as f:
                content = f.read()
            
            if 'defusedxml' not in content:
                self.warnings.append("defusedxml not found in requirements - needed for secure XML parsing")
            else:
                self.info.append("defusedxml found in requirements - good for XML security")
        else:
            self.warnings.append("requirements.txt not found")
    
    def validate_cors_config(self) -> None:
        """Validate CORS configuration."""
        config_file = "app/config.py"
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                content = f.read()
            
            if 'cors_origins: List[str] = Field(default=["*"]' in content:
                self.warnings.append("Default CORS configuration allows all origins")
    
    def check_production_readiness(self) -> None:
        """Check if configuration is ready for production."""
        env_vars = os.environ.copy()
        
        # Load .env file manually
        if os.path.exists('.env'):
            with open('.env', 'r') as f:
                for line in f:
                    if '=' in line and not line.strip().startswith('#'):
                        key, value = line.strip().split('=', 1)
                        env_vars[key] = value.strip('"')
        
        environment = env_vars.get('ENVIRONMENT', 'development')
        
        if environment == 'production':
            self.info.append("Running production readiness checks...")
            
            # Critical production checks
            if env_vars.get('DEBUG', 'false').lower() == 'true':
                self.errors.append("DEBUG=true in production environment!")
            
            cors_origins = env_vars.get('CORS_ORIGINS', '')
            if '*' in cors_origins:
                self.errors.append("CORS allows all origins in production!")
            
            api_key = env_vars.get('API_KEY', '')
            if not api_key or 'default' in api_key.lower() or 'test' in api_key.lower():
                self.errors.append("Weak or missing API key in production!")
    
    def generate_secure_api_key(self) -> str:
        """Generate a cryptographically secure API key."""
        return secrets.token_urlsafe(32)
    
    def print_results(self) -> None:
        """Print validation results."""
        print("🔍 Wildbox Security API - Security Configuration Validation")
        print("=" * 60)
        
        if self.errors:
            print("\n❌ ERRORS (must fix before deployment):")
            for error in self.errors:
                print(f"   • {error}")
        
        if self.warnings:
            print("\n⚠️  WARNINGS (recommended to fix):")
            for warning in self.warnings:
                print(f"   • {warning}")
        
        if self.info:
            print("\n✅ INFO:")
            for info in self.info:
                print(f"   • {info}")
        
        print(f"\n📊 Summary:")
        print(f"   Errors: {len(self.errors)}")
        print(f"   Warnings: {len(self.warnings)}")
        print(f"   Info: {len(self.info)}")
        
        if len(self.errors) == 0:
            if len(self.warnings) == 0:
                print("\n🎉 All security checks passed!")
            else:
                print("\n✅ No critical issues found, but please review warnings.")
        else:
            print("\n🚨 Critical issues found - fix before production deployment!")
            
        print("\n💡 To generate a secure API key, run:")
        print(f"   python -c \"import secrets; print('API_KEY=\"' + secrets.token_urlsafe(32) + '\"')\"")


def main():
    """Main function."""
    print("Starting security validation...")
    
    validator = SecurityValidator()
    
    # Run all validations
    validator.validate_env_file()
    validator.validate_file_permissions()
    validator.check_dependencies()
    validator.validate_cors_config()
    validator.check_production_readiness()
    
    # Print results
    validator.print_results()
    
    # Exit with error code if critical issues found
    if validator.errors:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
