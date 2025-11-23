#!/usr/bin/env python3
"""
Wildbox Secret Validator

Validates that .env file contains secure values and no insecure defaults.
This script must pass before services can start in production.

Usage:
    python scripts/validate_secrets.py

    Or via Makefile:
    make validate-secrets
    
Exit Codes:
    0 - All validations passed
    1 - Validation failed (insecure secrets detected)
"""

import os
import sys
import re
from pathlib import Path
from typing import List, Tuple


# Required secrets that MUST be present and secure
REQUIRED_SECRETS = [
    'JWT_SECRET_KEY',
    'POSTGRES_PASSWORD',
    'GATEWAY_INTERNAL_SECRET',
    'API_KEY',
    'INITIAL_ADMIN_PASSWORD',
    'NEXTAUTH_SECRET',
    'N8N_BASIC_AUTH_PASSWORD',
]

# Optional secrets (warn if missing, but don't fail)
OPTIONAL_SECRETS = [
    'STRIPE_SECRET_KEY',
    'STRIPE_PUBLISHABLE_KEY',
    'GRAFANA_ADMIN_PASSWORD',
]

# Insecure patterns (case-insensitive)
# If any secret contains these substrings, it's considered insecure
INSECURE_PATTERNS = [
    'postgres',
    'admin',
    'password',
    'secret',
    'change',
    'default',
    'test-',
    'example',
    'CHANGE-THIS',
    'INSECURE',
    'demo',
    '12345',
    'qwerty',
]

# Minimum lengths for different secret types
MIN_LENGTHS = {
    'JWT_SECRET_KEY': 32,
    'POSTGRES_PASSWORD': 16,
    'GATEWAY_INTERNAL_SECRET': 32,
    'API_KEY': 40,  # wsk_xxxx. + 64 chars
    'INITIAL_ADMIN_PASSWORD': 12,
}


def load_env_file(env_path: Path) -> dict:
    """Load .env file and return as dictionary"""
    env_vars = {}
    
    if not env_path.exists():
        return env_vars
    
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse KEY=VALUE
            if '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip()
    
    return env_vars


def validate_secret(name: str, value: str) -> Tuple[bool, List[str]]:
    """
    Validate a single secret value
    
    Returns:
        (is_valid, error_messages)
    """
    errors = []
    
    # Check if empty
    if not value:
        errors.append("Secret is empty or not set")
        return False, errors
    
    # Check minimum length
    min_length = MIN_LENGTHS.get(name, 16)
    if len(value) < min_length:
        errors.append(f"Secret is too short (minimum {min_length} characters, got {len(value)})")
    
    # Check for insecure patterns
    value_lower = value.lower()
    for pattern in INSECURE_PATTERNS:
        if pattern.lower() in value_lower:
            errors.append(f"Secret contains insecure pattern: '{pattern}'")
            break  # One pattern match is enough to flag it
    
    # Additional validation for API_KEY format
    if name == 'API_KEY' and not re.match(r'^wsk_[a-z0-9]+\.[a-f0-9]{64}$', value):
        errors.append("API key does not match expected format: wsk_<prefix>.<64-char-hex>")
    
    return len(errors) == 0, errors


def main():
    """Main validation logic"""
    
    # Paths
    project_root = Path(__file__).parent.parent
    env_path = project_root / '.env'
    
    print("🔍 Wildbox Secret Validator")
    print("=" * 60)
    
    # Check if .env exists
    if not env_path.exists():
        print(f"\n❌ FATAL: .env file not found at {env_path}")
        print("\n📋 Setup instructions:")
        print("   1. Copy template:     cp .env.template .env")
        print("   2. Generate secrets:  make generate-secrets")
        print("   3. Re-run validation: make validate-secrets")
        sys.exit(1)
    
    print(f"✅ Found .env file: {env_path}")
    print(f"   File size: {env_path.stat().st_size} bytes\n")
    
    # Load environment variables
    env_vars = load_env_file(env_path)
    print(f"📄 Loaded {len(env_vars)} environment variables\n")
    
    # Validation results
    all_errors = []
    warnings = []
    
    # Validate required secrets
    print("🔐 Validating required secrets:")
    print("-" * 60)
    
    for secret_name in REQUIRED_SECRETS:
        value = env_vars.get(secret_name, '')
        is_valid, errors = validate_secret(secret_name, value)
        
        if is_valid:
            print(f"   ✅ {secret_name:<30} SECURE")
        else:
            print(f"   ❌ {secret_name:<30} FAILED")
            for error in errors:
                print(f"      └─ {error}")
                all_errors.append(f"{secret_name}: {error}")
    
    # Check optional secrets (warnings only)
    print(f"\n📝 Checking optional secrets:")
    print("-" * 60)
    
    for secret_name in OPTIONAL_SECRETS:
        value = env_vars.get(secret_name, '')
        
        if not value:
            print(f"   ⚠️  {secret_name:<30} NOT SET (optional)")
            warnings.append(f"{secret_name} is not set (optional)")
        else:
            is_valid, errors = validate_secret(secret_name, value)
            if is_valid:
                print(f"   ✅ {secret_name:<30} SECURE")
            else:
                print(f"   ⚠️  {secret_name:<30} INSECURE (optional)")
                for error in errors:
                    warnings.append(f"{secret_name}: {error}")
    
    # Summary
    print("\n" + "=" * 60)
    
    if all_errors:
        print("\n🚨 VALIDATION FAILED!")
        print(f"   {len(all_errors)} critical error(s) found\n")
        
        print("Critical errors:")
        for error in all_errors:
            print(f"   • {error}")
        
        print("\n📋 How to fix:")
        print("   Option 1 (Recommended): Regenerate all secrets")
        print("   └─ make generate-secrets")
        print("\n   Option 2 (Manual): Edit .env and fix the errors above")
        print("   └─ Use: openssl rand -hex 32")
        print("   └─ Or:  openssl rand -base64 32")
        
        if warnings:
            print(f"\n⚠️  {len(warnings)} warning(s):")
            for warning in warnings:
                print(f"   • {warning}")
        
        sys.exit(1)
    
    else:
        print("\n✅ ALL REQUIRED SECRETS VALIDATED - SECURE TO START SERVICES")
        print(f"   • {len(REQUIRED_SECRETS)} required secrets verified")
        print(f"   • All values are cryptographically strong")
        print(f"   • No insecure patterns detected")
        
        if warnings:
            print(f"\n⚠️  {len(warnings)} non-critical warning(s):")
            for warning in warnings[:5]:  # Show first 5 warnings
                print(f"   • {warning}")
            if len(warnings) > 5:
                print(f"   ... and {len(warnings) - 5} more")
            print("\n   These warnings can be ignored for local development.")
            print("   For production, ensure all optional secrets are set.")
        
        print("\n🚀 Ready to start:")
        print("   docker-compose up -d")
        
        sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Validation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
