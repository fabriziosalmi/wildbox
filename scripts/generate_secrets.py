#!/usr/bin/env python3
"""
Wildbox Secret Generator

Generates cryptographically secure random values for all required secrets
in the .env file. This script creates a production-ready .env from .env.template.

Usage:
    python scripts/generate_secrets.py

    Or via Makefile:
    make generate-secrets
"""

import secrets
import string
import os
import sys
from pathlib import Path


def generate_hex(length: int = 32) -> str:
    """Generate secure random hex string"""
    return secrets.token_hex(length)


def generate_base64(length: int = 32) -> str:
    """Generate secure random URL-safe base64 string"""
    return secrets.token_urlsafe(length)


def generate_password(length: int = 24) -> str:
    """Generate strong alphanumeric password with special characters"""
    # Use a mix of letters, digits, and safe special characters
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    
    # Ensure password has at least one of each type
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*-_=+")
    ]
    
    # Fill the rest with random chars
    password += [secrets.choice(alphabet) for _ in range(length - 4)]
    
    # Shuffle to avoid predictable pattern
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)


def generate_api_key(prefix: str = "prod") -> str:
    """Generate Wildbox API key in format: wsk_<prefix>.<hex>"""
    return f"wsk_{prefix}.{generate_hex(32)}"


def main():
    """Main secret generation logic"""
    
    # Paths
    project_root = Path(__file__).parent.parent
    env_template_path = project_root / '.env.template'
    env_path = project_root / '.env'
    
    # Check if template exists
    if not env_template_path.exists():
        print(f"❌ ERROR: Template file not found: {env_template_path}")
        print("   Expected location: .env.template in project root")
        sys.exit(1)
    
    # Warn if .env already exists
    if env_path.exists():
        print(f"⚠️  WARNING: {env_path} already exists!")
        response = input("   Overwrite with new secrets? This cannot be undone! (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ Aborted. Existing .env file preserved.")
            sys.exit(0)
        
        # Backup existing .env
        backup_path = env_path.with_suffix('.env.backup')
        import shutil
        shutil.copy2(env_path, backup_path)
        print(f"✅ Backed up existing .env to {backup_path}")
    
    print("\n🔐 Generating secure random secrets...\n")
    
    # Generate all secrets
    # CodeQL[py/clear-text-storage-sensitive-data] - Intentional: This script generates secrets, must store temporarily
    secrets_map = {
        'JWT_SECRET_KEY': generate_hex(32),
        'POSTGRES_PASSWORD': generate_base64(32),
        'GATEWAY_INTERNAL_SECRET': generate_hex(32),
        'API_KEY': generate_api_key('prod'),
        'INITIAL_ADMIN_PASSWORD': generate_password(24),
        'N8N_BASIC_AUTH_PASSWORD': generate_password(16),
        'N8N_ENCRYPTION_KEY': generate_hex(32),
        'NEXTAUTH_SECRET': generate_base64(32),
        # Encrypts cloud credentials before CSPM writes them to Redis
        # (WILDBO-SEC-02). Required; the service refuses to scan without it.
        'CSPM_CREDENTIAL_KEY': generate_base64(32),
        # Keys the HMAC for stored API-key digests, kept separate from
        # JWT_SECRET_KEY so the two rotate independently (WILDBO-SEC-01).
        'API_KEY_HASH_SECRET': generate_hex(32),
        'GRAFANA_ADMIN_PASSWORD': generate_password(16),
    }
    
    # Read template
    with open(env_template_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace empty secret placeholders with generated values
    for key, value in secrets_map.items():
        # Match pattern: KEY= followed by newline (empty value)
        # This preserves commented-out lines and lines with values
        content = content.replace(f'{key}=\n', f'{key}={value}\n')
    
    # Write .env with owner-only permissions.
    #
    # This used to be a plain open(...,'w'), so the file took the process umask
    # -- typically 0644 -- and every local user could read the entire secret set,
    # including GATEWAY_INTERNAL_SECRET, the only thing preventing forged
    # identity headers (WILDBO-SEC-03). backup_postgres.sh already does this
    # correctly for its .pgpass; the generator did not.
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)
    os.chmod(env_path, 0o600)
    
    print("✅ Successfully generated .env with secure random secrets!\n")
    print("📊 Generated secrets:")
    print("   • JWT_SECRET_KEY")
    print("   • POSTGRES_PASSWORD")
    print("   • GATEWAY_INTERNAL_SECRET")
    print("   • API_KEY")
    print("   • INITIAL_ADMIN_PASSWORD")
    print("   • N8N_BASIC_AUTH_PASSWORD")
    print("   • N8N_ENCRYPTION_KEY")
    print("   • NEXTAUTH_SECRET")
    print("   • CSPM_CREDENTIAL_KEY")
    print("   • API_KEY_HASH_SECRET")
    print("   • GRAFANA_ADMIN_PASSWORD")
    
    print("\n📋 Next steps:")
    print("   1. Review .env and add any optional values (Stripe keys, OpenAI key, etc.)")
    print("   2. Run validation:  make validate-secrets")
    print("   3. Start services:  make start        (development)")
    print("                       make start-prod   (production)")
    
    print("\n🔒 Security reminders:")
    print("   • NEVER commit .env to version control")
    print("   • Store production secrets in a password manager")
    print("   • Rotate secrets regularly (every 90 days recommended)")
    print("   • Change INITIAL_ADMIN_PASSWORD after first login")
    
    print(f"\n✅ File created: {env_path}")
    print(f"   File size: {env_path.stat().st_size} bytes")
    

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Aborted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
