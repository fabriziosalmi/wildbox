#!/bin/bash

# Security Setup Script for Open Security API
# This script sets up security components gradually without breaking existing functionality

set -e

echo "🔐 Setting up Security Components for Open Security API"
echo "======================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root for system-wide setup
if [[ $EUID -eq 0 ]]; then
    SECURITY_DIR="/etc/security"
    print_warning "Running as root - will create system-wide security configuration"
else
    SECURITY_DIR="$HOME/.config/wildbox-security"
    print_status "Running as user - will create user-specific security configuration"
fi

# Create security configuration directory
print_step "Creating security configuration directory: $SECURITY_DIR"
mkdir -p "$SECURITY_DIR"

# Step 1: Create basic environment file if it doesn't exist
print_step "Setting up environment configuration"
if [ ! -f ".env" ]; then
    cp .env.template .env
    print_status "Created .env file from template"
    print_warning "Please edit .env file and set appropriate values"
else
    print_status ".env file already exists"
fi

# Step 2: Generate encryption key if needed
print_step "Generating encryption key"
if ! grep -q "ENCRYPTION_KEY=" .env || grep -q "your-32-byte-encryption-key-here" .env; then
    ENCRYPTION_KEY=$(openssl rand -hex 32)
    sed -i.bak "s/ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$ENCRYPTION_KEY/" .env
    print_status "Generated new encryption key"
else
    print_status "Encryption key already configured"
fi

# Step 3: Generate JWT secret if needed
print_step "Checking JWT secret key"
if grep -q "your-super-secret-jwt-key-here-change-this" .env; then
    JWT_SECRET=$(openssl rand -hex 32)
    sed -i.bak "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET/" .env
    print_status "Generated new JWT secret key"
else
    print_status "JWT secret key already configured"
fi

# Step 4: Create authorized targets configuration
print_step "Creating authorized targets configuration"
cat > "$SECURITY_DIR/authorized_targets.json" << 'EOF'
{
    "targets": [
        "https://httpbin.org",
        "https://jsonplaceholder.typicode.com",
        "127.0.0.1",
        "localhost"
    ],
    "description": "List of authorized targets for security testing",
    "notes": [
        "Only add targets you own or have explicit permission to test",
        "Use full URLs for web targets",
        "Use CIDR notation for IP ranges (e.g., 192.168.1.0/24)",
        "Use .domain.com format for wildcard domains"
    ]
}
EOF
print_status "Created authorized targets configuration"

# Step 5: Create user permissions configuration
print_step "Creating user permissions configuration"
cat > "$SECURITY_DIR/user_permissions.json" << 'EOF'
{
    "default_admin": [
        "read_only",
        "passive_scan",
        "active_scan"
    ],
    "security_analyst": [
        "read_only",
        "passive_scan"
    ],
    "description": "User permissions for different operation types",
    "operation_types": {
        "read_only": "Information gathering without active probing",
        "passive_scan": "Non-intrusive scanning and analysis",
        "active_scan": "Active network and service scanning",
        "destructive_test": "Potentially destructive security tests (admin only)",
        "credential_test": "Authentication and credential testing (admin only)",
        "vulnerability_exploit": "Exploit testing (highest risk, admin only)"
    }
}
EOF
print_status "Created user permissions configuration"

# Step 6: Create minimal IoT credentials file
print_step "Creating IoT default credentials configuration"
cat > "$SECURITY_DIR/iot_default_creds.json" << 'EOF'
[
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": ""},
    {"username": "root", "password": "root"}
]
EOF
print_status "Created IoT default credentials configuration"

# Step 7: Create JWT secrets file
print_step "Creating JWT secrets wordlist"
cat > "$SECURITY_DIR/jwt_secrets.txt" << 'EOF'
secret
password
test
key
EOF
print_status "Created JWT secrets wordlist"

# Step 8: Update environment with security paths
print_step "Updating environment configuration"
{
    echo ""
    echo "# Security Configuration Paths"
    echo "AUTHORIZED_TARGETS_FILE=$SECURITY_DIR/authorized_targets.json"
    echo "USER_PERMISSIONS_FILE=$SECURITY_DIR/user_permissions.json"
    echo "IOT_DEFAULT_CREDS_FILE=$SECURITY_DIR/iot_default_creds.json"
    echo "JWT_SECRETS_FILE=$SECURITY_DIR/jwt_secrets.txt"
} >> .env

print_status "Updated .env with security configuration paths"

# Step 9: Set appropriate permissions
print_step "Setting secure file permissions"
chmod 600 "$SECURITY_DIR"/*.json 2>/dev/null || true
chmod 600 "$SECURITY_DIR"/*.txt 2>/dev/null || true
chmod 700 "$SECURITY_DIR"
chmod 600 .env

print_status "Set secure file permissions"

# Step 10: Create a test configuration for gradual rollout
print_step "Setting up gradual security rollout"
echo ""
echo "SECURITY_CONTROLS_ENABLED=false" >> .env
echo "SECURITY_STRICT_MODE=false" >> .env
print_status "Security controls are DISABLED by default"

print_warning "To enable security controls, edit .env and set:"
print_warning "  SECURITY_CONTROLS_ENABLED=true"
print_warning "  SECURITY_STRICT_MODE=true (for strict enforcement)"

echo ""
print_status "Security setup completed successfully!"
echo ""
echo "📋 Next Steps:"
echo "1. Review and edit .env file with your specific configuration"
echo "2. Review security configurations in: $SECURITY_DIR"
echo "3. Add your authorized targets to: $SECURITY_DIR/authorized_targets.json"
echo "4. Configure user permissions in: $SECURITY_DIR/user_permissions.json"
echo "5. Test the application: python -m uvicorn app.main:app --reload"
echo "6. Enable security controls when ready by setting SECURITY_CONTROLS_ENABLED=true in .env"
echo ""
print_warning "⚠️  Security controls are currently DISABLED for backward compatibility"
print_warning "   Enable them gradually after testing your existing workflows"
echo ""
