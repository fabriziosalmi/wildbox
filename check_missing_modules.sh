#!/bin/bash
# Comprehensive Missing Modules Checker for Wildbox Security Platform
# =====================================================================

set -e

echo "🔍 Wildbox Security Platform - Missing Modules Analysis"
echo "========================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_section() {
    echo -e "${BLUE}$1${NC}"
    echo "----------------------------------------"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Docker containers are running
print_section "1. Container Status Check"
if ! docker-compose ps | grep -q "Up"; then
    print_error "Docker containers are not running. Please start them first:"
    echo "cd /Users/fab/GitHub/wildbox && docker-compose up -d"
    exit 1
fi
print_success "Docker containers are running"
echo ""

# Check Python package import errors from logs
print_section "2. Python Import Errors Analysis"
echo "Checking container logs for missing Python packages..."
PYTHON_ERRORS=$(docker-compose logs 2>&1 | grep -i "no module named\|modulenotfounderror" | sort | uniq)

if [ -z "$PYTHON_ERRORS" ]; then
    print_success "No Python import errors found in recent logs"
else
    print_warning "Found Python import errors:"
    echo "$PYTHON_ERRORS" | while read line; do
        echo "  • $line"
    done
fi
echo ""

# Check specific missing packages
print_section "3. Missing Python Packages Check"

echo "Checking API service for missing packages..."
API_MISSING=""

# Check for whois package
if docker-compose exec -T api pip show python-whois > /dev/null 2>&1; then
    print_success "python-whois package is installed"
else
    print_error "python-whois package is missing (needed for digital_footprint_analyzer)"
    API_MISSING="$API_MISSING python-whois"
fi

# Check for lxml package
if docker-compose exec -T api pip show lxml > /dev/null 2>&1; then
    print_success "lxml package is installed"
else
    print_error "lxml package is missing (needed for saml_analyzer)"
    API_MISSING="$API_MISSING lxml"
fi

# Check for beautifulsoup4
if docker-compose exec -T api pip show beautifulsoup4 > /dev/null 2>&1; then
    print_success "beautifulsoup4 package is installed"
else
    print_warning "beautifulsoup4 package is missing (recommended for web scraping tools)"
    API_MISSING="$API_MISSING beautifulsoup4"
fi

# Check for dnspython
if docker-compose exec -T api pip show dnspython > /dev/null 2>&1; then
    print_success "dnspython package is installed"
else
    print_warning "dnspython package is missing (needed for DNS tools)"
    API_MISSING="$API_MISSING dnspython"
fi

echo ""

# Check CSPM missing modules
print_section "4. CSPM Service Check Modules"
echo "Analyzing CSPM service check modules..."

# Check AWS checks
AWS_CHECKS_DIR="open-security-cspm/app/checks/aws"
if [ -d "$AWS_CHECKS_DIR" ]; then
    print_success "AWS checks directory exists"
    
    # Expected AWS check files based on error logs
    EXPECTED_AWS_CHECKS=(
        "check_enabled.py"
        "check_multi_region.py" 
        "check_ebs_encryption.py"
        "check_security_groups_open_ports.py"
        "check_password_policy.py"
        "check_root_mfa_enabled.py"
        "check_unused_iam_keys.py"
        "check_key_rotation.py"
        "check_environment_encryption.py"
        "check_encryption.py"
        "check_public_access.py"
        "check_public_buckets.py"
        "check_flow_logs.py"
    )
    
    echo "Checking AWS compliance checks:"
    for check in "${EXPECTED_AWS_CHECKS[@]}"; do
        if find "$AWS_CHECKS_DIR" -name "$check" | grep -q .; then
            print_success "Found $check"
        else
            print_error "Missing $check"
        fi
    done
else
    print_error "AWS checks directory not found"
fi

# Check GCP checks
GCP_CHECKS_DIR="open-security-cspm/app/checks/gcp"
if [ -d "$GCP_CHECKS_DIR" ]; then
    print_success "GCP checks directory exists"
    EXPECTED_GCP_CHECKS=(
        "check_default_service_accounts.py"
        "check_service_account_keys.py"
        "check_public_buckets.py"
    )
    
    echo "Checking GCP compliance checks:"
    for check in "${EXPECTED_GCP_CHECKS[@]}"; do
        if find "$GCP_CHECKS_DIR" -name "$check" | grep -q .; then
            print_success "Found $check"
        else
            print_error "Missing $check"
        fi
    done
else
    print_error "GCP checks directory not found"
fi

# Check Azure checks
AZURE_CHECKS_DIR="open-security-cspm/app/checks/azure"
if [ -d "$AZURE_CHECKS_DIR" ]; then
    print_success "Azure checks directory exists"
    EXPECTED_AZURE_CHECKS=(
        "check_mfa_privileged_users.py"
        "check_public_access.py"
    )
    
    echo "Checking Azure compliance checks:"
    for check in "${EXPECTED_AZURE_CHECKS[@]}"; do
        if find "$AZURE_CHECKS_DIR" -name "$check" | grep -q .; then
            print_success "Found $check"
        else
            print_error "Missing $check"
        fi
    done
else
    print_error "Azure checks directory not found"
fi

echo ""

# Check API tool schema issues
print_section "5. API Tool Schema Issues"
echo "Checking for schema import problems..."

SCHEMA_ERRORS=$(docker-compose logs api 2>&1 | grep -i "cannot import name" | tail -10)
if [ -z "$SCHEMA_ERRORS" ]; then
    print_success "No schema import errors found"
else
    print_warning "Found schema import issues:"
    echo "$SCHEMA_ERRORS" | while read line; do
        echo "  • $line"
    done
fi

echo ""

# Check Node.js package issues (Dashboard)
print_section "6. Node.js Dependencies (Dashboard)"
if docker-compose exec -T dashboard npm list --depth=0 > /dev/null 2>&1; then
    print_success "Dashboard Node.js dependencies are satisfied"
else
    print_warning "Dashboard may have Node.js dependency issues"
    echo "You may need to run: docker-compose exec dashboard npm install"
fi

echo ""

# Generate fix recommendations
print_section "7. Fix Recommendations"

if [ ! -z "$API_MISSING" ]; then
    echo -e "${YELLOW}📦 To fix missing Python packages in API service:${NC}"
    echo "docker-compose exec api pip install$API_MISSING"
    echo ""
    echo "Or update requirements.txt and rebuild:"
    echo "echo '$API_MISSING' | tr ' ' '\n' >> open-security-api/requirements.txt"
    echo "docker-compose build api && docker-compose restart api"
    echo ""
fi

if docker-compose logs cspm 2>&1 | grep -q "Failed to load submodule"; then
    echo -e "${YELLOW}🔧 To fix CSPM missing check modules:${NC}"
    echo "The CSPM service expects check modules to be in specific locations."
    echo "You may need to:"
    echo "1. Create missing check files in the appropriate directories"
    echo "2. Update the CSPM service configuration to skip missing checks"
    echo "3. Check if the modules are in subdirectories and update imports"
    echo ""
fi

if docker-compose logs api 2>&1 | grep -q "cannot import name"; then
    echo -e "${YELLOW}⚙️  To fix schema import issues:${NC}"
    echo "1. Check tool schema files for missing class definitions"
    echo "2. Ensure all required classes are exported from schemas.py"
    echo "3. Verify tool structure follows the expected pattern"
    echo ""
fi

echo -e "${BLUE}🔄 Quick fix command:${NC}"
echo "make check-missing-modules  # Run this analysis again"
echo ""

print_section "8. Summary"
TOTAL_ISSUES=0

if [ ! -z "$API_MISSING" ]; then
    ((TOTAL_ISSUES++))
    print_error "Missing Python packages in API service"
fi

if docker-compose logs cspm 2>&1 | grep -q "Failed to load submodule"; then
    ((TOTAL_ISSUES++))
    print_error "Missing CSPM check modules"
fi

if docker-compose logs api 2>&1 | grep -q "cannot import name"; then
    ((TOTAL_ISSUES++))
    print_error "Schema import issues in API tools"
fi

if [ $TOTAL_ISSUES -eq 0 ]; then
    print_success "No critical missing module issues found!"
    echo "Your Wildbox platform appears to have all necessary modules."
else
    print_warning "Found $TOTAL_ISSUES categories of missing module issues"
    echo "See recommendations above for fixes."
fi

echo ""
echo "Analysis complete! 🎉"
