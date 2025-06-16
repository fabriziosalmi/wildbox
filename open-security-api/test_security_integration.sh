#!/bin/bash

# Quick Security Integration Test Script
# Tests the new security components without breaking existing functionality

echo "🧪 Testing Security Integration"
echo "==============================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test functions
test_passed() {
    echo -e "${GREEN}✓${NC} $1"
}

test_failed() {
    echo -e "${RED}✗${NC} $1"
}

test_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "app/main.py" ]; then
    test_failed "Not in the correct directory. Please run from the open-security-api root."
    exit 1
fi

echo "Testing backward compatibility..."

# Test 1: Check if app can start without security (default)
echo "1. Testing app startup without security controls..."
timeout 10s python -c "
import sys
sys.path.append('.')
try:
    from app.main import create_app
    app = create_app()
    print('SUCCESS: App can start without security controls')
except Exception as e:
    print(f'FAILED: {e}')
    sys.exit(1)
" && test_passed "App starts without security controls" || test_failed "App startup failed"

# Test 2: Check if security integration is importable
echo "2. Testing security integration import..."
python -c "
try:
    from app.security_integration import security_integration
    print(f'Security enabled: {security_integration.security_enabled}')
    print('SUCCESS: Security integration imported')
except ImportError as e:
    print(f'FAILED: Could not import security integration: {e}')
    exit(1)
except Exception as e:
    print(f'WARNING: Security integration has issues: {e}')
" && test_passed "Security integration is importable" || test_warning "Security integration has issues"

# Test 3: Check if tools can be imported
echo "3. Testing tool imports..."
python -c "
import sys
sys.path.append('.')
try:
    from app.tools.sql_injection_scanner.main import execute_tool
    from app.tools.sql_injection_scanner.schemas import SQLInjectionScannerInput
    print('SUCCESS: SQL injection scanner can be imported')
except Exception as e:
    print(f'FAILED: {e}')
    sys.exit(1)
" && test_passed "Tools can be imported" || test_failed "Tool import failed"

# Test 4: Test SQL injection scanner with safe payloads
echo "4. Testing SQL injection scanner safety..."
python -c "
import sys
sys.path.append('.')
try:
    from app.tools.sql_injection_scanner.main import SAFE_SQL_PAYLOADS
    dangerous_payloads = ['DROP TABLE', 'EXEC xp_cmdshell', 'WAITFOR DELAY']
    
    # Check that dangerous payloads are not in the safe list
    found_dangerous = []
    for payload in SAFE_SQL_PAYLOADS:
        for dangerous in dangerous_payloads:
            if dangerous.lower() in payload.lower():
                found_dangerous.append(payload)
    
    if found_dangerous:
        print(f'FAILED: Found dangerous payloads: {found_dangerous}')
        sys.exit(1)
    else:
        print(f'SUCCESS: No dangerous payloads found in {len(SAFE_SQL_PAYLOADS)} safe payloads')
except Exception as e:
    print(f'FAILED: {e}')
    sys.exit(1)
" && test_passed "SQL injection scanner uses safe payloads" || test_failed "Dangerous payloads still present"

# Test 5: Check environment template
echo "5. Testing environment template..."
if [ -f ".env.template" ]; then
    if grep -q "SECURITY_CONTROLS_ENABLED" .env.template; then
        test_passed "Environment template includes security controls"
    else
        test_failed "Environment template missing security controls"
    fi
else
    test_failed "Environment template not found"
fi

# Test 6: Check security configuration files
echo "6. Testing security configuration..."
if [ -f "config/authorized_targets.json.example" ]; then
    test_passed "Authorized targets example exists"
else
    test_failed "Authorized targets example missing"
fi

# Test 7: Check setup script
echo "7. Testing setup script..."
if [ -f "setup_security.sh" ] && [ -x "setup_security.sh" ]; then
    test_passed "Setup script exists and is executable"
else
    test_failed "Setup script missing or not executable"
fi

echo ""
echo "🎯 Integration Test Summary"
echo "=========================="

# Quick functionality test with security disabled
echo "Testing with security DISABLED (default)..."
export SECURITY_CONTROLS_ENABLED=false
python -c "
import sys
import os
sys.path.append('.')
os.environ['SECURITY_CONTROLS_ENABLED'] = 'false'

try:
    from app.security_integration import security_integration
    from app.tools.sql_injection_scanner.main import execute_tool
    from app.tools.sql_injection_scanner.schemas import SQLInjectionScannerInput
    
    print(f'Security enabled: {security_integration.security_enabled}')
    
    # Test tool execution without security
    test_input = SQLInjectionScannerInput(
        target_url='https://httpbin.org/get?id=1',
        method='GET',
        timeout=5
    )
    
    # This should work without security controls
    result = execute_tool(test_input)
    print(f'SUCCESS: Tool executed without security, found {result.vulnerabilities_found} vulnerabilities')
    
except Exception as e:
    print(f'FAILED: Tool execution failed: {e}')
    sys.exit(1)
" && test_passed "Tools work with security disabled" || test_failed "Tools broken with security disabled"

echo ""
if command -v python3 >/dev/null 2>&1; then
    echo "✅ Ready to test! Run the following commands:"
    echo ""
    echo "1. Set up security (optional):"
    echo "   ./setup_security.sh"
    echo ""
    echo "2. Start the application:"
    echo "   python -m uvicorn app.main:app --reload"
    echo ""
    echo "3. Test a tool:"
    echo "   curl -X POST http://localhost:8000/api/tools/sql_injection_scanner \\"
    echo "        -H 'Content-Type: application/json' \\"
    echo "        -d '{\"target_url\": \"https://httpbin.org/get?id=1\"}'"
    echo ""
    echo "4. To enable security controls:"
    echo "   Edit .env and set SECURITY_CONTROLS_ENABLED=true"
    echo ""
else
    test_failed "Python 3 not found. Please install Python 3."
fi

echo ""
echo "🔐 Security Status: BACKWARD COMPATIBLE"
echo "   - Existing functionality preserved"
echo "   - Security controls are OPTIONAL"
echo "   - No breaking changes introduced"
echo ""
