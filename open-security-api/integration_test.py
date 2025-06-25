#!/usr/bin/env python3
"""
Integration Test: Secure Execution with Standardized Schemas
Tests the complete pipeline from schema validation to secure execution
"""

import asyncio
import sys
import time
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, '/Users/fab/GitHub/wildbox/open-security-api')

from app.secure_execution_manager import SecureToolExecutionManager
from app.standardized_schemas import BaseToolInput, BaseToolOutput
from pydantic import Field

# Test schemas
class TestToolInput(BaseToolInput):
    """Test input schema"""
    target: str = Field(..., description="Target to test")
    timeout: int = Field(default=30, description="Timeout in seconds")

class TestToolOutput(BaseToolOutput):
    """Test output schema"""
    result: str = Field(..., description="Test result")
    execution_time: float = Field(..., description="Execution time")

# Test tool function
async def test_tool_function(input_data: TestToolInput) -> TestToolOutput:
    """Simple test tool that validates input and returns output"""
    start_time = time.time()
    
    # Simulate some processing
    await asyncio.sleep(0.1)
    
    execution_time = time.time() - start_time
    
    return TestToolOutput(
        result=f"Successfully processed target: {input_data.target}",
        execution_time=execution_time,
        success=True,
        message="Test completed successfully"
    )

async def test_secure_execution():
    """Test the secure execution framework with standardized schemas"""
    print("🧪 Starting Secure Execution Integration Test")
    print("=" * 60)
    
    # Initialize secure execution manager
    execution_manager = SecureToolExecutionManager()
    
    # Test cases
    test_cases = [
        {
            "name": "Basic Execution Test",
            "input": TestToolInput(target="test.example.com", timeout=30),
            "expected_success": True
        },
        {
            "name": "Invalid Input Test", 
            "input": {"invalid": "data"},  # This should trigger validation error
            "expected_success": False
        }
    ]
    
    results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"[{i}/{len(test_cases)}] Running: {test_case['name']}")
        
        try:
            # Validate input if it's a proper schema
            if hasattr(test_case['input'], 'model_validate'):
                validated_input = test_case['input']
            else:
                # This should fail validation
                validated_input = TestToolInput(**test_case['input'])
            
            # Execute with secure execution manager
            result = await execution_manager.execute_tool_secure(
                tool_func=test_tool_function,
                input_data=validated_input,
                tool_name="test_tool",
                timeout=5
            )
            
            if result.status.value == "completed":
                print(f"   ✅ SUCCESS: {result.result.result}")
                print(f"   ⏱️  Execution time: {result.duration:.3f}s")
                results.append({
                    "test": test_case['name'],
                    "status": "PASS",
                    "execution_time": result.duration
                })
            else:
                print(f"   ❌ FAILED: {result.error}")
                results.append({
                    "test": test_case['name'], 
                    "status": "FAIL",
                    "error": result.error
                })
                
        except Exception as e:
            expected_failure = not test_case['expected_success']
            if expected_failure:
                print(f"   ✅ EXPECTED FAILURE: {str(e)}")
                results.append({
                    "test": test_case['name'],
                    "status": "PASS (Expected Failure)",
                    "error": str(e)
                })
            else:
                print(f"   ❌ UNEXPECTED FAILURE: {str(e)}")
                results.append({
                    "test": test_case['name'],
                    "status": "FAIL",
                    "error": str(e)
                })
        
        print()
    
    # Print summary
    print("📊 TEST SUMMARY")
    print("=" * 60)
    passed = sum(1 for r in results if "PASS" in r['status'])
    total = len(results)
    
    for result in results:
        status_icon = "✅" if "PASS" in result['status'] else "❌"
        print(f"{status_icon} {result['test']}: {result['status']}")
    
    print(f"\n🎯 Overall Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED - Integration successful!")
        return True
    else:
        print("⚠️  Some tests failed - Review implementation")
        return False

async def test_real_tool_execution():
    """Test execution with a real tool from the codebase"""
    print("\n🔧 Testing Real Tool Execution")
    print("=" * 60)
    
    try:
        # Import a real tool
        from app.tools.base64_tool.main import execute_tool as base64_execute
        from app.tools.base64_tool.schemas import Base64ToolInput
        
        execution_manager = SecureToolExecutionManager()
        
        # Test base64 encoding
        test_input = Base64ToolInput(
            operation="encode",
            data="Hello, Wildbox Security!",
            url_safe=False
        )
        
        print("Testing base64_tool with secure execution...")
        
        result = await execution_manager.execute_tool_secure(
            tool_func=base64_execute,
            input_data=test_input,
            tool_name="base64_tool",
            timeout=10
        )
        
        if result.status.value == "completed":
            print(f"✅ Real tool execution successful!")
            print(f"   Input: {test_input.data}")
            print(f"   Output: {result.result.encoded_data if hasattr(result.result, 'encoded_data') else 'Success'}")
            print(f"   Execution time: {result.duration:.3f}s")
            return True
        else:
            print(f"❌ Real tool execution failed: {result.error}")
            return False
            
    except Exception as e:
        print(f"❌ Real tool test failed: {str(e)}")
        return False

async def main():
    """Run all integration tests"""
    print("🚀 Wildbox Secure Execution Integration Test Suite")
    print("🎯 Testing: Schema validation + Secure execution pipeline")
    print()
    
    # Run basic tests
    basic_success = await test_secure_execution()
    
    # Run real tool test
    real_tool_success = await test_real_tool_execution()
    
    # Final result
    print("\n🏁 FINAL INTEGRATION TEST RESULT")
    print("=" * 60)
    
    if basic_success and real_tool_success:
        print("🎉 🎉 ALL INTEGRATION TESTS PASSED! 🎉 🎉")
        print("✅ Schema standardization working correctly")
        print("✅ Secure execution framework operational")
        print("✅ Real tool integration successful")
        print("\n🚀 Ready for production deployment!")
    else:
        print("⚠️  Integration tests failed - review implementation")
        print("❌ Some components need attention before deployment")

if __name__ == "__main__":
    asyncio.run(main())
