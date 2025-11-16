#!/usr/bin/env python3
"""Quick test for API key management endpoint"""
import asyncio
import sys
sys.path.insert(0, 'tests/integration')

from test_identity_comprehensive import IdentityServiceTester

async def main():
    tester = IdentityServiceTester()

    print("Testing API Key Management...")
    success = await tester.test_api_key_management()

    print("\n" + "="*60)
    if success:
        print("✅ API KEY MANAGEMENT TEST PASSED!")
    else:
        print("❌ API KEY MANAGEMENT TEST FAILED!")
    print("="*60)

    return success

if __name__ == "__main__":
    result = asyncio.run(main())
    sys.exit(0 if result else 1)
