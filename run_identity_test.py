#!/usr/bin/env python3
"""
Quick Identity Test Runner
"""
import sys
import asyncio
import importlib.util
from pathlib import Path

def load_test_module(test_file: Path):
    """Load a test module dynamically"""
    spec = importlib.util.spec_from_file_location("test_module", test_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

async def main():
    test_file = Path("tests/integration/test_identity_comprehensive.py")

    print("=" * 70)
    print("IDENTITY SERVICE INTEGRATION TESTS")
    print("=" * 70)
    print()

    try:
        module = load_test_module(test_file)
        result = await module.run_tests()

        print("\n" + "=" * 70)
        print("TEST RESULTS")
        print("=" * 70)
        print(f"\nSummary: {result.get('summary', 'Unknown')}")
        print(f"Overall Success: {result.get('success', False)}")

        if 'tests' in result:
            print(f"\nDetailed Results ({len(result['tests'])} tests):")
            for test in result['tests']:
                status = "✅ PASS" if test['passed'] else "❌ FAIL"
                print(f"  {status} - {test['name']}")
                if test.get('details'):
                    print(f"      {test['details']}")

        return 0 if result.get('success', False) else 1

    except Exception as e:
        print(f"❌ Error running tests: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
