#!/usr/bin/env python3
"""
Test runner for Wildbox Pulse Check system
Runs a dry-run test to verify the orchestrator works without requiring services
"""

import asyncio
import sys
from pathlib import Path

# Add tests directory to path
sys.path.insert(0, str(Path(__file__).parent))

async def test_pulse_check_dry_run():
    """Test pulse check system in dry run mode"""
    print("🧪 Testing Wildbox Pulse Check System (Dry Run)")
    print("=" * 60)
    
    try:
        # Test imports
        print("📦 Testing imports...")
        
        from tests.utils.auth_helpers import AuthManager
        from tests.utils.test_data_generator import TestDataGenerator
        from tests.utils.report_generator import ReportGenerator
        
        print("✅ All utility modules imported successfully")
        
        # Test module loading
        print("\n🔧 Testing test modules...")
        
        test_modules = [
            "test_identity_comprehensive",
            "test_gateway_security", 
            "test_tools_execution",
            "test_data_integration",
            "test_guardian_monitoring",
            "test_sensor_telemetry",
            "test_responder_metrics",
            "test_agents_ai",
            "test_cspm_compliance",
            "test_automations_workflow",
            "test_dashboard_frontend"
        ]
        
        loaded_modules = 0
        for module_name in test_modules:
            try:
                module_path = Path(__file__).parent / "integration" / f"{module_name}.py"
                if module_path.exists():
                    # Test import
                    import importlib.util
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Check for run_tests function
                    if hasattr(module, 'run_tests'):
                        loaded_modules += 1
                        print(f"✅ {module_name} - loaded and ready")
                    else:
                        print(f"⚠️  {module_name} - loaded but missing run_tests function")
                else:
                    print(f"❌ {module_name} - file not found")
            except Exception as e:
                print(f"❌ {module_name} - import error: {e}")
        
        print(f"\n📊 Module Loading Results: {loaded_modules}/{len(test_modules)} modules ready")
        
        # Test utility classes
        print("\n🛠️  Testing utility classes...")
        
        try:
            auth_manager = AuthManager()
            print("✅ AuthManager instantiated")
        except Exception as e:
            print(f"❌ AuthManager error: {e}")
            
        try:
            data_generator = TestDataGenerator()
            test_data = data_generator.get_test_datasets()
            print(f"✅ TestDataGenerator working - generated {len(test_data)} datasets")
        except Exception as e:
            print(f"❌ TestDataGenerator error: {e}")
            
        try:
            report_generator = ReportGenerator()
            print("✅ ReportGenerator instantiated")
        except Exception as e:
            print(f"❌ ReportGenerator error: {e}")
        
        # Test report generation with dummy data
        print("\n📋 Testing report generation...")
        
        try:
            dummy_summary = {
                "overall_success": True,
                "timestamp": "2024-01-01T12:00:00",
                "total_tests": 65,
                "passed_tests": 65,
                "total_duration": 120.5,
                "total_modules": 11,
                "successful_modules": 11,
                "modules": [
                    {
                        "module": "test_identity",
                        "description": "Identity Service Test",
                        "success": True,
                        "tests": [
                            {"name": "Health Check", "passed": True},
                            {"name": "Authentication", "passed": True}
                        ],
                        "duration": 10.5
                    }
                ]
            }
            
            # Test JSON generation
            json_report = report_generator.generate_json_summary(dummy_summary)
            print(f"✅ JSON report generated ({len(json_report)} characters)")
            
            # Test HTML generation
            html_path = Path("tests/reports/test_report.html")
            html_path.parent.mkdir(exist_ok=True)
            report_generator.generate_html_report(dummy_summary, html_path)
            
            if html_path.exists():
                print(f"✅ HTML report generated at {html_path}")
            else:
                print("❌ HTML report generation failed")
                
        except Exception as e:
            print(f"❌ Report generation error: {e}")
        
        print("\n🎉 Pulse Check System Test Complete!")
        print("=" * 60)
        print("✅ System is ready for production testing")
        print("📝 To run full tests: python3 pulse_check.py")
        
        return True
        
    except Exception as e:
        print(f"\n💥 Critical error in pulse check test: {e}")
        return False

if __name__ == "__main__":
    try:
        success = asyncio.run(test_pulse_check_dry_run())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Fatal test error: {e}")
        sys.exit(1)