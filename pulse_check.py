#!/usr/bin/env python3
"""
Wildbox Master Pulse Check: Comprehensive Production Ready Verification

This orchestrator runs all tests to verify that every component of the 
Wildbox ecosystem is 100% Production Ready.
"""

import asyncio
import time
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import concurrent.futures
import importlib.util

# Add tests directory to path
sys.path.insert(0, str(Path(__file__).parent / "tests"))

from tests.utils.auth_helpers import AuthManager
from tests.utils.test_data_generator import TestDataGenerator  
from tests.utils.report_generator import ReportGenerator


class PulseCheckOrchestrator:
    """Main orchestrator for comprehensive Wildbox testing"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.auth_manager = AuthManager()
        self.test_data_generator = TestDataGenerator()
        self.report_generator = ReportGenerator()
        self.test_results = []
        self.overall_success = True
        
    def log(self, message: str, level: str = "INFO"):
        """Log with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    async def run_test_module(self, module_name: str, description: str) -> Dict[str, Any]:
        """Run a single test module and return results"""
        self.log(f"🧪 Starting {description}")
        
        try:
            # Dynamic import of test module
            module_path = Path(__file__).parent / "tests" / "integration" / f"{module_name}.py"
            if not module_path.exists():
                return {
                    "module": module_name,
                    "description": description,
                    "success": False,
                    "error": f"Test module {module_name}.py not found",
                    "tests": [],
                    "duration": 0
                }
            
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Run the test class
            test_start = time.time()
            if hasattr(module, 'run_tests'):
                results = await module.run_tests()
            else:
                # Fallback for modules without async run_tests
                results = {"tests": [], "success": False, "error": "No run_tests function found"}
                
            duration = time.time() - test_start
            
            # Format results
            result = {
                "module": module_name,
                "description": description,
                "success": results.get("success", False),
                "tests": results.get("tests", []),
                "duration": duration,
                "error": results.get("error", None)
            }
            
            if result["success"]:
                self.log(f"✅ {description} - PASSED ({len(result['tests'])} tests)")
            else:
                self.log(f"❌ {description} - FAILED", "ERROR")
                self.overall_success = False
                
            return result
            
        except Exception as e:
            self.log(f"❌ {description} - ERROR: {str(e)}", "ERROR")
            self.overall_success = False
            return {
                "module": module_name,
                "description": description,
                "success": False,
                "error": str(e),
                "tests": [],
                "duration": 0
            }
    
    async def run_all_tests(self):
        """Run all test modules in parallel where possible"""
        self.log("🚀 Wildbox Master Pulse Check - Production Ready Verification")
        self.log("=" * 80)
        
        # Test modules to run (order matters for some dependencies)
        test_modules = [
            # Core services first
            ("test_identity_comprehensive", "🔐 Identity Service: Authentication, JWT, RBAC, Billing"),
            ("test_gateway_security", "🛡️ Gateway: Routing, Security Headers, Rate Limiting"),
            
            # Satellite services 
            ("test_tools_execution", "🔧 Tools: 57+ Tools, Execution, Plan Protection"),
            ("test_data_integration", "📊 Data: IOC Lookup, Threat Intel, Team-Scoped Data"),
            ("test_guardian_monitoring", "🛡️ Guardian: Assets, Vulnerabilities, Celery Tasks"),
            ("test_sensor_telemetry", "📡 Sensor: osquery, Telemetry, Remote Config"),
            ("test_responder_metrics", "🎯 Responder: Playbooks, Metrics, Execution"),
            ("test_agents_ai", "🤖 Agents: OpenAI, AI Analysis, Reports"),
            ("test_cspm_compliance", "☁️ CSPM: Dashboard, Cloud Scanning, Findings"),
            ("test_automations_workflow", "⚙️ Automations: n8n UI, Webhook Execution"),
            
            # Frontend last
            ("test_dashboard_frontend", "🖥️ Dashboard: UI Loading, Navigation, Data"),
        ]
        
        # Run core services sequentially first (identity, gateway)
        core_modules = test_modules[:2]
        for module_name, description in core_modules:
            result = await self.run_test_module(module_name, description)
            self.test_results.append(result)
            
        # Run satellite services in parallel
        satellite_modules = test_modules[2:-1]
        if satellite_modules:
            self.log("🔄 Running satellite services in parallel...")
            tasks = [
                self.run_test_module(module_name, description)
                for module_name, description in satellite_modules
            ]
            satellite_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in satellite_results:
                if isinstance(result, Exception):
                    self.log(f"❌ Satellite service failed: {result}", "ERROR")
                    self.overall_success = False
                else:
                    self.test_results.append(result)
        
        # Run frontend test last
        frontend_module = test_modules[-1]
        frontend_result = await self.run_test_module(frontend_module[0], frontend_module[1])
        self.test_results.append(frontend_result)
        
    def generate_reports(self):
        """Generate comprehensive reports"""
        self.log("📋 Generating comprehensive reports...")
        
        end_time = datetime.now()
        total_duration = (end_time - self.start_time).total_seconds()
        
        # Count total tests
        total_tests = sum(len(result.get("tests", [])) for result in self.test_results)
        passed_tests = sum(
            len([t for t in result.get("tests", []) if t.get("passed", False)])
            for result in self.test_results
        )
        
        # Generate summary
        summary = {
            "overall_success": self.overall_success,
            "total_modules": len(self.test_results),
            "successful_modules": len([r for r in self.test_results if r.get("success", False)]),
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "total_duration": total_duration,
            "timestamp": datetime.now().isoformat(),
            "modules": self.test_results
        }
        
        # Save JSON report
        json_path = Path("tests/reports/detailed_results.json")
        with open(json_path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
            
        # Generate HTML report
        html_path = Path("tests/reports/pulse_check_report.html")
        self.report_generator.generate_html_report(summary, html_path)
        
        self.log(f"📄 JSON Report: {json_path}")
        self.log(f"🌐 HTML Report: {html_path}")
        
        return summary
        
    async def run(self):
        """Main entry point"""
        try:
            # Setup test environment
            self.log("🔧 Setting up test environment...")
            await self.auth_manager.setup()
            await self.test_data_generator.setup()
            
            # Run all tests
            await self.run_all_tests()
            
            # Generate reports
            summary = self.generate_reports()
            
            # Final status
            self.log("=" * 80)
            if self.overall_success:
                self.log("🎉 🎉 WILDBOX IS 100% PRODUCTION READY! 🎉 🎉", "SUCCESS")
                self.log(f"✅ All {summary['total_tests']} tests passed across {summary['total_modules']} modules")
                self.log("🚀 Ready for production deployment!")
            else:
                self.log("⚠️ WILDBOX NEEDS ATTENTION BEFORE PRODUCTION", "WARNING")
                self.log(f"❌ {summary['total_tests'] - summary['passed_tests']} tests failed")
                self.log("🔧 Review detailed report for issues to fix")
                
            self.log(f"⏱️ Total execution time: {summary['total_duration']:.2f} seconds")
            
            return 0 if self.overall_success else 1
            
        except Exception as e:
            self.log(f"💥 Critical error in pulse check: {str(e)}", "CRITICAL")
            return 2


async def main():
    """Main entry point"""
    orchestrator = PulseCheckOrchestrator()
    return await orchestrator.run()


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n🛑 Pulse check interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        sys.exit(1)