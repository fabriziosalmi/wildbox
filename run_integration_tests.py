#!/usr/bin/env python3
"""
Integration Tests Runner
Esegue tutti i test di integrazione e genera report
"""

import sys
import asyncio
import importlib.util
from pathlib import Path
from typing import Dict, List, Any
import json
from datetime import datetime

class IntegrationTestRunner:
    """Runner per test di integrazione custom"""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests": [],
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0
            }
        }
    
    def load_test_module(self, test_file: Path):
        """Carica dinamicamente un modulo di test"""
        spec = importlib.util.spec_from_file_location(test_file.stem, test_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    
    async def run_test_file(self, test_file: Path) -> Dict[str, Any]:
        """Esegue un singolo file di test"""
        print(f"\n{'='*70}")
        print(f"Running: {test_file.name}")
        print(f"{'='*70}")
        
        try:
            module = self.load_test_module(test_file)
            
            # Trova la classe Tester nel modulo
            tester_class = None
            for name in dir(module):
                obj = getattr(module, name)
                if isinstance(obj, type) and name.endswith('Tester'):
                    tester_class = obj
                    break
            
            if not tester_class:
                print(f"⚠️  No Tester class found in {test_file.name}")
                return {
                    "file": test_file.name,
                    "status": "skipped",
                    "reason": "No Tester class found"
                }
            
            # Istanzia e esegui
            tester = tester_class()
            
            # Trova metodi di test (iniziano con test_)
            test_methods = [m for m in dir(tester) if m.startswith('test_')]
            
            test_results = []
            for method_name in test_methods:
                method = getattr(tester, method_name)
                
                try:
                    # Esegui (potrebbe essere async)
                    if asyncio.iscoroutinefunction(method):
                        result = await method()
                    else:
                        result = method()
                    
                    status = "passed" if result else "failed"
                    test_results.append({
                        "method": method_name,
                        "status": status
                    })
                    
                    symbol = "✅" if result else "❌"
                    print(f"  {symbol} {method_name}")
                    
                except Exception as e:
                    test_results.append({
                        "method": method_name,
                        "status": "error",
                        "error": str(e)
                    })
                    print(f"  ❌ {method_name} - ERROR: {str(e)[:50]}")
            
            return {
                "file": test_file.name,
                "status": "completed",
                "tests": test_results,
                "passed": sum(1 for t in test_results if t["status"] == "passed"),
                "failed": sum(1 for t in test_results if t["status"] in ["failed", "error"])
            }
            
        except Exception as e:
            print(f"❌ Failed to load/run {test_file.name}: {e}")
            return {
                "file": test_file.name,
                "status": "error",
                "error": str(e)
            }
    
    async def run_all_tests(self, test_dir: Path = None):
        """Esegue tutti i test di integrazione"""
        if test_dir is None:
            test_dir = Path("/Users/fab/GitHub/wildbox/tests/integration")
        
        test_files = sorted(test_dir.glob("test_*.py"))
        
        print(f"\n🔍 Found {len(test_files)} integration test files")
        print(f"📂 Test directory: {test_dir}\n")
        
        for test_file in test_files:
            result = await self.run_test_file(test_file)
            self.results["tests"].append(result)
            
            # Aggiorna summary
            self.results["summary"]["total"] += 1
            if result["status"] == "completed":
                self.results["summary"]["passed"] += result.get("passed", 0)
                self.results["summary"]["failed"] += result.get("failed", 0)
            elif result["status"] == "skipped":
                self.results["summary"]["skipped"] += 1
        
        self.print_summary()
        self.save_results()
    
    def print_summary(self):
        """Stampa riepilogo risultati"""
        print(f"\n{'='*70}")
        print("📊 TEST EXECUTION SUMMARY")
        print(f"{'='*70}")
        
        summary = self.results["summary"]
        print(f"Total test files: {summary['total']}")
        print(f"Tests passed: {summary['passed']} ✅")
        print(f"Tests failed: {summary['failed']} ❌")
        print(f"Tests skipped: {summary['skipped']} ⚠️")
        
        # Dettaglio per file
        print(f"\n📋 DETAILS BY FILE")
        print(f"{'-'*70}")
        for test in self.results["tests"]:
            status_symbol = {
                "completed": "✅",
                "error": "❌",
                "skipped": "⚠️"
            }.get(test["status"], "❓")
            
            if test["status"] == "completed":
                detail = f"({test['passed']}/{test['passed']+test['failed']} passed)"
            elif test["status"] == "skipped":
                detail = f"({test.get('reason', 'unknown')})"
            else:
                detail = f"(error)"
            
            print(f"{status_symbol} {test['file']:40s} {detail}")
        
        print(f"{'='*70}\n")
    
    def save_results(self):
        """Salva risultati in JSON"""
        output_file = Path("/Users/fab/GitHub/wildbox/integration_test_results.json")
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"💾 Results saved to: {output_file}")


async def main():
    """Main function"""
    runner = IntegrationTestRunner()
    
    # Limita a 3 test per velocità (puoi rimuovere il [:3] per tutti)
    test_dir = Path("/Users/fab/GitHub/wildbox/tests/integration")
    
    print("🚀 WILDBOX INTEGRATION TESTS - BASELINE RUN")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    await runner.run_all_tests(test_dir)


if __name__ == "__main__":
    asyncio.run(main())
