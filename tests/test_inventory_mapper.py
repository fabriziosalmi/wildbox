#!/usr/bin/env python3
"""
Wildbox Test Suite Mapper - Passo 1: Discovery
Scansiona e categorizza tutti i test nel repository
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

class TestInventoryMapper:
    """Mappa tutti i test nel repository Wildbox"""
    
    def __init__(self, repo_path: str = "/Users/fab/GitHub/wildbox"):
        self.repo_path = Path(repo_path)
        self.inventory = {
            "python_tests": [],
            "typescript_tests": [],
            "test_helpers": [],
            "summary": {}
        }
    
    def scan_python_tests(self) -> List[Dict[str, Any]]:
        """Scansiona tutti i file di test Python"""
        python_tests = []
        
        # Pattern di ricerca per test Python
        patterns = ["test_*.py", "*_test.py"]
        exclude_dirs = {".venv", "venv", "node_modules", ".git", ".next", "__pycache__"}
        
        for pattern in patterns:
            for test_file in self.repo_path.rglob(pattern):
                # Escludi directory non rilevanti
                if any(excl in test_file.parts for excl in exclude_dirs):
                    continue
                
                test_info = self._analyze_python_test(test_file)
                python_tests.append(test_info)
        
        return python_tests
    
    def _analyze_python_test(self, file_path: Path) -> Dict[str, Any]:
        """Analizza un singolo file di test Python"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
        
        # Determina categoria
        category = self._categorize_python_test(file_path, content)
        
        # Estrai informazioni
        return {
            "path": str(file_path.relative_to(self.repo_path)),
            "absolute_path": str(file_path),
            "name": file_path.name,
            "lines": len(lines),
            "category": category,
            "service": self._extract_service(file_path),
            "framework": self._detect_python_framework(content),
            "has_classes": "class " in content,
            "has_async": "async def" in content or "asyncio" in content,
            "imports": self._extract_imports(lines[:50])
        }
    
    def _categorize_python_test(self, file_path: Path, content: str) -> str:
        """Categorizza il tipo di test Python"""
        path_str = str(file_path)
        
        if "tests/integration" in path_str:
            return "integration"
        elif "test_e2e" in file_path.name or "e2e" in path_str:
            return "e2e"
        elif "scripts/test_" in path_str:
            return "script-based"
        elif "test_basic" in file_path.name:
            return "unit"
        elif "/tests/" in path_str and "test_" in file_path.name:
            return "unit"
        else:
            return "standalone"
    
    def _detect_python_framework(self, content: str) -> str:
        """Rileva il framework di testing usato"""
        if "import pytest" in content or "from pytest" in content:
            return "pytest"
        elif "import unittest" in content or "from unittest" in content:
            return "unittest"
        elif "class " in content and "Tester" in content:
            return "custom-class"
        else:
            return "unknown"
    
    def _extract_imports(self, lines: List[str]) -> List[str]:
        """Estrae i principali import dalle prime righe"""
        imports = []
        for line in lines:
            line = line.strip()
            if line.startswith("import ") or line.startswith("from "):
                imports.append(line)
        return imports[:10]  # Primi 10 import
    
    def scan_typescript_tests(self) -> List[Dict[str, Any]]:
        """Scansiona tutti i file di test TypeScript/JavaScript"""
        ts_tests = []
        
        patterns = ["*.spec.ts", "*.spec.tsx", "*.test.ts", "*.test.tsx"]
        exclude_dirs = {"node_modules", ".next", "dist", "build"}
        
        for pattern in patterns:
            for test_file in self.repo_path.rglob(pattern):
                if any(excl in test_file.parts for excl in exclude_dirs):
                    continue
                
                test_info = self._analyze_typescript_test(test_file)
                ts_tests.append(test_info)
        
        return ts_tests
    
    def _analyze_typescript_test(self, file_path: Path) -> Dict[str, Any]:
        """Analizza un singolo file di test TypeScript"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return {}
        
        return {
            "path": str(file_path.relative_to(self.repo_path)),
            "absolute_path": str(file_path),
            "name": file_path.name,
            "lines": len(lines),
            "category": "e2e" if "e2e" in str(file_path) else "unit",
            "service": self._extract_service(file_path),
            "framework": self._detect_ts_framework(content),
            "has_page_objects": "page-objects" in str(file_path) or "import {" in content and "Page" in content,
            "test_count": content.count("test(") + content.count("test.only("),
            "describe_count": content.count("describe(")
        }
    
    def _detect_ts_framework(self, content: str) -> str:
        """Rileva il framework di testing TypeScript"""
        if "@playwright/test" in content:
            return "playwright"
        elif "jest" in content.lower():
            return "jest"
        elif "vitest" in content.lower():
            return "vitest"
        else:
            return "unknown"
    
    def _extract_service(self, file_path: Path) -> str:
        """Estrae il nome del servizio dal path"""
        services = [
            "agents", "automations", "cspm", "dashboard", "data",
            "gateway", "guardian", "identity", "responder", "sensor", "tools"
        ]
        
        path_str = str(file_path).lower()
        for service in services:
            if service in path_str:
                return service
        
        return "shared"
    
    def scan_test_helpers(self) -> List[Dict[str, Any]]:
        """Scansiona file helper per i test (Page Objects, utilities, etc.)"""
        helpers = []
        
        # Cerca Page Objects
        page_objects_dir = self.repo_path / "open-security-dashboard" / "tests" / "e2e" / "page-objects"
        if page_objects_dir.exists():
            for po_file in page_objects_dir.glob("*.ts"):
                helpers.append({
                    "path": str(po_file.relative_to(self.repo_path)),
                    "type": "page-object",
                    "name": po_file.name
                })
        
        # Cerca test utilities
        utils_dirs = list(self.repo_path.rglob("tests/utils"))
        for utils_dir in utils_dirs:
            for util_file in utils_dir.glob("*.py"):
                if not util_file.name.startswith("__"):
                    helpers.append({
                        "path": str(util_file.relative_to(self.repo_path)),
                        "type": "utility",
                        "name": util_file.name
                    })
        
        return helpers
    
    def generate_summary(self):
        """Genera statistiche riassuntive"""
        py_tests = self.inventory["python_tests"]
        ts_tests = self.inventory["typescript_tests"]
        
        # Conta per categoria
        py_by_category = defaultdict(int)
        for test in py_tests:
            py_by_category[test["category"]] += 1
        
        # Conta per servizio
        by_service = defaultdict(int)
        for test in py_tests + ts_tests:
            by_service[test["service"]] += 1
        
        # Conta per framework
        by_framework = defaultdict(int)
        for test in py_tests:
            by_framework[test.get("framework", "unknown")] += 1
        
        # Linee di codice
        total_py_lines = sum(t["lines"] for t in py_tests)
        total_ts_lines = sum(t["lines"] for t in ts_tests)
        
        self.inventory["summary"] = {
            "total_test_files": len(py_tests) + len(ts_tests),
            "python_tests": {
                "count": len(py_tests),
                "total_lines": total_py_lines,
                "by_category": dict(py_by_category),
                "by_framework": dict(by_framework)
            },
            "typescript_tests": {
                "count": len(ts_tests),
                "total_lines": total_ts_lines,
                "e2e_count": sum(1 for t in ts_tests if t["category"] == "e2e")
            },
            "by_service": dict(sorted(by_service.items())),
            "test_helpers": len(self.inventory["test_helpers"])
        }
    
    def run_full_scan(self):
        """Esegue la scansione completa"""
        print("🔍 Scanning Python tests...")
        self.inventory["python_tests"] = self.scan_python_tests()
        print(f"   Found {len(self.inventory['python_tests'])} Python test files")
        
        print("🔍 Scanning TypeScript tests...")
        self.inventory["typescript_tests"] = self.scan_typescript_tests()
        print(f"   Found {len(self.inventory['typescript_tests'])} TypeScript test files")
        
        print("🔍 Scanning test helpers...")
        self.inventory["test_helpers"] = self.scan_test_helpers()
        print(f"   Found {len(self.inventory['test_helpers'])} helper files")
        
        print("📊 Generating summary...")
        self.generate_summary()
        
        return self.inventory
    
    def print_report(self):
        """Stampa un report leggibile"""
        summary = self.inventory["summary"]
        
        print("\n" + "="*60)
        print("📊 WILDBOX TEST SUITE INVENTORY - DETAILED REPORT")
        print("="*60)
        
        print(f"\n📈 OVERVIEW")
        print(f"   Total test files: {summary['total_test_files']}")
        print(f"   Python tests: {summary['python_tests']['count']}")
        print(f"   TypeScript tests: {summary['typescript_tests']['count']}")
        print(f"   Test helpers: {summary['test_helpers']}")
        
        print(f"\n🐍 PYTHON TESTS BREAKDOWN")
        print(f"   Total lines of code: {summary['python_tests']['total_lines']:,}")
        print(f"   By category:")
        for cat, count in sorted(summary['python_tests']['by_category'].items()):
            print(f"      {cat:15s}: {count:2d} file(s)")
        print(f"   By framework:")
        for fw, count in sorted(summary['python_tests']['by_framework'].items()):
            print(f"      {fw:15s}: {count:2d} file(s)")
        
        print(f"\n📘 TYPESCRIPT TESTS BREAKDOWN")
        print(f"   Total lines of code: {summary['typescript_tests']['total_lines']:,}")
        print(f"   E2E tests (Playwright): {summary['typescript_tests']['e2e_count']}")
        
        print(f"\n🎯 TESTS BY SERVICE")
        for service, count in sorted(summary['by_service'].items(), key=lambda x: x[1], reverse=True):
            print(f"   {service:15s}: {count:2d} file(s)")
        
        print("\n" + "="*60)
    
    def save_to_json(self, output_file: str = "test_inventory.json"):
        """Salva l'inventario in formato JSON"""
        output_path = self.repo_path / output_file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.inventory, f, indent=2)
        print(f"\n💾 Inventory saved to: {output_path}")


def main():
    """Main function"""
    mapper = TestInventoryMapper()
    
    # Esegui scansione completa
    inventory = mapper.run_full_scan()
    
    # Stampa report
    mapper.print_report()
    
    # Salva in JSON
    mapper.save_to_json()
    
    print("\n✅ Passo 1 (Discovery) completato con successo!")
    print("   Next steps:")
    print("   - Passo 2: Categorizzare test per tipo e qualità")
    print("   - Passo 3: Valutare coverage per servizio")
    print("   - Passo 4: Identificare gap e priorità")


if __name__ == "__main__":
    main()
