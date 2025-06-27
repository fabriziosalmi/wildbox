#!/usr/bin/env python3
"""
Security Fix Scanner - Automated tool to identify and help fix security issues

This script scans all tools and identifies critical security patterns that need fixing.
"""

import os
import re
import ast
import json
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict


class SecurityIssueScanner:
    """Scanner for security issues in tool implementations"""
    
    def __init__(self, tools_directory: str = "app/tools"):
        self.tools_dir = Path(tools_directory)
        self.issues = defaultdict(list)
        self.tool_stats = {}
    
    def scan_all_tools(self) -> Dict[str, Any]:
        """Scan all tools for security issues"""
        print("🔍 Scanning all tools for security issues...")
        
        for tool_dir in self.tools_dir.iterdir():
            if tool_dir.is_dir() and not tool_dir.name.startswith('.'):
                main_file = tool_dir / "main.py"
                if main_file.exists():
                    self.scan_tool_file(tool_dir.name, main_file)
        
        return self.generate_report()
    
    def scan_tool_file(self, tool_name: str, file_path: Path):
        """Scan a single tool file for issues"""
        print(f"  📝 Scanning {tool_name}...")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Initialize tool stats
            self.tool_stats[tool_name] = {
                'file_path': str(file_path),
                'total_lines': len(content.split('\n')),
                'issues': []
            }
            
            # Check for security issues
            self.check_bare_exceptions(tool_name, content)
            self.check_http_session_leaks(tool_name, content)
            self.check_input_validation(tool_name, content)
            self.check_hardcoded_credentials(tool_name, content)
            self.check_import_patterns(tool_name, content)
            self.check_error_handling(tool_name, content)
            self.check_logging_patterns(tool_name, content)
            self.check_rate_limiting(tool_name, content)
            
        except Exception as e:
            self.add_issue(tool_name, 'file_error', f"Could not scan file: {e}", 'HIGH')
    
    def check_bare_exceptions(self, tool_name: str, content: str):
        """Check for bare except clauses"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if re.match(r'^\s*except\s*:\s*$', line) or stripped == 'except:':
                self.add_issue(
                    tool_name, 
                    'bare_exception', 
                    f"Line {i}: Bare except clause - masks all exceptions",
                    'CRITICAL'
                )
    
    def check_http_session_leaks(self, tool_name: str, content: str):
        """Check for HTTP session resource leaks"""
        lines = content.split('\n')
        has_session_creation = False
        has_session_close = False
        has_async_with = False
        
        for i, line in enumerate(lines, 1):
            if 'aiohttp.ClientSession(' in line:
                has_session_creation = True
                # Check if it's in an async with statement
                if 'async with' in line:
                    has_async_with = True
                else:
                    self.add_issue(
                        tool_name,
                        'session_leak',
                        f"Line {i}: HTTP session created without async with context manager",
                        'HIGH'
                    )
            
            if '.close()' in line and 'session' in line:
                has_session_close = True
        
        if has_session_creation and not has_async_with and not has_session_close:
            self.add_issue(
                tool_name,
                'session_leak',
                "HTTP session created but never closed - potential resource leak",
                'HIGH'
            )
    
    def check_input_validation(self, tool_name: str, content: str):
        """Check for missing input validation"""
        issues = []
        
        # Check for direct use of user input in dangerous contexts
        dangerous_patterns = [
            (r'f["\'].*{.*data\..*}.*["\']', 'Direct string formatting with user data'),
            (r'open\(.*data\.', 'File operations with unvalidated user input'),
            (r'subprocess\..*data\.', 'Subprocess calls with unvalidated user input'),
            (r'socket\.connect.*data\.', 'Socket connections with unvalidated user input'),
        ]
        
        for pattern, description in dangerous_patterns:
            if re.search(pattern, content):
                self.add_issue(tool_name, 'input_validation', description, 'HIGH')
        
        # Check for validation imports
        if 'InputValidator' not in content and 'validate' not in content:
            self.add_issue(
                tool_name,
                'input_validation',
                "No input validation detected",
                'MEDIUM'
            )
    
    def check_hardcoded_credentials(self, tool_name: str, content: str):
        """Check for hardcoded credentials and API keys"""
        patterns = [
            (r'(?:^|\s)api_key\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded API key'),
            (r'(?:^|\s)password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
            (r'(?:^|\s)secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret'),
            (r'(?:^|\s)token\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded token'),
        ]
        
        for pattern, description in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # Skip obvious placeholders and legitimate strings
                value = match.group().lower()
                if any(placeholder in value for placeholder in [
                    'placeholder', 'your', 'example', 'xxx', 'test', 'demo',
                    'category', 'security', 'analyzer', 'wildbox', 'user-agent',
                    'application/', 'text/', 'json', '/1.0', 'tool', 'input_schema',
                    'output_schema', 'api_key=', 'in url', 'if ', 'or '
                ]):
                    continue
                
                self.add_issue(tool_name, 'hardcoded_credentials', description, 'CRITICAL')
    
    def check_import_patterns(self, tool_name: str, content: str):
        """Check for inconsistent import patterns"""
        lines = content.split('\n')
        relative_imports = 0
        absolute_imports = 0
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('from .'):
                relative_imports += 1
            elif stripped.startswith('from app.'):
                absolute_imports += 1
        
        if relative_imports > 0 and absolute_imports > 0:
            self.add_issue(
                tool_name,
                'import_pattern',
                "Mixed relative and absolute imports - inconsistent pattern",
                'MEDIUM'
            )
    
    def check_error_handling(self, tool_name: str, content: str):
        """Check error handling patterns"""
        if 'try:' in content:
            # Check if there's proper error handling
            if 'logger.error' not in content and 'logging.' not in content:
                self.add_issue(
                    tool_name,
                    'error_handling',
                    "Exception handling without proper logging",
                    'MEDIUM'
                )
    
    def check_logging_patterns(self, tool_name: str, content: str):
        """Check logging implementation"""
        if 'import logging' not in content and 'logger' not in content:
            self.add_issue(
                tool_name,
                'logging',
                "No logging implementation detected",
                'MEDIUM'
            )
    
    def check_rate_limiting(self, tool_name: str, content: str):
        """Check for rate limiting on external API calls"""
        has_external_api = False
        has_rate_limiting = False
        
        api_patterns = [
            'aiohttp.ClientSession',
            'requests.get',
            'requests.post',
            'urllib.request',
            'httpx.'
        ]
        
        for pattern in api_patterns:
            if pattern in content:
                has_external_api = True
                break
        
        if 'rate_limit' in content.lower() or 'RateLimiter' in content:
            has_rate_limiting = True
        
        if has_external_api and not has_rate_limiting:
            self.add_issue(
                tool_name,
                'rate_limiting',
                "External API calls without rate limiting",
                'HIGH'
            )
    
    def add_issue(self, tool_name: str, issue_type: str, description: str, severity: str):
        """Add an issue to the results"""
        issue = {
            'tool': tool_name,
            'type': issue_type,
            'description': description,
            'severity': severity
        }
        
        self.issues[severity].append(issue)
        self.tool_stats[tool_name]['issues'].append(issue)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        total_tools = len(self.tool_stats)
        tools_with_critical = len([t for t in self.tool_stats.values() if any(i['severity'] == 'CRITICAL' for i in t['issues'])])
        tools_with_high = len([t for t in self.tool_stats.values() if any(i['severity'] == 'HIGH' for i in t['issues'])])
        
        # Count issues by type
        issue_counts = defaultdict(int)
        for severity_issues in self.issues.values():
            for issue in severity_issues:
                issue_counts[issue['type']] += 1
        
        # Find tools with most issues
        tools_by_issue_count = sorted(
            self.tool_stats.items(),
            key=lambda x: len(x[1]['issues']),
            reverse=True
        )[:10]
        
        report = {
            'summary': {
                'total_tools_scanned': total_tools,
                'tools_with_critical_issues': tools_with_critical,
                'tools_with_high_issues': tools_with_high,
                'total_issues': sum(len(issues) for issues in self.issues.values()),
                'issues_by_severity': {severity: len(issues) for severity, issues in self.issues.items()},
                'issues_by_type': dict(issue_counts)
            },
            'critical_issues': self.issues['CRITICAL'],
            'high_issues': self.issues['HIGH'],
            'medium_issues': self.issues['MEDIUM'],
            'top_problematic_tools': [
                {
                    'tool': tool_name,
                    'issue_count': len(stats['issues']),
                    'critical_count': len([i for i in stats['issues'] if i['severity'] == 'CRITICAL']),
                    'high_count': len([i for i in stats['issues'] if i['severity'] == 'HIGH']),
                    'file_path': stats['file_path']
                }
                for tool_name, stats in tools_by_issue_count
            ],
            'detailed_results': self.tool_stats
        }
        
        return report
    
    def generate_fix_script(self, report: Dict[str, Any]) -> str:
        """Generate automated fix script for common issues"""
        script = '''#!/bin/bash
# Automated Security Fix Script
# Generated by Security Issue Scanner

echo "🔧 Starting automated security fixes..."

'''
        
        # Add fixes for bare exceptions
        bare_exception_tools = [issue['tool'] for issue in report['critical_issues'] if issue['type'] == 'bare_exception']
        if bare_exception_tools:
            script += '''
# Fix bare exception handlers
echo "Fixing bare exception handlers..."
'''
            for tool in set(bare_exception_tools):
                script += f'''
# Fix {tool}
sed -i.bak 's/except:/except Exception as e:/g' app/tools/{tool}/main.py
'''
        
        # Add session management fixes
        session_leak_tools = [issue['tool'] for issue in report['high_issues'] if issue['type'] == 'session_leak']
        if session_leak_tools:
            script += '''
# Add session management comments
echo "Adding session management TODO comments..."
'''
            for tool in set(session_leak_tools):
                script += f'''
# Add TODO comment for {tool}
echo "# TODO: Implement proper session management with async with" >> app/tools/{tool}/main.py
'''
        
        script += '''
echo "✅ Automated fixes completed!"
echo "⚠️  Manual review required for all changes"
echo "📋 Check the generated .bak files for original versions"
'''
        
        return script


def main():
    """Main function to run security scanning"""
    print("🚨 Wildbox Security Tools - Security Issue Scanner")
    print("=" * 60)
    
    # Initialize scanner
    scanner = SecurityIssueScanner()
    
    # Scan all tools
    report = scanner.scan_all_tools()
    
    # Print summary
    print("\n📊 SCAN RESULTS SUMMARY")
    print("=" * 40)
    print(f"Total tools scanned: {report['summary']['total_tools_scanned']}")
    print(f"Tools with CRITICAL issues: {report['summary']['tools_with_critical_issues']}")
    print(f"Tools with HIGH issues: {report['summary']['tools_with_high_issues']}")
    print(f"Total issues found: {report['summary']['total_issues']}")
    
    print("\n🚨 Issues by Severity:")
    for severity, count in report['summary']['issues_by_severity'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    print("\n📋 Issues by Type:")
    for issue_type, count in report['summary']['issues_by_type'].items():
        print(f"  {issue_type}: {count}")
    
    print("\n🏆 Most Problematic Tools:")
    for i, tool_info in enumerate(report['top_problematic_tools'][:5], 1):
        print(f"  {i}. {tool_info['tool']} - {tool_info['issue_count']} issues "
              f"({tool_info['critical_count']} critical, {tool_info['high_count']} high)")
    
    # Save detailed report
    with open('security_scan_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n💾 Detailed report saved to: security_scan_report.json")
    
    # Generate fix script
    fix_script = scanner.generate_fix_script(report)
    with open('auto_fix_security.sh', 'w') as f:
        f.write(fix_script)
    print(f"🔧 Fix script generated: auto_fix_security.sh")
    
    # Print critical issues
    if report['critical_issues']:
        print(f"\n🚨 CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION:")
        for issue in report['critical_issues'][:10]:  # Show first 10
            print(f"  • {issue['tool']}: {issue['description']}")
        
        if len(report['critical_issues']) > 10:
            print(f"  ... and {len(report['critical_issues']) - 10} more")
    
    print("\n✅ Security scan completed!")
    return report


if __name__ == "__main__":
    main()
