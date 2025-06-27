#!/usr/bin/env python3
"""
Tool Compliance Audit Script
Blueprint Phase 1 - Audit all 57 tools for standardization compliance
"""

import os
import sys
import importlib
import json
from pathlib import Path
from typing import Dict, Any, List
import logging

# Add the app directory to Python path
sys.path.insert(0, '/Users/fab/GitHub/wildbox/open-security-tools')

from app.standardized_schemas import tool_validator, BaseToolInput, BaseToolOutput

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def discover_tools() -> List[str]:
    """Discover all available tools."""
    tools_dir = Path('/Users/fab/GitHub/wildbox/open-security-tools/app/tools')
    tools = []
    
    for tool_dir in tools_dir.iterdir():
        if tool_dir.is_dir() and not tool_dir.name.startswith('__'):
            if (tool_dir / 'main.py').exists() and (tool_dir / 'schemas.py').exists():
                tools.append(tool_dir.name)
    
    return sorted(tools)


def audit_tool_schemas(tool_name: str) -> Dict[str, Any]:
    """Audit a single tool for schema compliance."""
    audit_result = {
        'tool_name': tool_name,
        'has_schemas_file': False,
        'has_main_file': False,
        'input_schema_compliant': False,
        'output_schema_compliant': False,
        'has_input_schema': False,
        'has_output_schema': False,
        'errors': [],
        'warnings': [],
        'compliance_score': 0
    }
    
    try:
        # Check if files exist
        tool_path = Path(f'/Users/fab/GitHub/wildbox/open-security-tools/app/tools/{tool_name}')
        schemas_file = tool_path / 'schemas.py'
        main_file = tool_path / 'main.py'
        
        audit_result['has_schemas_file'] = schemas_file.exists()
        audit_result['has_main_file'] = main_file.exists()
        
        if not audit_result['has_schemas_file']:
            audit_result['errors'].append("Missing schemas.py file")
            return audit_result
        
        if not audit_result['has_main_file']:
            audit_result['errors'].append("Missing main.py file")
        
        # Try to import schemas
        try:
            schemas_module = importlib.import_module(f'app.tools.{tool_name}.schemas')
            
            # Look for Input and Output classes
            input_class = None
            output_class = None
            
            for attr_name in dir(schemas_module):
                attr = getattr(schemas_module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseToolInput):
                    if 'Input' in attr_name:
                        input_class = attr
                        audit_result['has_input_schema'] = True
                
                if isinstance(attr, type) and issubclass(attr, BaseToolOutput):
                    if 'Output' in attr_name:
                        output_class = attr
                        audit_result['has_output_schema'] = True
            
            # Check for non-standard schema names
            if not input_class:
                # Look for any class ending with Input
                for attr_name in dir(schemas_module):
                    if attr_name.endswith('Input'):
                        attr = getattr(schemas_module, attr_name)
                        if isinstance(attr, type):
                            input_class = attr
                            audit_result['has_input_schema'] = True
                            if not issubclass(attr, BaseToolInput):
                                audit_result['warnings'].append(f"Input schema {attr_name} doesn't inherit from BaseToolInput")
                            else:
                                audit_result['input_schema_compliant'] = True
            
            if not output_class:
                # Look for any class ending with Output
                for attr_name in dir(schemas_module):
                    if attr_name.endswith('Output'):
                        attr = getattr(schemas_module, attr_name)
                        if isinstance(attr, type):
                            output_class = attr
                            audit_result['has_output_schema'] = True
                            if not issubclass(attr, BaseToolOutput):
                                audit_result['warnings'].append(f"Output schema {attr_name} doesn't inherit from BaseToolOutput")
                            else:
                                audit_result['output_schema_compliant'] = True
            
            if input_class and issubclass(input_class, BaseToolInput):
                audit_result['input_schema_compliant'] = True
            
            if output_class and issubclass(output_class, BaseToolOutput):
                audit_result['output_schema_compliant'] = True
            
            if not audit_result['has_input_schema']:
                audit_result['errors'].append("No input schema found")
            
            if not audit_result['has_output_schema']:
                audit_result['errors'].append("No output schema found")
                
        except ImportError as e:
            audit_result['errors'].append(f"Failed to import schemas: {str(e)}")
        except Exception as e:
            audit_result['errors'].append(f"Schema analysis error: {str(e)}")
    
    except Exception as e:
        audit_result['errors'].append(f"Tool audit error: {str(e)}")
    
    # Calculate compliance score
    criteria = [
        audit_result['has_schemas_file'],
        audit_result['has_main_file'],
        audit_result['has_input_schema'],
        audit_result['has_output_schema'],
        audit_result['input_schema_compliant'],
        audit_result['output_schema_compliant']
    ]
    
    audit_result['compliance_score'] = (sum(criteria) / len(criteria)) * 100
    
    return audit_result


def generate_audit_report(audit_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate comprehensive audit report."""
    total_tools = len(audit_results)
    compliant_tools = [r for r in audit_results if r['compliance_score'] == 100]
    partial_compliant = [r for r in audit_results if 50 <= r['compliance_score'] < 100]
    non_compliant = [r for r in audit_results if r['compliance_score'] < 50]
    
    report = {
        'audit_date': '2025-06-26',
        'total_tools_audited': total_tools,
        'fully_compliant': len(compliant_tools),
        'partially_compliant': len(partial_compliant),
        'non_compliant': len(non_compliant),
        'overall_compliance_rate': (len(compliant_tools) / total_tools) * 100 if total_tools > 0 else 0,
        'average_compliance_score': sum(r['compliance_score'] for r in audit_results) / total_tools if total_tools > 0 else 0,
        'compliance_breakdown': {
            'fully_compliant_tools': [r['tool_name'] for r in compliant_tools],
            'partially_compliant_tools': [r['tool_name'] for r in partial_compliant],
            'non_compliant_tools': [r['tool_name'] for r in non_compliant]
        },
        'common_issues': {},
        'tool_details': audit_results
    }
    
    # Identify common issues
    all_errors = []
    all_warnings = []
    
    for result in audit_results:
        all_errors.extend(result['errors'])
        all_warnings.extend(result['warnings'])
    
    # Count common issues
    error_counts = {}
    for error in all_errors:
        error_counts[error] = error_counts.get(error, 0) + 1
    
    warning_counts = {}
    for warning in all_warnings:
        warning_counts[warning] = warning_counts.get(warning, 0) + 1
    
    report['common_issues'] = {
        'errors': dict(sorted(error_counts.items(), key=lambda x: x[1], reverse=True)),
        'warnings': dict(sorted(warning_counts.items(), key=lambda x: x[1], reverse=True))
    }
    
    return report


def main():
    """Run complete tool compliance audit."""
    print("Starting Wildbox Security API - Tool Compliance Audit")
    print("=" * 60)
    
    # Discover all tools
    tools = discover_tools()
    print(f"Discovered {len(tools)} tools")
    
    # Audit each tool
    audit_results = []
    for i, tool_name in enumerate(tools, 1):
        print(f"[{i:2d}/{len(tools)}] Auditing {tool_name}...", end=" ")
        result = audit_tool_schemas(tool_name)
        audit_results.append(result)
        
        if result['compliance_score'] == 100:
            print("✅ COMPLIANT")
        elif result['compliance_score'] >= 50:
            print("🟡 PARTIAL")
        else:
            print("🔴 NON-COMPLIANT")
    
    # Generate report
    report = generate_audit_report(audit_results)
    
    # Save detailed report
    with open('/Users/fab/GitHub/wildbox/TOOL_COMPLIANCE_AUDIT.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\\n" + "=" * 60)
    print("AUDIT SUMMARY")
    print("=" * 60)
    print(f"Total Tools Audited:     {report['total_tools_audited']}")
    print(f"Fully Compliant:         {report['fully_compliant']} ({report['overall_compliance_rate']:.1f}%)")
    print(f"Partially Compliant:     {report['partially_compliant']}")
    print(f"Non-Compliant:           {report['non_compliant']}")
    print(f"Average Compliance:      {report['average_compliance_score']:.1f}%")
    
    print("\\nTOP ISSUES:")
    for issue, count in list(report['common_issues']['errors'].items())[:5]:
        print(f"  🔴 {issue}: {count} tools")
    
    for issue, count in list(report['common_issues']['warnings'].items())[:3]:
        print(f"  🟡 {issue}: {count} tools")
    
    print("\\nNON-COMPLIANT TOOLS:")
    for tool in report['compliance_breakdown']['non_compliant_tools'][:10]:
        print(f"  - {tool}")
    if len(report['compliance_breakdown']['non_compliant_tools']) > 10:
        print(f"  ... and {len(report['compliance_breakdown']['non_compliant_tools']) - 10} more")
    
    print(f"\\nDetailed report saved to: TOOL_COMPLIANCE_AUDIT.json")
    
    return report


if __name__ == "__main__":
    main()
