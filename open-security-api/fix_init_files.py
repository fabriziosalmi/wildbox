#!/usr/bin/env python3
"""
Fix __init__.py files for tools with import issues
"""

import os
from pathlib import Path

def fix_tool_init(tool_path):
    """Fix the __init__.py file for a specific tool"""
    init_file = tool_path / "__init__.py"
    
    if not init_file.exists():
        return False
    
    try:
        with open(init_file, 'r') as f:
            content = f.read()
        
        # Check if the file is trying to import schemas
        if 'from .schemas import' in content:
            # Try to find the actual schema class names
            schemas_file = tool_path / "schemas.py"
            if schemas_file.exists():
                with open(schemas_file, 'r') as f:
                    schemas_content = f.read()
                
                # Extract Input and Output class names
                import re
                input_classes = re.findall(r'class\s+(\w+Input)\s*\(BaseToolInput\):', schemas_content)
                output_classes = re.findall(r'class\s+(\w+Output)\s*\(BaseToolOutput\):', schemas_content)
                
                if input_classes and output_classes:
                    input_class = input_classes[0]
                    output_class = output_classes[0]
                    
                    # Update the init file
                    new_content = f'''"""
{tool_path.name.replace('_', ' ').title()} Tool
"""

from .main import execute_tool, TOOL_INFO
from .schemas import {input_class}, {output_class}

__all__ = ['execute_tool', 'TOOL_INFO', '{input_class}', '{output_class}']
'''
                    
                    with open(init_file, 'w') as f:
                        f.write(new_content)
                    
                    print(f"✅ Fixed {tool_path.name}/__init__.py")
                    return True
        
        return False
        
    except Exception as e:
        print(f"❌ Error fixing {tool_path.name}: {e}")
        return False

def main():
    """Fix all problematic __init__.py files"""
    tools_dir = Path("app/tools")
    
    # Problem tools identified from audit
    problem_tools = [
        'api_security_analyzer',
        'ct_log_scanner', 
        'network_port_scanner',
        'social_engineering_toolkit',
        'social_media_osint',
        'vulnerability_db_scanner'
    ]
    
    fixed_count = 0
    
    for tool_name in problem_tools:
        tool_path = tools_dir / tool_name
        if tool_path.exists():
            if fix_tool_init(tool_path):
                fixed_count += 1
    
    print(f"\n📊 Fixed {fixed_count} out of {len(problem_tools)} problematic tools")

if __name__ == "__main__":
    main()
