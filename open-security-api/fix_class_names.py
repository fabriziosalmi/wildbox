#!/usr/bin/env python3
"""
Fix schema class name references in main.py files
"""

import os
import re
from pathlib import Path

# Mapping of old class names to new ones
class_name_mappings = {
    'ct_log_scanner': {
        'CTLogScannerRequest': 'CTLogScannerInput',
        'CTLogScannerResponse': 'CTLogScannerOutput'
    },
    'network_port_scanner': {
        'PortScannerRequest': 'NetworkPortScannerInput',
        'PortScannerResponse': 'NetworkPortScannerOutput'
    },
    'social_engineering_toolkit': {
        'SocialEngToolkitRequest': 'SocialEngineeringToolkitInput',
        'SocialEngToolkitResponse': 'SocialEngineeringToolkitOutput'
    },
    'social_media_osint': {
        'SocialMediaOSINTRequest': 'SocialMediaOSINTInput',
        'SocialMediaOSINTResponse': 'SocialMediaOSINTOutput'
    },
    'vulnerability_db_scanner': {
        'VulnDbScannerRequest': 'VulnerabilityDbScannerInput',
        'VulnDbScannerResponse': 'VulnerabilityDbScannerOutput'
    }
}

def fix_tool_main(tool_name, tool_path):
    """Fix class name references in a main.py file"""
    main_file = tool_path / "main.py"
    
    if not main_file.exists():
        return False
    
    if tool_name not in class_name_mappings:
        return False
    
    try:
        with open(main_file, 'r') as f:
            content = f.read()
        
        original_content = content
        mappings = class_name_mappings[tool_name]
        
        # Replace all occurrences of old class names with new ones
        for old_name, new_name in mappings.items():
            content = content.replace(old_name, new_name)
        
        if content != original_content:
            with open(main_file, 'w') as f:
                f.write(content)
            print(f"✅ Fixed class names in {tool_name}/main.py")
            return True
        else:
            return False
            
    except Exception as e:
        print(f"❌ Error fixing {tool_name}: {e}")
        return False

def main():
    """Fix all problematic main.py files"""
    tools_dir = Path("app/tools")
    
    fixed_count = 0
    
    for tool_name in class_name_mappings.keys():
        tool_path = tools_dir / tool_name
        if tool_path.exists():
            if fix_tool_main(tool_name, tool_path):
                fixed_count += 1
    
    print(f"\n📊 Fixed {fixed_count} out of {len(class_name_mappings)} problematic tools")

if __name__ == "__main__":
    main()
