#!/usr/bin/env python3
"""
Fix relative imports in main.py files
"""

import os
import re
from pathlib import Path

def fix_main_imports(main_path):
    """Fix relative imports in a main.py file"""
    try:
        with open(main_path, 'r') as f:
            content = f.read()
        
        original_content = content
        
        # Fix 'from schemas import' to 'from .schemas import'
        content = re.sub(r'^from schemas import', 'from .schemas import', content, flags=re.MULTILINE)
        
        # Fix 'import schemas' to 'from . import schemas'
        content = re.sub(r'^import schemas$', 'from . import schemas', content, flags=re.MULTILINE)
        
        if content != original_content:
            with open(main_path, 'w') as f:
                f.write(content)
            print(f"✅ Fixed imports in {main_path}")
            return True
        else:
            return False
            
    except Exception as e:
        print(f"❌ Error fixing {main_path}: {e}")
        return False

def main():
    """Fix all main.py files"""
    tools_dir = Path("app/tools")
    
    fixed_count = 0
    total_count = 0
    
    # Find all main.py files
    for tool_dir in tools_dir.iterdir():
        if tool_dir.is_dir() and tool_dir.name != '__pycache__':
            main_file = tool_dir / "main.py"
            if main_file.exists():
                total_count += 1
                if fix_main_imports(main_file):
                    fixed_count += 1
    
    print(f"\n📊 Import Fix Complete:")
    print(f"   Total main.py files: {total_count}")
    print(f"   Files updated: {fixed_count}")

if __name__ == "__main__":
    main()
