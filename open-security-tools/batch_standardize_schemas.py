#!/usr/bin/env python3
"""
Batch Schema Standardization Script
Automatically updates all tool schemas to inherit from BaseToolInput and BaseToolOutput
"""

import os
import re
import sys
from pathlib import Path

def standardize_schema_file(schema_path):
    """Standardize a single schema file"""
    try:
        with open(schema_path, 'r') as f:
            content = f.read()
        
        original_content = content
        
        # Add import for standardized schemas if not present
        if 'from ...standardized_schemas import' not in content:
            # Find the imports section and add our import
            import_pattern = r'(from pydantic import BaseModel[^\n]*\n)'
            if re.search(import_pattern, content):
                content = re.sub(
                    import_pattern,
                    r'\1from ...standardized_schemas import BaseToolInput, BaseToolOutput\n',
                    content
                )
            else:
                # Add at the beginning if no pydantic import found
                content = 'from ...standardized_schemas import BaseToolInput, BaseToolOutput\n' + content
        
        # Find all class definitions that should inherit from BaseToolInput
        input_pattern = r'class\s+(\w*(?:Input|Request))\s*\(BaseModel\):'
        for match in re.finditer(input_pattern, content):
            class_name = match.group(1)
            if 'Input' in class_name or 'Request' in class_name:
                old_declaration = f'class {class_name}(BaseModel):'
                new_declaration = f'class {class_name}(BaseToolInput):'
                content = content.replace(old_declaration, new_declaration)
        
        # Find all class definitions that should inherit from BaseToolOutput  
        output_pattern = r'class\s+(\w*(?:Output|Response))\s*\(BaseModel\):'
        for match in re.finditer(output_pattern, content):
            class_name = match.group(1)
            if 'Output' in class_name or 'Response' in class_name:
                old_declaration = f'class {class_name}(BaseModel):'
                new_declaration = f'class {class_name}(BaseToolOutput):'
                content = content.replace(old_declaration, new_declaration)
        
        # Only write if content changed
        if content != original_content:
            with open(schema_path, 'w') as f:
                f.write(content)
            print(f"✅ Updated: {schema_path}")
            return True
        else:
            print(f"⏭️  Skipped: {schema_path} (already standardized)")
            return False
            
    except Exception as e:
        print(f"❌ Error processing {schema_path}: {e}")
        return False

def main():
    """Main batch standardization process"""
    tools_dir = Path("app/tools")
    
    if not tools_dir.exists():
        print(f"❌ Tools directory not found: {tools_dir}")
        return
    
    updated_count = 0
    total_count = 0
    
    # Find all schema files
    for tool_dir in tools_dir.iterdir():
        if tool_dir.is_dir() and tool_dir.name != '__pycache__':
            schema_file = tool_dir / "schemas.py"
            if schema_file.exists():
                total_count += 1
                if standardize_schema_file(schema_file):
                    updated_count += 1
    
    print(f"\n📊 Batch Standardization Complete:")
    print(f"   Total tools processed: {total_count}")
    print(f"   Files updated: {updated_count}")
    print(f"   Files skipped: {total_count - updated_count}")

if __name__ == "__main__":
    main()
