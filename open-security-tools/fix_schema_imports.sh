#!/bin/bash

# Script to fix relative imports in tool schemas.py files
# Changes "from ...standardized_schemas import" to "from standardized_schemas import"

echo "🔧 Fixing relative imports in tool schemas.py files..."

# Find all tool schemas.py files
SCHEMA_FILES=$(find app/tools/*/schemas.py -type f 2>/dev/null)

if [ -z "$SCHEMA_FILES" ]; then
    echo "❌ No tool schemas.py files found"
    exit 1
fi

FIXED_COUNT=0
TOTAL_COUNT=0

for file in $SCHEMA_FILES; do
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    
    # Check if file contains relative imports
    if grep -q "from \.\.\.standardized_schemas import" "$file"; then
        echo "📝 Fixing imports in: $file"
        
        # Create backup
        cp "$file" "$file.backup"
        
        # Replace relative imports with absolute imports
        sed -i '' 's/from \.\.\.standardized_schemas import/from standardized_schemas import/g' "$file"
        
        # Verify the change was made
        if grep -q "from standardized_schemas import" "$file" && ! grep -q "from \.\.\.standardized_schemas import" "$file"; then
            echo "✅ Successfully fixed: $file"
            FIXED_COUNT=$((FIXED_COUNT + 1))
            rm "$file.backup"  # Remove backup if successful
        else
            echo "❌ Failed to fix: $file (restoring backup)"
            mv "$file.backup" "$file"
        fi
    else
        echo "ℹ️  No relative imports found in: $file"
    fi
done

echo ""
echo "📊 Summary:"
echo "   Total schema files checked: $TOTAL_COUNT"
echo "   Schema files fixed: $FIXED_COUNT"
echo "   Schema files unchanged: $((TOTAL_COUNT - FIXED_COUNT))"

if [ $FIXED_COUNT -gt 0 ]; then
    echo ""
    echo "🎉 Schema import fixes completed! The tools should now load properly."
    echo "💡 You can test by running the API server and checking tool discovery."
else
    echo ""
    echo "ℹ️  No schema files needed fixing."
fi
