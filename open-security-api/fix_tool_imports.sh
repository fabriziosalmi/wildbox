#!/bin/bash

# Script to fix relative imports in tool main.py files
# Changes "from .schemas import" to "from schemas import"

echo "🔧 Fixing relative imports in tool main.py files..."

# Find all tool main.py files
TOOL_FILES=$(find app/tools/*/main.py -type f 2>/dev/null)

if [ -z "$TOOL_FILES" ]; then
    echo "❌ No tool main.py files found"
    exit 1
fi

FIXED_COUNT=0
TOTAL_COUNT=0

for file in $TOOL_FILES; do
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    
    # Check if file contains relative imports
    if grep -q "from \.schemas import" "$file"; then
        echo "📝 Fixing imports in: $file"
        
        # Create backup
        cp "$file" "$file.backup"
        
        # Replace relative imports with absolute imports
        sed -i '' 's/from \.schemas import/from schemas import/g' "$file"
        
        # Verify the change was made
        if grep -q "from schemas import" "$file" && ! grep -q "from \.schemas import" "$file"; then
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
echo "   Total files checked: $TOTAL_COUNT"
echo "   Files fixed: $FIXED_COUNT"
echo "   Files unchanged: $((TOTAL_COUNT - FIXED_COUNT))"

if [ $FIXED_COUNT -gt 0 ]; then
    echo ""
    echo "🎉 Import fixes completed! The tools should now load properly."
    echo "💡 You can test by running the API server and checking tool discovery."
else
    echo ""
    echo "ℹ️  No files needed fixing."
fi
