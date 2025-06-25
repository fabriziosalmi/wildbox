#!/bin/bash

# Wildbox Open Security Automations - Workflow Import Script
# This script imports workflows from JSON files into n8n

set -e

# Configuration
N8N_HOST="${N8N_HOST:-localhost}"
N8N_PORT="${N8N_PORT:-5678}"
N8N_AUTH_USER="${N8N_BASIC_AUTH_USER:-admin}"
N8N_AUTH_PASS="${N8N_BASIC_AUTH_PASSWORD:-wildbox_n8n_2025}"
WORKFLOWS_DIR="$(dirname "$0")/../workflows"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🤖 Wildbox Automations - Workflow Import Script${NC}"
echo "=================================================="

# Check if n8n is running
if ! curl -s --fail -u "$N8N_AUTH_USER:$N8N_AUTH_PASS" "http://$N8N_HOST:$N8N_PORT/healthz" > /dev/null; then
    echo -e "${RED}❌ Error: n8n is not running or not accessible at http://$N8N_HOST:$N8N_PORT${NC}"
    echo "Please start n8n with: docker-compose up -d"
    exit 1
fi

echo -e "${GREEN}✅ n8n is running and accessible${NC}"

# Check if workflows directory exists
if [ ! -d "$WORKFLOWS_DIR" ]; then
    echo -e "${RED}❌ Error: Workflows directory not found: $WORKFLOWS_DIR${NC}"
    exit 1
fi

# Function to import a workflow
import_workflow() {
    local file_path="$1"
    local filename=$(basename "$file_path")
    local workflow_name=$(jq -r '.name // "Unknown"' "$file_path" 2>/dev/null || echo "Unknown")
    
    echo -e "${YELLOW}📤 Importing workflow: $workflow_name ($filename)${NC}"
    
    # Validate JSON syntax
    if ! jq '.' "$file_path" > /dev/null 2>&1; then
        echo -e "${RED}  ❌ Invalid JSON in file: $filename${NC}"
        return 1
    fi
    
    # Prepare workflow data for import
    workflow_data=$(jq '{
        name: .name,
        nodes: .nodes,
        connections: .connections,
        settings: .settings,
        staticData: .staticData,
        tags: .tags,
        active: false
    }' "$file_path")
    
    # Check if workflow already exists
    existing_workflow=$(curl -s -u "$N8N_AUTH_USER:$N8N_AUTH_PASS" "http://$N8N_HOST:$N8N_PORT/api/v1/workflows" | jq -r ".data[]? | select(.name == \"$workflow_name\") | .id")
    
    if [ -n "$existing_workflow" ] && [ "$existing_workflow" != "null" ]; then
        echo -e "${YELLOW}  ⚠️  Workflow already exists (ID: $existing_workflow). Updating...${NC}"
        
        # Update existing workflow
        response=$(curl -s -w "%{http_code}" -u "$N8N_AUTH_USER:$N8N_AUTH_PASS" \
            -X PUT \
            -H "Content-Type: application/json" \
            -d "$workflow_data" \
            "http://$N8N_HOST:$N8N_PORT/api/v1/workflows/$existing_workflow")
        
        http_code="${response: -3}"
        if [ "$http_code" = "200" ]; then
            echo -e "${GREEN}  ✅ Successfully updated workflow${NC}"
            return 0
        else
            echo -e "${RED}  ❌ Failed to update workflow (HTTP $http_code)${NC}"
            return 1
        fi
    else
        echo -e "${BLUE}  📝 Creating new workflow...${NC}"
        
        # Create new workflow
        response=$(curl -s -w "%{http_code}" -u "$N8N_AUTH_USER:$N8N_AUTH_PASS" \
            -X POST \
            -H "Content-Type: application/json" \
            -d "$workflow_data" \
            "http://$N8N_HOST:$N8N_PORT/api/v1/workflows")
        
        http_code="${response: -3}"
        if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
            echo -e "${GREEN}  ✅ Successfully created workflow${NC}"
            return 0
        else
            echo -e "${RED}  ❌ Failed to create workflow (HTTP $http_code)${NC}"
            echo -e "${RED}     Response: ${response%???}${NC}"
            return 1
        fi
    fi
}

# Import workflows by category
import_category() {
    local category="$1"
    local category_dir="$WORKFLOWS_DIR/$category"
    
    if [ ! -d "$category_dir" ]; then
        echo -e "${YELLOW}⚠️  Category directory not found: $category${NC}"
        return 0
    fi
    
    echo -e "${BLUE}📁 Importing $category workflows...${NC}"
    
    local count=0
    local success=0
    
    for workflow_file in "$category_dir"/*.json; do
        if [ -f "$workflow_file" ]; then
            count=$((count + 1))
            if import_workflow "$workflow_file"; then
                success=$((success + 1))
            fi
        fi
    done
    
    echo -e "${BLUE}   Category summary: $success/$count workflows imported successfully${NC}"
    echo ""
}

# Check for specific workflow argument
if [ $# -eq 1 ]; then
    workflow_file="$1"
    if [ -f "$workflow_file" ]; then
        echo -e "${BLUE}📤 Importing single workflow: $workflow_file${NC}"
        import_workflow "$workflow_file"
        exit $?
    else
        echo -e "${RED}❌ Error: File not found: $workflow_file${NC}"
        exit 1
    fi
fi

# Import all workflows by category
echo -e "${BLUE}🔄 Starting bulk workflow import...${NC}"
echo ""

total_start=$(date +%s)

# Import each category
import_category "support"
import_category "intelligence" 
import_category "content"
import_category "monitoring"

# Import any workflows in the root directory
echo -e "${BLUE}📁 Importing miscellaneous workflows...${NC}"
count=0
success=0

for workflow_file in "$WORKFLOWS_DIR"/*.json; do
    if [ -f "$workflow_file" ]; then
        count=$((count + 1))
        if import_workflow "$workflow_file"; then
            success=$((success + 1))
        fi
    fi
done

if [ $count -gt 0 ]; then
    echo -e "${BLUE}   Miscellaneous summary: $success/$count workflows imported successfully${NC}"
fi

total_end=$(date +%s)
total_time=$((total_end - total_start))

# Final summary
echo ""
echo -e "${BLUE}📊 Import Summary${NC}"
echo "=================="
echo -e "Import completed in: ${GREEN}${total_time}s${NC}"
echo ""

# Get final workflow count from n8n
workflow_count=$(curl -s -u "$N8N_AUTH_USER:$N8N_AUTH_PASS" "http://$N8N_HOST:$N8N_PORT/api/v1/workflows" | jq -r '.data | length')
echo -e "Total workflows in n8n: ${GREEN}$workflow_count${NC}"

echo ""
echo -e "${GREEN}🎉 Workflow import completed!${NC}"
echo ""
echo -e "${YELLOW}📝 Next steps:${NC}"
echo "1. Configure credentials in n8n UI"
echo "2. Test workflows with sample data"
echo "3. Activate workflows when ready"
echo "4. Monitor execution logs"
