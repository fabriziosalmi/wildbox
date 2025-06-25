#!/bin/bash

# Wildbox Open Security Automations - Workflow Export Script
# This script exports all workflows from n8n to JSON files for version control

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

echo -e "${BLUE}🤖 Wildbox Automations - Workflow Export Script${NC}"
echo "=================================================="

# Check if n8n is running
if ! curl -s --fail -u "$N8N_AUTH_USER:$N8N_AUTH_PASS" "http://$N8N_HOST:$N8N_PORT/healthz" > /dev/null; then
    echo -e "${RED}❌ Error: n8n is not running or not accessible at http://$N8N_HOST:$N8N_PORT${NC}"
    echo "Please start n8n with: docker-compose up -d"
    exit 1
fi

echo -e "${GREEN}✅ n8n is running and accessible${NC}"

# Create workflows directory if it doesn't exist
mkdir -p "$WORKFLOWS_DIR/support"
mkdir -p "$WORKFLOWS_DIR/intelligence"
mkdir -p "$WORKFLOWS_DIR/content"
mkdir -p "$WORKFLOWS_DIR/monitoring"

# Get list of all workflows
echo -e "${BLUE}📋 Fetching workflow list...${NC}"
WORKFLOWS_JSON=$(curl -s -u "$N8N_AUTH_USER:$N8N_AUTH_PASS" "http://$N8N_HOST:$N8N_PORT/api/v1/workflows")

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Error: Failed to fetch workflows from n8n API${NC}"
    exit 1
fi

# Parse workflows and export each one
echo "$WORKFLOWS_JSON" | jq -r '.data[]? | "\(.id)|\(.name)"' | while IFS='|' read -r workflow_id workflow_name; do
    if [ -z "$workflow_id" ]; then
        continue
    fi
    
    echo -e "${YELLOW}📥 Exporting workflow: $workflow_name (ID: $workflow_id)${NC}"
    
    # Determine target directory based on workflow name/tags
    target_dir="$WORKFLOWS_DIR"
    if [[ "$workflow_name" == *"Support"* ]] || [[ "$workflow_name" == *"Ticket"* ]]; then
        target_dir="$WORKFLOWS_DIR/support"
    elif [[ "$workflow_name" == *"OSINT"* ]] || [[ "$workflow_name" == *"Intelligence"* ]] || [[ "$workflow_name" == *"Honeypot"* ]]; then
        target_dir="$WORKFLOWS_DIR/intelligence"
    elif [[ "$workflow_name" == *"Content"* ]] || [[ "$workflow_name" == *"Blog"* ]] || [[ "$workflow_name" == *"Report"* ]]; then
        target_dir="$WORKFLOWS_DIR/content"
    elif [[ "$workflow_name" == *"Monitor"* ]] || [[ "$workflow_name" == *"Health"* ]] || [[ "$workflow_name" == *"Alert"* ]]; then
        target_dir="$WORKFLOWS_DIR/monitoring"
    fi
    
    # Clean filename
    filename=$(echo "$workflow_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g' | sed 's/__*/_/g' | sed 's/^_\|_$//g')
    
    # Export workflow
    workflow_data=$(curl -s -u "$N8N_AUTH_USER:$N8N_AUTH_PASS" "http://$N8N_HOST:$N8N_PORT/api/v1/workflows/$workflow_id")
    
    if [ $? -eq 0 ]; then
        echo "$workflow_data" | jq '.' > "$target_dir/$filename.json"
        echo -e "${GREEN}  ✅ Exported to: $target_dir/$filename.json${NC}"
    else
        echo -e "${RED}  ❌ Failed to export workflow: $workflow_name${NC}"
    fi
done

# Create backup with timestamp
backup_dir="$(dirname "$0")/../backups/workflows"
mkdir -p "$backup_dir"
timestamp=$(date '+%Y%m%d_%H%M%S')
backup_file="$backup_dir/workflows_backup_$timestamp.tar.gz"

echo -e "${BLUE}💾 Creating backup...${NC}"
tar -czf "$backup_file" -C "$WORKFLOWS_DIR" .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Backup created: $backup_file${NC}"
else
    echo -e "${RED}❌ Failed to create backup${NC}"
fi

# Generate workflow inventory
inventory_file="$WORKFLOWS_DIR/README.md"
echo -e "${BLUE}📊 Generating workflow inventory...${NC}"

cat > "$inventory_file" << EOF
# Wildbox Automations - Workflow Inventory

*Auto-generated on $(date)*

## 📁 Workflow Categories

### Support Workflows
EOF

find "$WORKFLOWS_DIR/support" -name "*.json" -type f | while read -r file; do
    filename=$(basename "$file" .json)
    workflow_name=$(jq -r '.name // "Unknown"' "$file" 2>/dev/null || echo "Unknown")
    echo "- **$workflow_name** - \`$filename.json\`" >> "$inventory_file"
done

cat >> "$inventory_file" << EOF

### Intelligence Workflows
EOF

find "$WORKFLOWS_DIR/intelligence" -name "*.json" -type f | while read -r file; do
    filename=$(basename "$file" .json)
    workflow_name=$(jq -r '.name // "Unknown"' "$file" 2>/dev/null || echo "Unknown")
    echo "- **$workflow_name** - \`$filename.json\`" >> "$inventory_file"
done

cat >> "$inventory_file" << EOF

### Content Workflows
EOF

find "$WORKFLOWS_DIR/content" -name "*.json" -type f | while read -r file; do
    filename=$(basename "$file" .json)
    workflow_name=$(jq -r '.name // "Unknown"' "$file" 2>/dev/null || echo "Unknown")
    echo "- **$workflow_name** - \`$filename.json\`" >> "$inventory_file"
done

cat >> "$inventory_file" << EOF

### Monitoring Workflows
EOF

find "$WORKFLOWS_DIR/monitoring" -name "*.json" -type f | while read -r file; do
    filename=$(basename "$file" .json)
    workflow_name=$(jq -r '.name // "Unknown"' "$file" 2>/dev/null || echo "Unknown")
    echo "- **$workflow_name** - \`$filename.json\`" >> "$inventory_file"
done

cat >> "$inventory_file" << EOF

## 🔄 Workflow Management

- **Export**: \`./scripts/export_workflows.sh\`
- **Import**: \`./scripts/import_workflows.sh\`
- **Backup**: \`./scripts/backup_n8n.sh\`

## 📝 Notes

- Workflows are automatically categorized based on their names
- Each export creates a timestamped backup
- Always test workflows in development before deploying to production
- Credentials are not exported and must be configured separately

---
*Last updated: $(date)*
EOF

echo -e "${GREEN}✅ Workflow inventory updated: $inventory_file${NC}"

# Summary
workflow_count=$(find "$WORKFLOWS_DIR" -name "*.json" -type f | wc -l)
echo ""
echo -e "${BLUE}📊 Export Summary${NC}"
echo "=================="
echo -e "Total workflows exported: ${GREEN}$workflow_count${NC}"
echo -e "Backup created: ${GREEN}$backup_file${NC}"
echo -e "Inventory updated: ${GREEN}$inventory_file${NC}"
echo ""
echo -e "${GREEN}🎉 Workflow export completed successfully!${NC}"
