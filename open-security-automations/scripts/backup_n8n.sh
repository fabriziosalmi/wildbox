#!/bin/bash

# Wildbox Open Security Automations - n8n Backup Script
# This script creates comprehensive backups of n8n data

set -e

# Configuration
BACKUP_DIR="$(dirname "$0")/../backups"
N8N_CONTAINER_NAME="${N8N_CONTAINER_NAME:-wildbox-automations-n8n}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🤖 Wildbox Automations - n8n Backup Script${NC}"
echo "=============================================="

# Create backup directory
mkdir -p "$BACKUP_DIR"/{full,workflows,data}

# Generate timestamp
timestamp=$(date '+%Y%m%d_%H%M%S')

echo -e "${BLUE}📅 Backup timestamp: $timestamp${NC}"

# Check if n8n container is running
if ! docker ps --format "table {{.Names}}" | grep -q "$N8N_CONTAINER_NAME"; then
    echo -e "${YELLOW}⚠️  Warning: n8n container is not running${NC}"
    echo -e "${YELLOW}   Proceeding with data volume backup only...${NC}"
    container_running=false
else
    echo -e "${GREEN}✅ n8n container is running${NC}"
    container_running=true
fi

# 1. Backup n8n data volume
echo -e "${BLUE}💾 Backing up n8n data volume...${NC}"
data_backup_file="$BACKUP_DIR/data/n8n_data_$timestamp.tar.gz"

docker run --rm \
    -v wildbox-automations_n8n_data:/data \
    -v "$BACKUP_DIR/data":/backup \
    alpine tar czf "/backup/n8n_data_$timestamp.tar.gz" -C /data .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Data volume backup created: $data_backup_file${NC}"
    data_size=$(du -h "$data_backup_file" | cut -f1)
    echo -e "${BLUE}   Size: $data_size${NC}"
else
    echo -e "${RED}❌ Failed to backup data volume${NC}"
    exit 1
fi

# 2. Export workflows (if container is running)
if [ "$container_running" = true ]; then
    echo -e "${BLUE}📋 Exporting workflows...${NC}"
    workflow_backup_file="$BACKUP_DIR/workflows/workflows_$timestamp.tar.gz"
    
    # Run workflow export script
    if [ -f "$(dirname "$0")/export_workflows.sh" ]; then
        "$(dirname "$0")/export_workflows.sh"
        
        # Create workflows backup
        if [ -d "$(dirname "$0")/../workflows" ]; then
            tar -czf "$workflow_backup_file" -C "$(dirname "$0")/../" workflows/
            echo -e "${GREEN}✅ Workflows backup created: $workflow_backup_file${NC}"
            workflow_size=$(du -h "$workflow_backup_file" | cut -f1)
            echo -e "${BLUE}   Size: $workflow_size${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Workflow export script not found, skipping...${NC}"
    fi
fi

# 3. Backup n8n database (if accessible)
if [ "$container_running" = true ]; then
    echo -e "${BLUE}🗄️  Backing up n8n database...${NC}"
    db_backup_file="$BACKUP_DIR/data/n8n_database_$timestamp.sqlite"
    
    # Copy database file from container
    docker cp "$N8N_CONTAINER_NAME:/home/node/.n8n/database.sqlite" "$db_backup_file" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Database backup created: $db_backup_file${NC}"
        db_size=$(du -h "$db_backup_file" | cut -f1)
        echo -e "${BLUE}   Size: $db_size${NC}"
        
        # Compress database backup
        gzip "$db_backup_file"
        echo -e "${GREEN}✅ Database backup compressed: ${db_backup_file}.gz${NC}"
    else
        echo -e "${YELLOW}⚠️  Could not backup database (SQLite file not accessible)${NC}"
    fi
fi

# 4. Create full backup archive
echo -e "${BLUE}📦 Creating full backup archive...${NC}"
full_backup_file="$BACKUP_DIR/full/wildbox_automations_full_backup_$timestamp.tar.gz"

# Include configuration files in full backup
config_files=()
if [ -f "$(dirname "$0")/../docker-compose.yml" ]; then
    config_files+=("docker-compose.yml")
fi
if [ -f "$(dirname "$0")/../.env" ]; then
    config_files+=(".env")
fi

# Create full backup
tar -czf "$full_backup_file" \
    -C "$(dirname "$0")/../" \
    "${config_files[@]}" \
    backups/data \
    backups/workflows 2>/dev/null || true

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Full backup archive created: $full_backup_file${NC}"
    full_size=$(du -h "$full_backup_file" | cut -f1)
    echo -e "${BLUE}   Size: $full_size${NC}"
else
    echo -e "${RED}❌ Failed to create full backup archive${NC}"
fi

# 5. Generate backup manifest
echo -e "${BLUE}📋 Generating backup manifest...${NC}"
manifest_file="$BACKUP_DIR/backup_manifest_$timestamp.json"

cat > "$manifest_file" << EOF
{
  "backup_info": {
    "timestamp": "$timestamp",
    "date": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "backup_type": "full",
    "n8n_container_running": $container_running
  },
  "files": {
    "data_volume": {
      "file": "data/n8n_data_$timestamp.tar.gz",
      "size": "$([ -f "$data_backup_file" ] && du -b "$data_backup_file" | cut -f1 || echo "0")",
      "created": $([ -f "$data_backup_file" ] && echo "true" || echo "false")
    },
    "workflows": {
      "file": "workflows/workflows_$timestamp.tar.gz",
      "size": "$([ -f "$workflow_backup_file" ] && du -b "$workflow_backup_file" | cut -f1 || echo "0")",
      "created": $([ -f "$workflow_backup_file" ] && echo "true" || echo "false")
    },
    "database": {
      "file": "data/n8n_database_$timestamp.sqlite.gz",
      "size": "$([ -f "${db_backup_file}.gz" ] && du -b "${db_backup_file}.gz" | cut -f1 || echo "0")",
      "created": $([ -f "${db_backup_file}.gz" ] && echo "true" || echo "false")
    },
    "full_archive": {
      "file": "full/wildbox_automations_full_backup_$timestamp.tar.gz",
      "size": "$([ -f "$full_backup_file" ] && du -b "$full_backup_file" | cut -f1 || echo "0")",
      "created": $([ -f "$full_backup_file" ] && echo "true" || echo "false")
    }
  },
  "environment": {
    "docker_version": "$(docker --version 2>/dev/null || echo "unknown")",
    "n8n_container": "$N8N_CONTAINER_NAME",
    "backup_script_version": "1.0.0"
  }
}
EOF

echo -e "${GREEN}✅ Backup manifest created: $manifest_file${NC}"

# 6. Clean up old backups
echo -e "${BLUE}🧹 Cleaning up old backups (older than $BACKUP_RETENTION_DAYS days)...${NC}"

# Clean old files
find "$BACKUP_DIR" -name "*.tar.gz" -type f -mtime "+$BACKUP_RETENTION_DAYS" -delete 2>/dev/null || true
find "$BACKUP_DIR" -name "*.sqlite.gz" -type f -mtime "+$BACKUP_RETENTION_DAYS" -delete 2>/dev/null || true
find "$BACKUP_DIR" -name "*.json" -type f -mtime "+$BACKUP_RETENTION_DAYS" -delete 2>/dev/null || true

# Count remaining backups
backup_count=$(find "$BACKUP_DIR" -name "*$timestamp*" | wc -l)
total_backups=$(find "$BACKUP_DIR" -name "*.tar.gz" | wc -l)

echo -e "${GREEN}✅ Cleanup completed${NC}"

# 7. Final summary
echo ""
echo -e "${BLUE}📊 Backup Summary${NC}"
echo "=================="
echo -e "Backup timestamp: ${GREEN}$timestamp${NC}"
echo -e "Files created in this backup: ${GREEN}$backup_count${NC}"
echo -e "Total backup files retained: ${GREEN}$total_backups${NC}"
echo -e "Backup location: ${GREEN}$BACKUP_DIR${NC}"
echo ""

if [ "$container_running" = true ]; then
    echo -e "${GREEN}✅ Full backup completed successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  Partial backup completed (container not running)${NC}"
fi

echo ""
echo -e "${BLUE}📝 Restore Instructions:${NC}"
echo "To restore from this backup:"
echo "1. Stop n8n: docker-compose down"
echo "2. Restore data: docker run --rm -v wildbox-automations_n8n_data:/data -v $BACKUP_DIR/data:/backup alpine tar xzf /backup/n8n_data_$timestamp.tar.gz -C /data"
echo "3. Start n8n: docker-compose up -d"
echo "4. Import workflows: ./scripts/import_workflows.sh"
