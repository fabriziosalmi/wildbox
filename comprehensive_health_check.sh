#!/bin/bash

# Wildbox Security Platform - Health Check & Auto-Fix Script
# ==========================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARN:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS:${NC} $1"
}

# Service configuration (using simple arrays for macOS compatibility)
SERVICES="api:8000 identity:8001 data:8002 guardian:8013 sensor:8004 responder:8005 agents:8006 cspm:8007 dashboard:3000 automations:5678"

# Function to check if a service is responding
check_service() {
    local service=$1
    local port=$2
    local endpoint="http://localhost:${port}"
    
    if [[ "$service" == "dashboard" ]]; then
        endpoint="http://localhost:${port}"
    elif [[ "$service" == "automations" ]]; then
        endpoint="http://localhost:${port}"
    elif [[ "$service" == "sensor" ]]; then
        endpoint="http://localhost:${port}/health"
    else
        endpoint="http://localhost:${port}/health"
    fi
    
    if curl -s --max-time 5 "$endpoint" >/dev/null 2>&1; then
        success "✅ $service service is healthy ($port)"
        return 0
    else
        error "❌ $service service is not responding ($port)"
        return 1
    fi
}

# Function to check container status
check_containers() {
    log "Checking container status..."
    
    # Get all containers from the docker-compose setup
    local containers
    containers=$(docker-compose ps --format "table {{.Name}}\t{{.State}}\t{{.Ports}}" 2>/dev/null || echo "No containers found")
    
    echo "$containers"
    echo ""
    
    # Count unhealthy containers
    local unhealthy=0
    while IFS= read -r line; do
        if [[ "$line" == *"Exit"* ]] || [[ "$line" == *"Down"* ]]; then
            unhealthy=$((unhealthy + 1))
            warn "Container issue detected: $line"
        fi
    done <<< "$containers"
    
    if [[ $unhealthy -eq 0 ]]; then
        success "All containers are running"
    else
        warn "$unhealthy containers have issues"
    fi
}

# Function to check database connectivity
check_databases() {
    log "Checking database connectivity..."
    
    # Check PostgreSQL
    if docker-compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
        success "✅ PostgreSQL is healthy"
        
        # Check if required databases exist
        local missing_dbs=()
        
        # Check for 'data' database (based on error in logs)
        if ! docker-compose exec -T postgres psql -U postgres -lqt | cut -d \| -f 1 | grep -qw data; then
            missing_dbs+=("data")
        fi
        
        if [[ ${#missing_dbs[@]} -gt 0 ]]; then
            warn "Missing databases: ${missing_dbs[*]}"
            log "Creating missing databases..."
            for db in "${missing_dbs[@]}"; do
                docker-compose exec -T postgres createdb -U postgres "$db" || warn "Failed to create database: $db"
            done
        fi
    else
        error "❌ PostgreSQL is not responding"
    fi
    
    # Check Redis instance (consolidated)
    if docker-compose exec -T wildbox-redis redis-cli ping >/dev/null 2>&1; then
        success "✅ wildbox-redis is healthy"
    else
        error "❌ wildbox-redis is not responding"
    fi
}

# Function to check service health endpoints
check_service_health() {
    log "Checking service health endpoints..."
    
    local failed_services=()
    
    for service_port in $SERVICES; do
        local service=$(echo "$service_port" | cut -d: -f1)
        local port=$(echo "$service_port" | cut -d: -f2)
        if ! check_service "$service" "$port"; then
            failed_services+=("$service")
        fi
    done
    
    if [[ ${#failed_services[@]} -eq 0 ]]; then
        success "All services are healthy"
    else
        warn "Failed services: ${failed_services[*]}"
    fi
}

# Function to check and fix specific issues from logs
fix_known_issues() {
    log "Checking for known issues and applying fixes..."
    
    # Fix 1: Gateway nginx config issue
    if docker-compose logs gateway 2>/dev/null | grep -q "host not found in upstream"; then
        warn "Detected nginx upstream host resolution issue in gateway"
        log "Restarting gateway service..."
        docker-compose restart gateway || warn "Failed to restart gateway"
    fi
    
    # Fix 2: Data service database connection
    if docker-compose logs data 2>/dev/null | grep -q "database.*does not exist"; then
        warn "Detected missing database for data service"
        log "Creating missing databases..."
        docker-compose exec -T postgres createdb -U postgres data 2>/dev/null || warn "Database might already exist"
        log "Restarting data service..."
        docker-compose restart data || warn "Failed to restart data service"
    fi
    
    # Fix 3: Missing Python dependencies
    if docker-compose logs api 2>/dev/null | grep -q "No module named"; then
        warn "Detected missing Python dependencies"
        log "Consider rebuilding API container with updated requirements"
    fi
    
    # Fix 4: Sensor osquery table issues
    if docker-compose logs sensor 2>/dev/null | grep -q "no such table: services"; then
        warn "Sensor osquery compatibility issue detected (Linux container trying to query Windows/macOS specific tables)"
        log "This is expected in containerized environments - sensor will continue with available tables"
    fi
    
    # Fix 5: Sensor data lake connectivity
    if docker-compose logs sensor 2>/dev/null | grep -q "Cannot connect to host your-security-data-platform.com"; then
        warn "Sensor cannot connect to external data platform"
        log "This is expected with default config - update sensor config for production use"
    fi
}

# Function to show resource usage
show_resource_usage() {
    log "Checking resource usage..."
    
    if command -v docker >/dev/null 2>&1; then
        echo "Container Resource Usage:"
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" 2>/dev/null || warn "Could not get container stats"
        echo ""
    fi
    
    # System resources
    echo "System Resources:"
    echo "Memory: $(free -h 2>/dev/null | grep Mem | awk '{print $3 "/" $2}' || echo "N/A")"
    echo "Disk: $(df -h / 2>/dev/null | tail -1 | awk '{print $3 "/" $2 " (" $5 " used)"}' || echo "N/A")"
    echo ""
}

# Function to provide service URLs
show_service_urls() {
    log "Service Access URLs:"
    echo ""
    echo "🌐 Web Interfaces:"
    echo "  • Main Dashboard:    http://localhost:3000"
    echo "  • API Documentation: http://localhost:8000/docs"
    echo "  • API Interface:     http://localhost:8000"
    echo "  • n8n Automations:   http://localhost:5678"
    echo ""
    echo "🔌 API Services:"
    echo "  • Security API:      http://localhost:8000"
    echo "  • Identity Service:  http://localhost:8001"
    echo "  • Data Service:      http://localhost:8002"
    echo "  • Guardian:          http://localhost:8003"
    echo "  • Sensor:            http://localhost:8004"
    echo "  • Responder:         http://localhost:8005"
    echo "  • Agents:            http://localhost:8006"
    echo "  • CSPM:              http://localhost:8007"
    echo ""
}

# Main execution
main() {
    echo "🏥 Wildbox Security Platform - Health Check & Auto-Fix"
    echo "======================================================"
    echo ""
    
    # Check if docker-compose is available
    if ! command -v docker-compose >/dev/null 2>&1; then
        error "docker-compose is not installed or not in PATH"
        exit 1
    fi
    
    # Check if we're in the right directory
    if [[ ! -f "docker-compose.yml" ]]; then
        error "docker-compose.yml not found. Please run this script from the wildbox directory."
        exit 1
    fi
    
    # Run all checks
    check_containers
    echo ""
    check_databases
    echo ""
    check_service_health
    echo ""
    fix_known_issues
    echo ""
    show_resource_usage
    show_service_urls
    
    # Summary
    echo "🎯 Health Check Complete"
    echo "========================"
    log "For detailed logs, run: docker-compose logs [service-name]"
    log "To restart a service, run: docker-compose restart [service-name]"
    log "To view live logs, run: docker-compose logs -f"
}

# Handle command line arguments
case "${1:-check}" in
    "check"|"")
        main
        ;;
    "fix")
        log "Running auto-fix for known issues..."
        fix_known_issues
        ;;
    "services")
        check_service_health
        ;;
    "containers")
        check_containers
        ;;
    "databases")
        check_databases
        ;;
    "urls")
        show_service_urls
        ;;
    *)
        echo "Usage: $0 [check|fix|services|containers|databases|urls]"
        echo ""
        echo "Commands:"
        echo "  check       - Run full health check (default)"
        echo "  fix         - Apply auto-fixes for known issues"
        echo "  services    - Check service health endpoints only"
        echo "  containers  - Check container status only"
        echo "  databases   - Check database connectivity only"
        echo "  urls        - Show service access URLs"
        exit 1
        ;;
esac
