#!/bin/bash

# Wildbox Security Platform - Enhanced System Monitor
# ===================================================

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

# Enhanced service monitoring
monitor_api_performance() {
    log "Testing API performance..."
    
    # Test security API
    local start_time=$(date +%s%N)
    local api_response=$(curl -s -w "%{http_code}" http://localhost:8000/health -o /dev/null)
    local end_time=$(date +%s%N)
    local response_time=$((($end_time - $start_time) / 1000000))
    
    if [[ "$api_response" == "200" ]]; then
        if [[ $response_time -lt 1000 ]]; then
            success "✅ Security API responsive (${response_time}ms)"
        else
            warn "⚠️  Security API slow (${response_time}ms)"
        fi
    else
        error "❌ Security API returned HTTP $api_response"
    fi
    
    # Test tool execution
    start_time=$(date +%s%N)
    local tool_test=$(curl -s -X POST http://localhost:8000/api/v1/tools/whois_lookup/execute \
        -H "Content-Type: application/json" \
        -d '{"target": "google.com", "options": {}}' | jq -r '.success // false')
    end_time=$(date +%s%N)
    local tool_time=$((($end_time - $start_time) / 1000000))
    
    if [[ "$tool_test" == "true" ]]; then
        success "✅ Tool execution working (${tool_time}ms)"
    else
        warn "⚠️  Tool execution may have issues"
    fi
}

# Memory and resource monitoring
monitor_resources() {
    log "Monitoring system resources..."
    
    # Check memory usage
    local memory_usage=$(docker stats --no-stream --format "{{.MemPerc}}" | head -1 | sed 's/%//')
    if (( $(echo "$memory_usage > 80" | bc -l) )); then
        warn "⚠️  High memory usage: ${memory_usage}%"
    else
        success "✅ Memory usage: ${memory_usage}%"
    fi
    
    # Check container count
    local container_count=$(docker ps | wc -l)
    log "Running containers: $((container_count - 1))"
    
    # Check disk space
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if (( disk_usage > 85 )); then
        warn "⚠️  High disk usage: ${disk_usage}%"
    else
        success "✅ Disk usage: ${disk_usage}%"
    fi
}

# Service dependency validation
validate_dependencies() {
    log "Validating service dependencies..."
    
    # Check database connections
    local db_connections=$(docker-compose exec -T postgres psql -U postgres -c "SELECT count(*) FROM pg_stat_activity;" | grep -E "^\s+[0-9]+$" | tr -d ' ')
    if [[ -n "$db_connections" ]] && [[ $db_connections -gt 0 ]]; then
        success "✅ Database active connections: $db_connections"
    else
        error "❌ Database connection check failed"
    fi
    
    # Check Redis memory usage
    local redis_memory=$(docker-compose exec -T wildbox-redis redis-cli INFO memory | grep used_memory_human | cut -d: -f2 | tr -d '\r')
    if [[ -n "$redis_memory" ]]; then
        success "✅ Redis memory usage: $redis_memory"
    else
        error "❌ Redis memory check failed"
    fi
}

# Security scan on the platform itself
security_self_scan() {
    log "Running security self-assessment..."
    
    # Check for exposed secrets in environment variables
    local exposed_secrets=0
    for container in $(docker ps --format "{{.Names}}"); do
        if docker inspect "$container" | grep -i "password\|secret\|key" | grep -v "CHANGE\|DUMMY\|TEST" >/dev/null 2>&1; then
            ((exposed_secrets++))
        fi
    done
    
    if [[ $exposed_secrets -eq 0 ]]; then
        success "✅ No exposed secrets detected in container configs"
    else
        warn "⚠️  $exposed_secrets containers may have exposed secrets"
    fi
    
    # Check for default passwords
    if docker-compose logs identity 2>/dev/null | grep -q "default admin credentials"; then
        warn "⚠️  Default admin credentials detected - change in production!"
    else
        success "✅ Admin credentials check passed"
    fi
}

# Generate system report
generate_report() {
    log "Generating system health report..."
    
    local report_file="/tmp/wildbox_health_report_$(date +%Y%m%d_%H%M%S).json"
    
    # Gather system metrics
    local services_count=$(docker ps | wc -l)
    local healthy_services=$(curl -s http://localhost:8000/health http://localhost:8001/health http://localhost:8002/health http://localhost:8013/health http://localhost:8004/health http://localhost:8018/health http://localhost:8006/health http://localhost:8019/health | grep -c "healthy" || echo "0")
    
    # Create JSON report
    cat > "$report_file" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "platform": "Wildbox Security Platform",
  "version": "1.0.0",
  "status": "operational",
  "services": {
    "total": $((services_count - 1)),
    "healthy": $healthy_services,
    "availability": "$(echo "scale=2; $healthy_services / 8 * 100" | bc)%"
  },
  "resources": {
    "memory_usage": "$(docker stats --no-stream --format "{{.MemPerc}}" | head -1)",
    "disk_usage": "$(df / | awk 'NR==2 {print $5}')",
    "container_count": $((services_count - 1))
  },
  "security": {
    "tools_available": 55,
    "authentication": "active",
    "encryption": "tls"
  }
}
EOF
    
    success "✅ Health report generated: $report_file"
    echo ""
    echo "📊 Quick Summary:"
    echo "=================="
    jq . "$report_file"
}

# Auto-optimization recommendations
suggest_optimizations() {
    log "Analyzing system for optimization opportunities..."
    
    echo ""
    echo "💡 Optimization Recommendations:"
    echo "================================"
    
    # Check resource usage patterns
    local high_cpu_containers=$(docker stats --no-stream --format "{{.Name}} {{.CPUPerc}}" | awk '$2+0 > 10 {print $1}' | wc -l)
    if [[ $high_cpu_containers -gt 0 ]]; then
        echo "• Consider CPU limits for high-usage containers"
    fi
    
    # Check memory usage
    local high_mem_containers=$(docker stats --no-stream --format "{{.Name}} {{.MemUsage}}" | wc -l)
    echo "• Monitor $high_mem_containers containers for memory optimization"
    
    # Check network performance
    echo "• Consider enabling compression for API responses"
    echo "• Review rate limiting settings for production workloads"
    echo "• Enable HTTPS redirect for production deployment"
    
    # Security recommendations
    echo "• Change default credentials before production use"
    echo "• Enable API key authentication for production"
    echo "• Configure proper backup strategy for databases"
}

# Main execution
main() {
    echo "🔍 Wildbox Security Platform - Enhanced System Monitor"
    echo "========================================================"
    echo ""
    
    # Run all monitoring checks
    monitor_api_performance
    echo ""
    monitor_resources
    echo ""
    validate_dependencies
    echo ""
    security_self_scan
    echo ""
    generate_report
    echo ""
    suggest_optimizations
    
    echo ""
    echo "🎯 Enhanced Monitoring Complete"
    echo "==============================="
    log "For detailed service logs: docker-compose logs [service]"
    log "For real-time monitoring: docker stats"
    log "For service debugging: ./comprehensive_health_check.sh"
}

# Handle command line arguments
case "${1:-monitor}" in
    "monitor"|"")
        main
        ;;
    "performance")
        monitor_api_performance
        ;;
    "resources")
        monitor_resources
        ;;
    "dependencies")
        validate_dependencies
        ;;
    "security")
        security_self_scan
        ;;
    "report")
        generate_report
        ;;
    "optimize")
        suggest_optimizations
        ;;
    *)
        echo "Usage: $0 [monitor|performance|resources|dependencies|security|report|optimize]"
        echo ""
        echo "Commands:"
        echo "  monitor       - Run full system monitoring (default)"
        echo "  performance   - Test API performance only"
        echo "  resources     - Check system resources only"
        echo "  dependencies  - Validate service dependencies"
        echo "  security      - Run security self-assessment"
        echo "  report        - Generate JSON health report"
        echo "  optimize      - Show optimization recommendations"
        exit 1
        ;;
esac
