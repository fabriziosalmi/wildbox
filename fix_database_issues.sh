#!/bin/bash

# Fix Database Issues for Wildbox Security Platform
# =================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

main() {
    echo "🔧 Fixing Database Issues for Wildbox Security Platform"
    echo "======================================================="
    echo ""
    
    # Check if PostgreSQL container is running
    if ! docker-compose ps postgres | grep -q "Up"; then
        error "PostgreSQL container is not running. Starting it..."
        docker-compose up -d postgres
        sleep 5
    fi
    
    # Wait for PostgreSQL to be ready
    log "Waiting for PostgreSQL to be ready..."
    for i in {1..30}; do
        if docker-compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
            success "PostgreSQL is ready"
            break
        fi
        echo -n "."
        sleep 1
    done
    echo ""
    
    # Create missing databases
    log "Creating missing databases..."
    
    # List of databases that need to exist
    databases=("data" "guardian" "identity")
    
    for db in "${databases[@]}"; do
        log "Checking database: $db"
        if docker-compose exec -T postgres psql -U postgres -lqt | cut -d \| -f 1 | grep -qw "$db"; then
            success "Database '$db' already exists"
        else
            log "Creating database: $db"
            if docker-compose exec -T postgres createdb -U postgres "$db"; then
                success "Created database: $db"
            else
                warn "Failed to create database: $db (might already exist)"
            fi
        fi
    done
    
    # Create users for each service if they don't exist
    log "Setting up database users..."
    
    # Guardian user
    docker-compose exec -T postgres psql -U postgres -c "
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = 'guardian') THEN
                CREATE USER guardian WITH PASSWORD 'guardian_password';
                GRANT ALL PRIVILEGES ON DATABASE guardian TO guardian;
            END IF;
        END
        \$\$;" 2>/dev/null || warn "Guardian user setup issue"
    
    # Identity user  
    docker-compose exec -T postgres psql -U postgres -c "
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = 'identity_user') THEN
                CREATE USER identity_user WITH PASSWORD 'identity_pass';
                GRANT ALL PRIVILEGES ON DATABASE identity TO identity_user;
            END IF;
        END
        \$\$;" 2>/dev/null || warn "Identity user setup issue"
    
    # Data service user
    docker-compose exec -T postgres psql -U postgres -c "
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = 'secdata') THEN
                CREATE USER secdata WITH PASSWORD 'secdata123';
                GRANT ALL PRIVILEGES ON DATABASE data TO secdata;
            END IF;
        END
        \$\$;" 2>/dev/null || warn "Data user setup issue"
    
    success "Database setup complete!"
    
    # Restart services that had database issues
    log "Restarting services with database dependencies..."
    docker-compose restart data guardian identity || warn "Some services failed to restart"
    
    # Wait a bit for services to restart
    sleep 10
    
    # Check if data service is now working
    log "Checking data service health..."
    if curl -s http://localhost:8002/health >/dev/null; then
        success "Data service is now healthy!"
    else
        warn "Data service may still have issues. Check logs with: docker-compose logs data"
    fi
    
    echo ""
    success "Database fix complete! Services should now be accessible."
    echo ""
    echo "Next steps:"
    echo "  • Run health check: make health"
    echo "  • Check service logs: docker-compose logs [service-name]"
    echo "  • Access services: ../comprehensive_health_check.sh urls"
}

main "$@"
