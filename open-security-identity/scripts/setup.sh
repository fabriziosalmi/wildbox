#!/bin/bash
set -e

echo "🚀 Wildbox Identity Service - Quick Setup"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi

print_status "Docker is running"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    print_error "docker-compose is not installed. Please install it first."
    exit 1
fi

print_status "docker-compose is available"

# Stop any existing containers
echo ""
echo "🧹 Cleaning up existing containers..."
docker-compose down -v

print_status "Existing containers stopped"

# Build and start services
echo ""
echo "🔨 Building and starting services..."
echo "This may take a few minutes on first run..."

docker-compose up --build -d

print_status "Services starting..."

# Wait for services to be ready
echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check if identity service is responding
echo ""
echo "🔍 Testing service endpoints..."

# Wait for the service to be ready
RETRY_COUNT=0
MAX_RETRIES=30

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -s -f http://localhost:8001/health > /dev/null 2>&1; then
        print_status "Identity service is responding"
        break
    else
        echo "Waiting for identity service... (attempt $((RETRY_COUNT + 1))/$MAX_RETRIES)"
        sleep 5
        RETRY_COUNT=$((RETRY_COUNT + 1))
    fi
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    print_error "Identity service did not start properly"
    echo ""
    echo "📋 Container logs:"
    docker-compose logs identity
    exit 1
fi

# Test endpoints
echo ""
echo "🧪 Testing key endpoints..."

# Test health endpoint
if curl -s http://localhost:8001/health | grep -q "healthy"; then
    print_status "Health endpoint working"
else
    print_warning "Health endpoint may have issues"
fi

# Test documentation
if curl -s -f http://localhost:8001/docs > /dev/null 2>&1; then
    print_status "API documentation available"
else
    print_warning "API documentation may have issues"
fi

# Show service information
echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Service Information:"
echo "======================="
echo "• Identity Service: http://localhost:8001"
echo "• API Documentation: http://localhost:8001/docs" 
echo "• PostgreSQL: localhost:5434"
echo "• Redis: localhost:6384"
echo ""
echo "🔑 Default Admin Credentials:"
echo "• Email: admin@wildbox.security"
echo "• Password: ChangeMeInProduction123!"
echo ""
echo "⚠️  IMPORTANT: Change the default admin password after first login!"
echo ""
echo "📖 Useful Commands:"
echo "• View logs: docker-compose logs -f identity"
echo "• Stop services: docker-compose down"
echo "• Restart services: docker-compose restart"
echo "• Access database: psql -h localhost -p 5434 -U postgres -d identity"
echo ""

# Test registration endpoint
echo "🧪 Testing FastAPI Users endpoints..."
echo ""

# Test registration
echo "Testing registration endpoint..."
REGISTER_RESPONSE=$(curl -s -X POST "http://localhost:8001/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"testpassword123"}' || echo "error")

if echo "$REGISTER_RESPONSE" | grep -q "email"; then
    print_status "Registration endpoint working"
    echo "  Sample user created: test@example.com"
else
    print_warning "Registration endpoint may have issues"
    echo "  Response: $REGISTER_RESPONSE"
fi

echo ""
print_status "FastAPI Users migration setup is complete!"
print_warning "The new authentication system is now active with all FastAPI Users features."
