#!/bin/bash

# Open Security Guardian - Development Setup Script
# This script sets up a complete development environment

set -e

echo "🚀 Setting up Open Security Guardian development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    print_status "Detected macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    print_status "Detected Linux"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

# Check for required tools
check_requirements() {
    print_status "Checking requirements..."
    
    # Check for Python 3.11+
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        if [[ $(echo "$PYTHON_VERSION >= 3.11" | bc -l) -eq 1 ]]; then
            print_success "Python $PYTHON_VERSION found"
        else
            print_error "Python 3.11+ required, found $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 not found. Please install Python 3.11+"
        exit 1
    fi
    
    # Check for pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 not found. Please install pip"
        exit 1
    fi
    
    # Check for git
    if ! command -v git &> /dev/null; then
        print_error "git not found. Please install git"
        exit 1
    fi
    
    # Check for Docker (optional but recommended)
    if command -v docker &> /dev/null; then
        print_success "Docker found"
        DOCKER_AVAILABLE=true
    else
        print_warning "Docker not found. Some features may not work."
        DOCKER_AVAILABLE=false
    fi
    
    # Check for Docker Compose
    if command -v docker-compose &> /dev/null; then
        print_success "Docker Compose found"
        DOCKER_COMPOSE_AVAILABLE=true
    else
        print_warning "Docker Compose not found."
        DOCKER_COMPOSE_AVAILABLE=false
    fi
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    if [[ "$OS" == "macos" ]]; then
        # Check for Homebrew
        if ! command -v brew &> /dev/null; then
            print_status "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        # Install dependencies
        brew update
        brew install postgresql redis libpq pkg-config
        
        # Start services
        brew services start postgresql
        brew services start redis
        
    elif [[ "$OS" == "linux" ]]; then
        # Detect Linux distribution
        if [[ -f /etc/debian_version ]]; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y postgresql postgresql-contrib redis-server python3-dev libpq-dev pkg-config
            sudo systemctl start postgresql
            sudo systemctl start redis-server
            sudo systemctl enable postgresql
            sudo systemctl enable redis-server
        elif [[ -f /etc/redhat-release ]]; then
            # RHEL/CentOS/Fedora
            sudo yum install -y postgresql-server postgresql-contrib redis python3-devel postgresql-devel pkgconfig
            sudo systemctl start postgresql
            sudo systemctl start redis
            sudo systemctl enable postgresql
            sudo systemctl enable redis
        else
            print_warning "Unknown Linux distribution. Please install PostgreSQL and Redis manually."
        fi
    fi
}

# Setup PostgreSQL database
setup_database() {
    print_status "Setting up PostgreSQL database..."
    
    # Create database user and database
    if [[ "$OS" == "macos" ]]; then
        createuser -s guardian 2>/dev/null || true
        createdb guardian 2>/dev/null || true
        psql -c "ALTER USER guardian PASSWORD 'guardian';" 2>/dev/null || true
    else
        sudo -u postgres createuser -s guardian 2>/dev/null || true
        sudo -u postgres createdb guardian 2>/dev/null || true
        sudo -u postgres psql -c "ALTER USER guardian PASSWORD 'guardian';" 2>/dev/null || true
    fi
    
    print_success "Database setup completed"
}

# Create Python virtual environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python dependencies
    pip install -r requirements.txt
    
    print_success "Python environment setup completed"
}

# Setup environment variables
setup_env_vars() {
    print_status "Setting up environment variables..."
    
    if [[ ! -f .env ]]; then
        cp .env.example .env
        
        # Generate a random secret key
        SECRET_KEY=$(python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')
        
        # Update .env file
        if [[ "$OS" == "macos" ]]; then
            sed -i '' "s/your-secret-key-here-make-it-long-and-random-at-least-50-characters/$SECRET_KEY/" .env
        else
            sed -i "s/your-secret-key-here-make-it-long-and-random-at-least-50-characters/$SECRET_KEY/" .env
        fi
        
        print_success "Environment file created and configured"
    else
        print_warning ".env file already exists, skipping creation"
    fi
}

# Run Django setup
setup_django() {
    print_status "Setting up Django application..."
    
    source venv/bin/activate
    
    # Run migrations
    python manage.py makemigrations
    python manage.py migrate
    
    # Create superuser (non-interactive)
    echo "from django.contrib.auth.models import User; User.objects.create_superuser('admin', 'admin@example.com', 'admin123') if not User.objects.filter(username='admin').exists() else None" | python manage.py shell
    
    # Load initial data
    python manage.py setup_guardian --demo-data
    
    # Collect static files
    python manage.py collectstatic --noinput
    
    print_success "Django setup completed"
}

# Setup development tools
setup_dev_tools() {
    print_status "Setting up development tools..."
    
    source venv/bin/activate
    
    # Install development dependencies
    pip install black flake8 pytest pytest-django pytest-cov pre-commit
    
    # Setup pre-commit hooks
    pre-commit install
    
    print_success "Development tools setup completed"
}

# Create sample data
create_sample_data() {
    print_status "Creating sample data..."
    
    source venv/bin/activate
    
    # Import some sample vulnerabilities
    if [[ -f "sample_data/vulnerabilities.csv" ]]; then
        python manage.py import_vulnerabilities --source csv --file sample_data/vulnerabilities.csv
    fi
    
    print_success "Sample data created"
}

# Setup Docker environment (optional)
setup_docker() {
    if [[ "$DOCKER_AVAILABLE" == true && "$DOCKER_COMPOSE_AVAILABLE" == true ]]; then
        print_status "Setting up Docker environment..."
        
        # Build Docker images
        docker-compose build
        
        # Start services
        docker-compose up -d postgres redis
        
        print_success "Docker environment setup completed"
    else
        print_warning "Docker not available, skipping Docker setup"
    fi
}

# Start development server
start_dev_server() {
    print_status "Starting development server..."
    
    source venv/bin/activate
    
    # Start Celery worker in background
    celery -A guardian worker --loglevel=info --detach
    
    # Start Celery beat in background
    celery -A guardian beat --loglevel=info --detach
    
    print_success "Background services started"
    print_status "Starting Django development server..."
    print_status "Access the application at: http://localhost:8000"
    print_status "Admin interface at: http://localhost:8000/admin (admin/admin123)"
    print_status "API documentation at: http://localhost:8000/docs/"
    
    # Start Django development server
    python manage.py runserver 0.0.0.0:8000
}

# Print final instructions
print_instructions() {
    echo ""
    print_success "🎉 Open Security Guardian development environment setup completed!"
    echo ""
    echo "Next steps:"
    echo "1. Activate the virtual environment: source venv/bin/activate"
    echo "2. Start the development server: python manage.py runserver"
    echo "3. Visit http://localhost:8000 to access the application"
    echo "4. Visit http://localhost:8000/admin to access the admin panel (admin/admin123)"
    echo "5. Visit http://localhost:8000/docs/ to access the API documentation"
    echo ""
    echo "Useful commands:"
    echo "- Run tests: python manage.py test"
    echo "- Create migrations: python manage.py makemigrations"
    echo "- Apply migrations: python manage.py migrate"
    echo "- Import vulnerabilities: python manage.py import_vulnerabilities --source csv --file data.csv"
    echo "- Generate compliance report: python manage.py generate_compliance_report --framework 'NIST CSF'"
    echo "- Run maintenance tasks: python manage.py maintenance"
    echo ""
    echo "Development tools:"
    echo "- Format code: black ."
    echo "- Lint code: flake8 ."
    echo "- Run tests with coverage: pytest --cov"
    echo ""
    echo "For more information, see README.md and GETTING_STARTED.md"
}

# Main execution flow
main() {
    echo "Open Security Guardian - Development Setup"
    echo "========================================"
    
    # Parse command line arguments
    SKIP_DEPS=false
    SKIP_DATABASE=false
    SKIP_DOCKER=false
    START_SERVER=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-deps)
                SKIP_DEPS=true
                shift
                ;;
            --skip-database)
                SKIP_DATABASE=true
                shift
                ;;
            --skip-docker)
                SKIP_DOCKER=true
                shift
                ;;
            --start-server)
                START_SERVER=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --skip-deps      Skip system dependencies installation"
                echo "  --skip-database  Skip database setup"
                echo "  --skip-docker    Skip Docker setup"
                echo "  --start-server   Start development server after setup"
                echo "  -h, --help       Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Run setup steps
    check_requirements
    
    if [[ "$SKIP_DEPS" == false ]]; then
        install_system_deps
    fi
    
    if [[ "$SKIP_DATABASE" == false ]]; then
        setup_database
    fi
    
    setup_python_env
    setup_env_vars
    setup_django
    setup_dev_tools
    create_sample_data
    
    if [[ "$SKIP_DOCKER" == false ]]; then
        setup_docker
    fi
    
    if [[ "$START_SERVER" == true ]]; then
        start_dev_server
    else
        print_instructions
    fi
}

# Run main function
main "$@"
