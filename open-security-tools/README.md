# Wildbox Security Tools

**Status**: Production Ready ✅
**Last Updated**: 16 Novembre 2025

A robust and extensible open security API platform built with Python and FastAPI. This modular system allows for easy integration of new security tools by simply adding them to the `tools` directory.

## 🚀 Features

- **Modular Architecture**: Dynamic discovery and loading of security tools
- **RESTful API**: Well-defined API endpoints with automatic OpenAPI documentation
- **Interactive Documentation**: Automatically generated Swagger UI and ReDoc
- **Web Interface**: User-friendly web interface for tool interaction
- **Security**: API key-based authentication and security best practices
- **Structured Logging**: JSON-formatted logging with configurable levels
- **Configuration Management**: Environment-based configuration using Pydantic
- **Docker Support**: Full Docker and Docker Compose support with development and production configurations
- **Redis Integration**: Caching and rate limiting with Redis
- **Nginx Support**: Optional reverse proxy with SSL/TLS support

## 🐳 Quick Start with Docker

The fastest way to get started is using our automated setup:

```bash
# Clone the repository
git clone <repository-url>
cd open-security-tools

# Run the setup script (recommended)
./scripts/setup.sh

# Or manual setup
make setup
make dev
```

Visit http://localhost:8000 to access the web interface.

### Alternative Quick Start

```bash
# Manual setup
git clone <repository-url>
cd open-security-tools

# Copy and configure environment
cp .env.example .env
# Edit .env with your API key

# Start development environment
make dev

# Or start production environment
make prod
```

## 📋 Prerequisites

### For Docker (Recommended)
- Docker 20.10+
- Docker Compose 2.0+

### For Local Development
- Python 3.11+
- Redis (optional, for caching and rate limiting)

## 🔧 Installation & Setup

### Option 1: Docker (Recommended)

1. **Clone and setup:**
   ```bash
   git clone https://github.com/fabriziosalmi/wildbox.git
   cd wildbox/open-security-tools
   make setup  # Creates .env from .env.example
   ```

2. **Configure environment:**
   Edit `.env` file with your settings:
   ```bash
   # Required: Change the default API key
   API_KEY=your-secure-api-key-here
   
   # Optional: Other settings
   DEBUG=false
   LOG_LEVEL=INFO
   ```

3. **Start the application:**
   ```bash
   # Development with hot reload
   make dev
   
   # Production
   make prod
   
   # Production with Nginx
   make prod-nginx
   ```

### Option 2: Local Development

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Setup environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run the application:**
   ```bash
   uvicorn app.main:app --reload
   ```

## 🐳 Docker Commands

We provide a comprehensive Makefile for easy Docker management:

### Development Commands
```bash
make dev          # Start development environment with hot reload
make dev-build    # Build and start development environment
make dev-down     # Stop development environment
make dev-logs     # Show development logs
```

### Production Commands
```bash
make prod         # Start production environment
make prod-build   # Build and start production environment
make prod-nginx   # Start with Nginx reverse proxy
make prod-down    # Stop production environment
make prod-logs    # Show production logs
```

### Management Commands
```bash
make status       # Show container status
make logs         # Show application logs
make shell        # Enter application container
make redis-cli    # Enter Redis CLI
make restart      # Restart services
make clean        # Remove containers and volumes
make clean-all    # Remove everything including images
make health       # Check application health
make urls         # Show useful URLs
```

## 🚀 Deployment

### Production Deployment with Docker

1. **Prepare production environment:**
   ```bash
   # Clone repository
   git clone <repository-url>
   cd open-security-tools
   
   # Setup environment
   cp .env.example .env
   ```

2. **Configure production settings:**
   ```bash
   # Edit .env file
   API_KEY=your-production-api-key-here
   DEBUG=false
   LOG_LEVEL=INFO
   HOST=0.0.0.0
   ```

3. **Deploy with Docker Compose:**
   ```bash
   # Standard deployment
   make prod-build
   
   # With Nginx reverse proxy
   make prod-nginx
   ```

4. **SSL/TLS Setup (Optional):**
   ```bash
   # Create SSL directory
   mkdir ssl
   
   # Add your certificates
   cp your-cert.pem ssl/cert.pem
   cp your-key.pem ssl/key.pem
   
   # Update nginx.conf for HTTPS
   # Uncomment the HTTPS server block
   ```

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `API_KEY` | API authentication key | - | ✅ |
| `SECRET_KEY` | Session secret key | auto-generated | ❌ |
| `HOST` | Server bind address | `127.0.0.1` | ❌ |
| `PORT` | Server port | `8000` | ❌ |
| `DEBUG` | Enable debug mode | `false` | ❌ |
| `LOG_LEVEL` | Logging level | `INFO` | ❌ |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` | ❌ |
| `RATE_LIMIT_ENABLED` | Enable rate limiting | `true` | ❌ |

### Production Considerations

- **Security**: Always change the default API key
- **Performance**: Use Redis for caching and rate limiting
- **Monitoring**: Check logs with `make prod-logs`
- **Scaling**: Use multiple container instances behind a load balancer
- **Backup**: Regularly backup Redis data if using persistence

### Docker Volumes

- **Application Logs**: `./logs:/app/logs`
- **Redis Data**: `redis-data:/data`
- **SSL Certificates**: `./ssl:/etc/nginx/ssl:ro`

### Health Monitoring

```bash
# Check application health
make health

# View container status
make status

# Monitor logs
make logs
```

## ⚙️ Configuration Management

### API Configuration

The application uses Pydantic Settings for configuration management with environment variable support:

```python
# Example configuration in .env
API_KEY=your-secure-api-key
HOST=0.0.0.0
PORT=8000
DEBUG=false
LOG_LEVEL=INFO
REDIS_URL=redis://redis:6379
```

### Security Configuration

- **API Key Authentication**: Required for all API endpoints
- **Rate Limiting**: Configurable per-IP rate limits
- **CORS**: Configurable cross-origin requests
- **Security Headers**: Automatic security headers via Nginx

### Tool Configuration

Each tool can have its own configuration:

```python
# In tool's main.py
TOOL_INFO = {
    "name": "My Security Tool",
    "description": "Tool description",
    "version": "1.0.0",
    "author": "Your Name",
    "category": "security_category",
    "timeout": 300,  # Tool-specific timeout
}
```

## 🏗️ Architecture

### Docker Services

- **wildbox-api**: Main FastAPI application service
- **redis**: Redis for caching and rate limiting
- **nginx**: Optional reverse proxy with SSL/TLS support

### Container Features

- **Security**: Non-root user, minimal base image
- **Health Checks**: Built-in health monitoring
- **Hot Reload**: Development environment with auto-reload
- **Logging**: Structured JSON logging
- **Networking**: Isolated Docker network
- **Persistence**: Redis data persistence

## 📁 Project Structure

```
open-security-tools/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application and tool discovery
│   ├── config.py               # Configuration management
│   ├── security.py             # Authentication and security
│   ├── logging_config.py       # Logging configuration
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   └── router.py           # API routes and dynamic endpoint creation
│   │
│   ├── tools/
│   │   └── sample_tool/        # Example security tool
│   │       ├── __init__.py
│   │       ├── main.py         # Tool implementation
│   │       └── schemas.py      # Input/output schemas
│   │
│   └── web/
│       ├── __init__.py
│       ├── router.py           # Web interface routes
│       ├── templates/          # Jinja2 templates
│       │   ├── base.html
│       │   ├── index.html
│       │   └── tool.html
│       └── static/             # CSS and JavaScript files
│           ├── css/
│           │   └── styles.css
│           └── js/
│               └── script.js
│
├── Docker Configuration
├── Dockerfile                  # Production Docker image
├── Dockerfile.dev              # Development Docker image
├── docker-compose.yml          # Production Docker Compose
├── docker-compose.dev.yml      # Development Docker Compose
├── nginx.conf                  # Nginx reverse proxy configuration
├── .dockerignore              # Docker ignore file
├── Makefile                   # Docker management commands
│
├── Scripts
├── scripts/
│   ├── setup.sh               # Automated setup script
│   └── health-check.sh        # Health check script
│
├── CI/CD
├── .github/
│   └── workflows/
│       └── ci-cd.yml          # GitHub Actions workflow
│
├── Configuration
├── .env.example               # Environment variables example
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Steps

1. **Clone or create the project directory:**
   ```bash
   mkdir open-security-tools
   cd open-security-tools
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```bash
   # Edit the .env file with your settings
   cp .env.example .env  # If you have an example file
   ```

## 🚀 Quick Start

### 1. Start the API Server

```bash
# Development mode with auto-reload
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Access the Interfaces

- **Web Interface**: http://127.0.0.1:8000
- **Swagger UI**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc
- **API Health Check**: http://127.0.0.1:8000/health

### 3. API Authentication

All API endpoints require authentication using either:

- **Bearer Token**: `Authorization: Bearer your-api-key`
- **API Key Header**: `X-API-Key: your-api-key`

Default API key: `wildbox-security-api-key-2025` (change this in production!)

## 📊 Using the API

### List Available Tools

```bash
curl -X GET "http://127.0.0.1:8000/api/tools" \
  -H "Authorization: Bearer wildbox-security-api-key-2025"
```

### Execute a Tool

```bash
curl -X POST "http://127.0.0.1:8000/api/tools/sample_tool" \
  -H "Authorization: Bearer wildbox-security-api-key-2025" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "basic",
    "timeout": 30
  }'
```

### Get Tool Information

```bash
curl -X GET "http://127.0.0.1:8000/api/tools/sample_tool/info" \
  -H "Authorization: Bearer wildbox-security-api-key-2025"
```

## ⚡ Asynchronous Tool Execution

For long-running security tools (e.g., port scanners, vulnerability assessments), Wildbox provides **asynchronous task execution** using Celery and Redis. This allows tools to run in the background without blocking the API.

### Why Async Execution?

- **Non-blocking API**: Get immediate response with a task ID instead of waiting for tool completion
- **Scalability**: Execute multiple tools concurrently without tying up API workers
- **Reliability**: Tasks survive server restarts and can be retried on failure
- **Monitoring**: Track task progress and retrieve results at any time

### Performance Comparison

| Execution Mode | Response Time | Use Case |
|----------------|---------------|----------|
| **Synchronous** | 500-2000ms | Quick lookups (WHOIS, DNS) |
| **Asynchronous** | 15-20ms | Long scans (port scanning, vulnerability assessments) |

**Speedup: ~30x faster API response** for background-compatible tools.

### Architecture

```
Client → FastAPI (submit task) → Redis Queue → Celery Worker (execute tool) → Redis (store result)
         ↓ (18ms response)                      ↓ (runs in background)
         task_id                                 ↓
                                                Result stored
         
Client → FastAPI (check status) → Redis → Retrieve result
```

### Step 1: Submit a Task

Submit a tool for asynchronous execution using the `/async` endpoint:

```bash
curl -X POST "http://127.0.0.1:8000/api/tools/whois_lookup/async" \
  -H "X-API-Key: wildbox-security-api-key-2025" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "cloudflare.com"
  }'
```

**Response (immediate, ~18ms):**
```json
{
  "task_id": "ad2b039b-cf50-46c1-9124-ffca7a424098",
  "status": "accepted",
  "message": "Task queued for execution"
}
```

### Step 2: Check Task Status

Query the task status and result using the task ID:

```bash
curl -X GET "http://127.0.0.1:8000/api/tasks/ad2b039b-cf50-46c1-9124-ffca7a424098" \
  -H "X-API-Key: wildbox-security-api-key-2025"
```

**Response while task is running:**
```json
{
  "task_id": "ad2b039b-cf50-46c1-9124-ffca7a424098",
  "state": "PENDING",
  "status": "pending",
  "message": "Task is waiting to be executed"
}
```

**Response when task is completed:**
```json
{
  "task_id": "ad2b039b-cf50-46c1-9124-ffca7a424098",
  "state": "SUCCESS",
  "status": "completed",
  "duration": 0.338,
  "result": {
    "tool_name": "whois_lookup",
    "execution_time": 0.338,
    "domain": "cloudflare.com",
    "success": true,
    "registrar": "Cloudflare, Inc.",
    "creation_date": "2009-02-17",
    "expiration_date": "2028-02-17",
    "name_servers": ["ns1.cloudflare.com", "ns2.cloudflare.com"]
  }
}
```

**Response if task failed:**
```json
{
  "task_id": "ad2b039b-cf50-46c1-9124-ffca7a424098",
  "state": "FAILURE",
  "status": "failed",
  "error": "DNS resolution failed: [Errno -2] Name or service not known"
}
```

### Step 3: Cancel a Running Task (Optional)

Cancel a task that is still pending or running:

```bash
curl -X DELETE "http://127.0.0.1:8000/api/tasks/ad2b039b-cf50-46c1-9124-ffca7a424098" \
  -H "X-API-Key: wildbox-security-api-key-2025"
```

**Response:**
```json
{
  "status": "cancelled",
  "message": "Task cancellation requested"
}
```

**Note:** Tasks already completed cannot be cancelled.

### Complete Workflow Example

```bash
# 1. Submit WHOIS lookup task
TASK_ID=$(curl -s -X POST "http://127.0.0.1:8000/api/tools/whois_lookup/async" \
  -H "X-API-Key: wildbox-security-api-key-2025" \
  -H "Content-Type: application/json" \
  -d '{"domain": "microsoft.com"}' | jq -r '.task_id')

echo "Task submitted: $TASK_ID"

# 2. Wait briefly for execution
sleep 2

# 3. Retrieve result
curl -X GET "http://127.0.0.1:8000/api/tasks/$TASK_ID" \
  -H "X-API-Key: wildbox-security-api-key-2025" | jq
```

### Task States

| State | Description | Next Action |
|-------|-------------|-------------|
| `PENDING` | Task queued, not yet started | Wait and poll again |
| `STARTED` | Task is currently executing | Wait and poll again |
| `SUCCESS` | Task completed successfully | Retrieve result from `result` field |
| `FAILURE` | Task failed with error | Check `error` field for details |
| `RETRY` | Task failed, retrying | Wait for final state |
| `REVOKED` | Task was cancelled | No further action |

### Monitoring Tasks

Access the Celery Flower monitoring UI to view all running tasks:

```bash
# Flower is available at:
http://127.0.0.1:5555
```

**Features:**
- Real-time task monitoring
- Worker status and performance metrics
- Task history and logs
- Task rate graphs

### Which Tools Support Async?

**All 55 security tools** support asynchronous execution. Recommended async usage for:

- **Port scanners** (network_port_scanner, service_version_scanner)
- **Vulnerability assessments** (sql_injection_scanner, xss_scanner)
- **Long-running scans** (directory_fuzzer, subdomain_enumerator)

Quick tools like WHOIS lookups can use either sync or async depending on your architecture preferences.

### Configuration

Async execution is configured via environment variables:

```bash
# Redis connection (task broker and result backend)
REDIS_URL=redis://wildbox-redis:6379/2

# Celery worker settings
CELERY_WORKER_CONCURRENCY=4           # Parallel task execution
CELERY_TASK_TIME_LIMIT=600            # Hard timeout (10 minutes)
CELERY_TASK_SOFT_TIME_LIMIT=570       # Soft timeout (9.5 minutes)
CELERY_WORKER_MAX_TASKS_PER_CHILD=50  # Worker restart after N tasks
```

### Best Practices

1. **Use async for long-running tools** (>1 second execution time)
2. **Poll task status** at reasonable intervals (every 500ms to 2 seconds)
3. **Set appropriate timeouts** based on tool execution expectations
4. **Handle all task states** in your client code (PENDING, SUCCESS, FAILURE)
5. **Clean up completed tasks** by deleting results you no longer need
6. **Monitor Flower** for worker health and task queue depth

## 🔧 Adding New Security Tools

To add a new security tool, create a new directory in `app/tools/` with the following structure:

### 1. Create Tool Directory

```bash
mkdir app/tools/your_tool_name
```

### 2. Create Required Files

#### `app/tools/your_tool_name/__init__.py`
```python
"""Your security tool package."""
```

#### `app/tools/your_tool_name/schemas.py`
```python
"""Pydantic schemas for your tool."""

from pydantic import BaseModel, Field
from typing import Dict, Any, List
from datetime import datetime

class YourToolInput(BaseModel):
    """Input schema for your security tool."""
    
    target: str = Field(..., description="Target to analyze")
    # Add more fields as needed

class YourToolOutput(BaseModel):
    """Output schema for your security tool."""
    
    target: str = Field(..., description="Analyzed target")
    timestamp: datetime = Field(..., description="Analysis timestamp")
    status: str = Field(..., description="Analysis status")
    findings: Dict[str, Any] = Field(..., description="Analysis findings")
    # Add more fields as needed
```

#### `app/tools/your_tool_name/main.py`
```python
"""Your security tool implementation."""

from datetime import datetime
from .schemas import YourToolInput, YourToolOutput

# Tool metadata
TOOL_INFO = {
    "name": "your_tool_name",
    "display_name": "Your Tool Display Name",
    "description": "Description of what your tool does",
    "version": "1.0.0",
    "author": "Your Name",
    "category": "your_category"
}

async def execute_tool(input_data: YourToolInput) -> YourToolOutput:
    """
    Execute your security tool.
    
    Args:
        input_data: Input parameters for the tool
        
    Returns:
        Tool execution results
    """
    
    # Implement your tool logic here
    start_time = datetime.utcnow()
    
    try:
        # Your tool implementation
        result = perform_analysis(input_data.target)
        
        return YourToolOutput(
            target=input_data.target,
            timestamp=start_time,
            status="success",
            findings=result
        )
        
    except Exception as e:
        return YourToolOutput(
            target=input_data.target,
            timestamp=start_time,
            status="failed",
            findings={"error": str(e)}
        )

def perform_analysis(target: str):
    """Implement your analysis logic here."""
    pass
```

### 3. Restart the Server

The new tool will be automatically discovered and available at:
- API: `POST /api/tools/your_tool_name`
- Web: `http://127.0.0.1:8000/tools/your_tool_name`

## 🔒 Security Considerations

### Production Deployment

1. **Change the default API key** in the `.env` file
2. **Use HTTPS** in production environments
3. **Configure CORS** appropriately for your domain
4. **Set up proper firewall rules**
5. **Enable rate limiting** (consider using nginx or similar)
6. **Regular security updates** for dependencies

### API Key Management

- Store API keys securely (consider using environment variables or secret management systems)
- Rotate API keys regularly
- Use different API keys for different environments
- Consider implementing multiple API keys for different users/services

## 📝 Configuration

### Environment Variables (`.env`)

```bash
# API Configuration
API_KEY="your-secret-api-key-here"
LOG_LEVEL="INFO"
ENVIRONMENT="development"

# Server Configuration (optional)
HOST="127.0.0.1"
PORT=8000
DEBUG=false
```

### Logging Levels

- `DEBUG`: Detailed debug information
- `INFO`: General operational information
- `WARNING`: Warning messages
- `ERROR`: Error messages
- `CRITICAL`: Critical errors

## 🔧 **Recent Improvements & Enhancements**

### Security Enhancements
- **🔒 Secure API Key Management**: API keys are now properly managed using Pydantic SecretStr
- **🛡️ Security Headers**: Comprehensive security headers including CSP, HSTS, X-Frame-Options
- **⚡ Rate Limiting**: Built-in rate limiting with configurable limits and windows
- **🔍 Input Validation**: Enhanced validation with custom validators and better error messages

### Performance & Scalability
- **⚙️ Execution Management**: Proper tool execution management with timeouts and concurrency control
- **📊 Metrics Collection**: Built-in metrics middleware for monitoring performance
- **🎯 Concurrent Execution**: Configurable maximum concurrent tool executions
- **⏱️ Timeout Control**: Proper timeout handling for long-running tools

### Architecture & Code Quality
- **🏗️ Enhanced Configuration**: Comprehensive configuration management with validation
- **🔧 Middleware System**: Custom middleware for logging, security, and performance
- **❌ Better Error Handling**: Comprehensive exception handling and user-friendly error messages
- **📝 Audit Logging**: Detailed audit trails for all tool executions

### Monitoring & Observability
- **📈 Health Monitoring**: Enhanced health check endpoints with detailed system information
- **📊 Execution Statistics**: Tool performance metrics and execution history
- **🔍 Request Logging**: Structured logging for all HTTP requests and responses
- **⚡ Real-time Metrics**: Live performance metrics collection

### Developer Experience
- **🔧 Better Configuration**: Environment-based configuration with validation
- **📚 Enhanced Documentation**: Comprehensive API documentation and examples
- **🧪 Testing Ready**: Test infrastructure preparation
- **🛠️ Development Tools**: Better development and debugging capabilities

## 🧪 Example Tool: Sample Tool

The included `sample_tool` demonstrates:

- **Port scanning simulation**: Simulates network port scanning
- **Vulnerability detection**: Identifies potential security issues
- **Security recommendations**: Provides actionable security advice
- **Realistic output**: Returns structured findings with detailed information

### Sample Tool Features

- Simulates scanning of common ports (21, 22, 80, 443, etc.)
- Generates realistic vulnerability findings
- Provides security recommendations
- Demonstrates proper error handling
- Shows async execution patterns

## 🐛 Troubleshooting

### Docker Issues

1. **Container won't start**:
   ```bash
   # Check container status
   make status
   
   # View logs
   make logs
   
   # Check if ports are available
   netstat -an | grep 8000
   ```

2. **Permission denied errors**:
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER .
   
   # Rebuild containers
   make clean
   make dev-build
   ```

3. **Redis connection issues**:
   ```bash
   # Check Redis container
   make redis-cli
   
   # Test Redis connection
   docker-compose exec wildbox-api ping redis
   ```

4. **Port already in use**:
   ```bash
   # Change port in .env file
   PORT=8001
   
   # Or stop conflicting services
   sudo lsof -ti:8000 | xargs sudo kill -9
   ```

### Application Issues

1. **Tool not discovered**:
   - Check that the tool directory contains `main.py` and `schemas.py`
   - Verify the `execute_tool` function exists in `main.py`
   - Check server logs for import errors
   ```bash
   make logs | grep ERROR
   ```

2. **Authentication failures**:
   - Verify the API key in the `.env` file
   - Check the Authorization header format
   - Ensure the API key matches exactly
   ```bash
   # Test with curl
   curl -H "X-API-Key: your-api-key" http://localhost:8000/health
   ```

3. **Import errors**:
   - Check Python path and virtual environment
   - Verify all dependencies are installed
   - Check for syntax errors in tool files
   ```bash
   # Enter container to debug
   make shell
   python -c "import app.tools.your_tool.main"
   ```

### Performance Issues

1. **Slow response times**:
   - Check Redis cache configuration
   - Monitor container resources
   - Check for tool timeout settings
   ```bash
   # Monitor container resources
   docker stats
   ```

2. **Memory issues**:
   ```bash
   # Check container memory usage
   docker-compose exec wildbox-api free -h
   
   # Increase Docker memory limits
   # Edit docker-compose.yml and add:
   # deploy:
   #   resources:
   #     limits:
   #       memory: 1G
   ```

### Debug Mode

Enable debug mode for detailed error messages:

```bash
# In .env file
DEBUG=true
LOG_LEVEL=DEBUG

# Restart containers
make restart
```

### Health Checks

```bash
# Check application health
curl http://localhost:8000/health

# Check all service health
make health

# Monitor logs in real-time
make logs
```

### Logs Analysis

```bash
# View application logs
make logs

# Follow logs in real-time
make dev-logs  # or make prod-logs

# Filter logs by level
make logs | grep ERROR

# Container-specific logs
docker-compose logs wildbox-api
docker-compose logs redis
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your security tool following the guidelines above
4. Test your implementation
5. Submit a pull request

## 📄 License

This project is open source. Please check the LICENSE file for details.

## 🆘 Support

For support and questions:

- Check the troubleshooting section above
- Review the API documentation at `/docs`
- Check server logs for error details
- Open an issue on the project repository

## 🔄 API Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Web interface dashboard |
| GET | `/tools/{tool_name}` | Tool interaction page |
| GET | `/health` | Health check |
| GET | `/api/tools` | List available tools |
| GET | `/api/tools/{tool_name}/info` | Get tool information |
| POST | `/api/tools/{tool_name}` | Execute specific tool |
| GET | `/docs` | Swagger UI documentation |
| GET | `/redoc` | ReDoc documentation |

## 🔗 Quick Access URLs

When running with Docker:

```bash
# Show all URLs
make urls
```

| Service | URL | Description |
|---------|-----|-------------|
| Web Interface | http://localhost:8000 | Main dashboard |
| API Documentation | http://localhost:8000/docs | Interactive API docs |
| ReDoc | http://localhost:8000/redoc | Alternative API docs |
| Health Check | http://localhost:8000/health | Service health status |

## 🏷️ Docker Tags and Versioning

- `latest` - Latest stable release
- `dev` - Development version with debug tools
- `v1.0.0` - Specific version releases

## 📊 Monitoring and Observability

### Built-in Monitoring
- Health check endpoints
- Structured JSON logging
- Redis performance metrics
- Container resource monitoring

### External Monitoring Integration
```yaml
# Example Prometheus configuration
version: '3.8'
services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
```

## 🔐 Security Best Practices

- ✅ Non-root container execution
- ✅ Minimal base images
- ✅ API key authentication
- ✅ Rate limiting
- ✅ Security headers via Nginx
- ✅ Input validation
- ✅ Secure secrets management

---

**Built with ❤️ using FastAPI, Python, Docker, and modern web technologies.**
