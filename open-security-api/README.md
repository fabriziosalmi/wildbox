# Wildbox Security API

A robust and extensible open security API platform built with Python and FastAPI. This modular system allows for easy integration of new security tools by simply adding them to the `tools` directory.

## 🚀 Features

- **Modular Architecture**: Dynamic discovery and loading of security tools
- **RESTful API**: Well-defined API endpoints with automatic OpenAPI documentation
- **Interactive Documentation**: Automatically generated Swagger UI and ReDoc
- **Web Interface**: User-friendly web interface for tool interaction
- **Security**: API key-based authentication and security best practices
- **Structured Logging**: JSON-formatted logging with configurable levels
- **Configuration Management**: Environment-based configuration using Pydantic

## 📁 Project Structure

```
open-security-api/
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
├── .env                        # Environment variables
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## 🛠️ Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Steps

1. **Clone or create the project directory:**
   ```bash
   mkdir open-security-api
   cd open-security-api
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

### Common Issues

1. **Tool not discovered**:
   - Check that the tool directory contains `main.py` and `schemas.py`
   - Verify the `execute_tool` function exists in `main.py`
   - Check server logs for import errors

2. **Authentication failures**:
   - Verify the API key in the `.env` file
   - Check the Authorization header format
   - Ensure the API key matches exactly

3. **Import errors**:
   - Check Python path and virtual environment
   - Verify all dependencies are installed
   - Check for syntax errors in tool files

### Debug Mode

Enable debug mode by setting `DEBUG=true` in `.env` for detailed error messages and auto-reload functionality.

### Logs

Check the application logs for detailed error information. Logs are output in JSON format to stdout.

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

---

**Built with ❤️ using FastAPI, Python, and modern web technologies.**
