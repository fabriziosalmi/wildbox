# 🛡️ Open Security Responder

**SOAR (Security Orchestration, Automation and Response) microservice for the Wildbox Security Suite**

The Responder is the orchestration heart of Wildbox, designed to automate security incident response through customizable playbooks.

## 🚀 Features

- **Playbook-based Automation**: YAML-defined security workflows
- **Asynchronous Execution**: Powered by Dramatiq and Redis
- **Connector Framework**: Extensible integration with security tools
- **Template Engine**: Jinja2-powered dynamic input resolution
- **REST API**: FastAPI-based management interface
- **Real-time Monitoring**: Track playbook execution status and logs

## 🏗️ Architecture

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI       │    │   Dramatiq      │    │   Connectors    │
│   REST API      │───▶│   Workflow      │───▶│   Framework     │
│                 │    │   Engine        │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Playbook      │    │   Redis         │    │   External      │
│   Parser        │    │   State Store   │    │   Services      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Docker Deployment (Recommended)

```bash
# Clone and navigate
cd /Users/fab/GitHub/wildbox/open-security-responder

# Start the services
make dev

# View logs
make logs
```

### Manual Installation

```bash
# Install dependencies
make install

# Start Redis (required)
redis-server --port 6381

# Start the API server
make run-local

# In another terminal, start the worker
make worker
```

## 📚 Usage

### Access Points

- **API Server**: http://localhost:8018
- **API Documentation**: http://localhost:8018/docs
- **Health Check**: http://localhost:8018/health

### Example Playbook Execution

```bash
# Execute a playbook
curl -X POST "http://localhost:8018/v1/playbooks/triage_ip/execute" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.1"}'

# Check execution status
curl "http://localhost:8018/v1/runs/{run_id}"
```

## 📋 Playbook Structure

Playbooks are defined in YAML format:

```yaml
playbook_id: "triage_ip"
name: "IP Address Triage"
trigger:
  type: "api"
steps:
  - name: "scan_ports"
    action: "api.run_tool"
    input:
      tool_name: "nmap"
      params:
        target: "{{ trigger.ip }}"
        
  - name: "check_reputation"
    action: "api.run_tool"
    input:
      tool_name: "whois"
      params:
        ip: "{{ trigger.ip }}"
    condition: "{{ steps.scan_ports.output.open_ports|length > 0 }}"
```

## 🔧 Configuration

Environment variables:

| Variable | Description | Default |
| ---------- | ------------- | --------- |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6381/0` |
| `WILDBOX_API_URL` | Open Security API URL | `http://localhost:8000` |
| `WILDBOX_DATA_URL` | Open Security Data URL | `http://localhost:8002` |
| `WILDBOX_GUARDIAN_URL` | Open Security Guardian URL | `http://localhost:8013` |
| `WILDBOX_SENSOR_URL` | Open Security Sensor URL | `http://localhost:8899` |
| `DEBUG` | Enable debug mode | `false` |

## 🧪 Testing

```bash
# Run all tests
make test

# Test a specific playbook
make test-playbook

# Run end-to-end test
python scripts/test_responder.py
```

## 🏗️ Development

### Project Structure

```text
open-security-responder/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── models.py               # Pydantic models
│   ├── config.py               # Configuration management
│   ├── playbook_parser.py      # YAML playbook parser
│   ├── workflow_engine.py      # Dramatiq workflow engine
│   └── connectors/             # Connector framework
│       ├── __init__.py
│       ├── base.py
│       └── wildbox_connector.py
├── playbooks/                  # YAML playbook definitions
├── scripts/                    # Utility scripts
├── tests/                      # Test suite
└── logs/                       # Application logs
```

### Adding Connectors

1. Create a new connector class inheriting from `BaseConnector`
2. Register it in the connector registry
3. Implement required action methods
4. Test with a playbook

## 📊 Monitoring

- **Health Endpoint**: `/health` - Service health status
- **Metrics Endpoint**: `/metrics` - Prometheus metrics
- **Run Status**: `/v1/runs/{run_id}` - Execution details and logs

## 🤝 Integration

The Responder integrates with other Wildbox components:

- **Open Security API**: Tool execution and analysis
- **Open Security Data**: IOC management and threat intelligence
- **Open Security Guardian**: Vulnerability management
- **Open Security Sensor**: Endpoint actions and monitoring

## 📝 License

Part of the Wildbox Security Suite - MIT License
