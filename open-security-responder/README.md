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
      tool_name: "port_scanner"
      params:
        target: "{{ trigger.ip }}"

  - name: "whois_lookup"
    action: "api.run_tool"
    input:
      tool_name: "ip_geolocation"
      params:
        ip_address: "{{ trigger.ip }}"
        include_whois: true
    condition: "steps.scan_ports.output.open_ports | length > 0"
```

A tool's name and parameters are those of the tools service
(`open-security-tools/app/tools/<name>/schemas.py`), and so are the fields
of its result that later steps read.

### Step context

A step's `input` templates and its `condition` see the same context:

| Name | What it holds |
| ---- | ------------- |
| `trigger` | The JSON body the run was started with, as sent. |
| `run.id` | The run's ID. |
| `run.playbook_id` | The ID of the playbook being run. |
| `run.started_at` | When the run was queued, ISO 8601 in UTC, for example `2026-10-03T09:42:03.123456+00:00`. |
| `steps.<key>.output` | What the step's action returned. |
| `steps.<key>.status` | `completed`, or `failed` for a step that failed under `on_failure: continue`. |
| `steps.<key>.error` | Why the step failed; present only when it did. |
| `steps.<key>.duration` | How long the step took, in seconds. |

- **The key** is the step's `id` when it has one, otherwise its `name`.
- **A step's result is `output`.** There is no `result` key, and no
  `system` object: write `steps.scan.output.open_ports`, and
  `run.started_at` for a timestamp.
- **A skipped step is absent from `steps`.** Test for it with
  `steps.<key> is defined` before reading its output.
- **A step that failed under `on_failure: continue`** is present, with
  `status: failed`, its `error` and `output: none`. Test
  `steps.<key>.output is not none` before reading a field of it.
- **Input templates render as data.** They are not HTML-escaped: a URL
  with `&` in it reaches the action unchanged. To pass a whole object or
  list, render it with `| tojson`; a rendered value that is a JSON object or
  array is parsed back into one.

### system.evaluate

`system.evaluate` combines named boolean conditions into one result. It
returns no verdict or severity of its own; a playbook names its signals and
guards later steps on `overall_result`.

```yaml
  - name: "threat_verdict"
    action: "system.evaluate"
    input:
      conditions:
        url_flagged: "{{ steps.url_analysis.output.security_analysis.is_suspicious }}"
        bad_reputation: "{{ steps.reputation.output.overall_threat_score >= 70 }}"
      min_true: 1        # omitted: every condition must hold

  - name: "add_to_blacklist"
    action: "data.add_to_blacklist"
    condition: "steps.threat_verdict is defined and steps.threat_verdict.output.overall_result"
    # ...
```

It returns `overall_result`, `conditions` (each name and whether it held),
`matched` (the names that held, in order), `matched_count`, `total`,
`min_true` and `timestamp`. Each condition must render to `True` or
`False`, or be a boolean; any other value, such as a nested mapping or a
word like `malicious`, fails the step instead of being guessed at.

### Step conditions

A step's `condition` is a Jinja2 expression, the body of an
`{% if %}`, written without `{{ }}`: the step runs when it is true and is
skipped when it is false. It sees the same context as the step's input
(see [Step context](#step-context)).

- **Undefined names.** A condition that references a name that is not
  defined, such as a trigger field that was not sent or an output field an
  earlier step did not return, evaluates to false and the step is skipped.
  The run log records a `WARNING` naming the reference as written in the
  condition, for example
  `Condition references an undefined name ('trigger.tag'); evaluating it as false`.
  No value from the context is logged; a key computed at run time is
  described as such. To test for an optional field explicitly, write
  `trigger.tag is defined and trigger.tag == 'urgent'`.
- **Other errors fail the step.** A condition that is not a valid
  expression (including one wrapped in `{{ }}`), that contains a blocked
  pattern such as `__class__`, or that the sandbox blocks raises, and the
  step fails according to its `on_failure` policy. None of these is
  treated as a false condition: an attempt to reach Python internals is
  not hidden behind a skipped step.
- **Inputs stay strict.** An undefined name in a step's `input` template
  is an error that fails the step, as before.
- **No load-time check of paths.** A playbook's trigger declares no schema
  of its fields, so a misspelt trigger field in a condition cannot be
  detected when the playbook loads; it shows up as the warning above.

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
# Unit tests (no services needed)
make test

# Playbook execution through the gateway (needs the whole stack running)
make test-playbook
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
