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

### With the whole stack (recommended)

The responder runs as the `responder` service of the main
`docker-compose.yml`, from the repository root, with the services its
playbooks call and the gateway in front of it:

```bash
docker compose up -d
docker compose logs -f responder
```

### Standalone

`open-security-responder/docker-compose.yml` runs the responder, its worker
and a Redis of their own, and reaches the other services where the main
stack publishes them on the host:

```bash
cd open-security-responder

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

Both need `GATEWAY_INTERNAL_SECRET`, and the worker the `WILDBOX_*_URL`
variables of the services it calls (see [Configuration](#-configuration)).

## 📚 Usage

### API

The gateway publishes the API at `https://<host>/api/v1/responder/<path>`
and forwards it to the responder's `/v1/<path>`. Every route but `/health`,
`/metrics` and `/` requires the gateway's identity headers, so a client
calls the gateway, not port 8018.

| Method and path (responder) | What it does | Who may |
| --- | --- | --- |
| `GET /v1/playbooks` | List the loaded playbooks | any member |
| `POST /v1/playbooks/{playbook_id}/execute` | Start a run; body `{"trigger_data": {...}}`; answers 202 with `run_id` | any member |
| `GET /v1/runs/{run_id}` | A run's status, step results and log | the run's team |
| `DELETE /v1/runs/{run_id}` | Cancel a run (see [Cancelling a run](#cancelling-a-run)) | the run's team |
| `POST /v1/playbooks/reload` | Reload the playbooks from disk | owner, admin |
| `GET /v1/connectors` | List the connectors and their actions | any member |
| `GET /health` | Health check, no authentication | anyone |
| `GET /metrics` | Prometheus metrics | anyone on the network |

A run of another team answers 404, as a run that does not exist does.
`/docs`, `/redoc` and `/openapi.json` are served only when `ENVIRONMENT` is
`development`, on the service port and not through the gateway.

### Cancelling a run

`DELETE /v1/runs/{run_id}` asks the worker to stop the run, and answers
with the status the run is in afterwards:

| Run was | Answer | What happens |
| --- | --- | --- |
| queued | 200, `cancelled` | The worker that picks it up runs no step. |
| running | 202, `cancelling` | The step in progress runs to its end; no further step starts. The run then reads `cancelled`. |
| cancelling | 202, `cancelling` | Nothing more: the first request stands. |
| completed, failed or cancelled | 200, its status | Nothing: the run has ended. |

- **A step in progress is not interrupted.** Its call to another service
  has been sent and may already have taken effect, so it runs to its end
  and is recorded as it ended, `completed` or `failed`, in
  `step_results`. Those are the steps that ran; the run's log names the
  steps that did not.
- **A cancelled run stays cancelled.** The worker's writes are
  compare-and-set against the run's status and its cancel request, so it
  cannot write `completed` or `failed` over a cancel. Whichever commits
  first decides: a cancel accepted before the run's last write ends the
  run `cancelled`, even when every step had already run, and a cancel
  after it answers with `completed` or `failed` and changes nothing. A
  step that fails while the run is cancelling leaves the run `cancelled`,
  with the failure in `error`.
- **The request is durable.** It is stored in Redis with the run, so a
  worker that picks the run up later still sees it; a worker that dies
  while a run is cancelling leaves it to the abandoned-run reaper, which
  records it as `cancelled`.

### Example Playbook Execution

Through the gateway, as a user with a token or an API key. The responder
accepts only requests the gateway forwards, and a run acts for the user who
starts it (see [Who a run acts for](#who-a-run-acts-for)). The development
gateway's certificate is self-signed: `--cacert` trusts it, from the
repository root.

```bash
# Execute a playbook: the trigger's fields go under trigger_data
curl --cacert open-security-gateway/ssl/wildbox.crt \
  -X POST "https://localhost/api/v1/responder/playbooks/triage_ip/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"trigger_data": {"ip": "203.0.113.7"}}'

# Check execution status
curl --cacert open-security-gateway/ssl/wildbox.crt \
  -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/v1/responder/runs/{run_id}"
```

## Who a run acts for

A run acts for the user who started it. The execute endpoint records the
user the gateway authenticated (user, team and role), the run is owned by
that user's team, and every request a connector makes for the run carries
that user's gateway identity (`X-Wildbox-User-ID`, `X-Wildbox-Team-ID`,
`X-Wildbox-Role`) and `X-Gateway-Secret`, the headers the gateway itself
puts on a request it forwards for that user. It also states
`X-Wildbox-Auth-Type: service`: tools, data and guardian check API-key
scopes themselves and refuse a request that does not say what its
credential is. The scopes of the key that started the run do not travel
with it; the gateway checked `write` when the run was started (#637).

- **The services authorize each call for that user.** The tools a run
  starts, the AI analysis tasks it queues and the vulnerabilities it
  records belong to that user and team, and a call the user may not make
  fails the step:
  Guardian lets only owners and admins create a vulnerability, so that step
  fails when a member runs the playbook. The responder has no identity of
  its own and never acts as anyone else.
- **A run without a complete caller fails before its first step**, and a
  connector sends nothing without a caller or without
  `GATEWAY_INTERNAL_SECRET`.
- **The identity is scoped to the run.** The worker sets it when the run
  starts and resets it when the run ends, however it ends, so the next run
  in the same worker thread does not inherit it. A step that hands work to
  another thread must run it in a copy of the current context
  (`copy_context().run`); a thread started without one has no caller, and
  its requests are refused.
- **The connectors call the services directly** on the internal network, as
  the agents service does, at the addresses in `WILDBOX_*_URL`. Each
  request is sent once; a refusal or an unreachable service fails the step
  with the service's status, and the step's `on_failure` decides what
  happens next.
- **API keys.** The gateway checks an API key's scopes on the execute
  request, which needs `write`. A `write` key may already run tools and
  write Guardian data directly, so a run does not do more than the key
  could.

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

  - name: "log_security_alert"
    action: "system.notification"
    condition: "steps.threat_verdict is defined and steps.threat_verdict.output.overall_result"
    # ...
```

It returns `overall_result`, `conditions` (each name and whether it held),
`matched` (the names that held, in order), `matched_count`, `total`,
`min_true` and `timestamp`. Each condition must render to `True` or
`False`, or be a boolean; any other value, such as a nested mapping or a
word like `malicious`, fails the step instead of being guessed at.

### system.notification

`system.notification` delivers nothing. No e-mail, webhook or chat message
leaves the responder: the message is written to the service log, and the
step's input and output to the run's log and record, where whoever reads
the run (`GET /v1/runs/{run_id}`) sees it.

```yaml
  - name: "log_security_alert"
    action: "system.notification"
    input:
      channel: "security-alerts"   # a label, recorded as given
      message: "Malicious URL: {{ trigger.url }}"
      priority: "high"
```

It returns `status: logged`, `delivered: false`, and the `channel`,
`message` and `priority` it was given, with a `timestamp`. No channel is
looked up or contacted. To have an alert reach people, read it from the
run, or have whatever polls the run forward it.

### Connector actions

The `api`, `wildbox` and `data` connectors call these routes, as the run's
caller. Their parameters are the actions' arguments in
`app/connectors/`.

| Action | Service | Route |
| ------ | ------- | ----- |
| `api.run_tool`, `wildbox.run_tool` | tools | `POST /api/tools/{tool}`, body: the tool's input |
| `api.run_tool` with `async_execution: true` | tools | `POST /api/tools/{tool}/async`; returns the task |
| `api.get_execution_status`, `api.cancel_execution` | tools | `GET`, `DELETE /api/tasks/{task_id}` |
| `api.list_tools`, `api.get_tool_info` | tools | `GET /api/tools`, `GET /api/tools/{tool}/info` |
| `wildbox.analyze_ioc` | agents | `POST /v1/analyze`; returns the task |
| `wildbox.create_vulnerability` | guardian | `GET /api/v1/assets/assets/?search=`, then `POST /api/v1/vulnerabilities/` |
| `wildbox.get_vulnerabilities` | guardian | `GET /api/v1/vulnerabilities/` |
| `wildbox.get_asset_info` | guardian | `GET /api/v1/assets/assets/{id}/` |
| `wildbox.query_threat_intel`, `data.search_indicators` | data | `GET /api/v1/indicators/search` |
| `data.lookup_indicators` | data | `POST /api/v1/indicators/lookup` |

- **A tool's parameters** are the tool's input schema, sent as the body
  itself. A tool name or a task id that is not of the shape the tools
  service issues fails the step before anything is sent.
- **`wildbox.analyze_ioc` returns a task, not a verdict.** The agents
  service analyzes in the background; the user who ran the playbook reads
  the report at the task's `result_url`. A step cannot wait for it.
- **`wildbox.create_vulnerability`** records the vulnerability against the
  one Guardian asset whose name or IP address is `asset_name`; with none,
  or more than one, the step fails and nothing is created.
- **There is no blacklist action.** The data service has no blacklist; it
  serves threat intelligence to read. No service isolates an endpoint, and
  Guardian's remediation tickets mirror an external ticketing system, so
  there are no actions for those either.

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
| `GATEWAY_INTERNAL_SECRET` | Checked on the requests the responder receives, and sent with the run's caller on the requests its connectors make. Required. | none |
| `WILDBOX_API_URL` | Tools service URL | `http://open-security-tools:8000` |
| `WILDBOX_DATA_URL` | Data service URL | `http://open-security-data:8002` |
| `WILDBOX_GUARDIAN_URL` | Guardian URL | `http://open-security-guardian:8013` |
| `WILDBOX_AGENTS_URL` | Agents service URL | `http://open-security-agents:8006` |
| `WILDBOX_SENSOR_URL` | Accepted and unused: no connector calls the sensor | `http://open-security-sensor:8004` |
| `DEBUG` | Enable debug mode | `false` |

The URL defaults are the services' addresses in the main
`docker-compose.yml`, which also sets them. Each must be an absolute
`http(s)` URL, or the service does not start.

The playbook worker (`python -m dramatiq app.workflow_engine`) makes the
connector calls, so it needs `GATEWAY_INTERNAL_SECRET` and the
`WILDBOX_*_URL` variables; in the Docker image it runs in the same container
as the API. The main `docker-compose.yml` sets the URLs to the services'
container addresses.

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
│   ├── auth.py                 # Gateway authentication of requests
│   ├── models.py               # Pydantic models
│   ├── config.py               # Configuration management
│   ├── caller.py               # The identity a run acts for
│   ├── playbook_parser.py      # YAML playbook parser
│   ├── workflow_engine.py      # Dramatiq workflow engine
│   └── connectors/             # Connector framework
│       ├── __init__.py
│       ├── base.py             # call_service: every request, as the caller
│       ├── api_connector.py    # tools
│       ├── data_connector.py   # data
│       ├── system_connector.py # local actions
│       └── wildbox_connector.py # tools, data, guardian, agents
├── playbooks/                  # YAML playbook definitions
├── scripts/                    # Utility scripts
├── tests/                      # Test suite
└── logs/                       # Application logs
```

### Adding Connectors

1. Create a new connector class inheriting from `BaseConnector`
2. Register it in the connector registry
3. Implement required action methods. Send every request to another Wildbox
   service through `call_service`, which adds the run's caller and the
   gateway secret.
4. Add the action to `ACTIONS` in
   `tests/unit/test_connectors_reach_the_services.py`, which checks its
   route and body against the target service's source.

## 📊 Monitoring

- **Health Endpoint**: `/health`: service health
- **Metrics Endpoint**: `/metrics`: Prometheus metrics
- **Run Status**: `/v1/runs/{run_id}`: a run's step results and log

## 🤝 Integration

The Responder integrates with other Wildbox components:

- **Open Security Tools**: Tool execution, synchronous or queued
- **Open Security Data**: Threat intelligence lookups
- **Open Security Guardian**: Vulnerabilities and assets
- **Open Security Agents**: AI analysis of an IOC, queued as a task

## 📝 License

Part of the Wildbox Security Suite - MIT License
