# Responder Service API

The responder is the FastAPI service that runs playbooks: YAML workflows loaded at
startup, whose steps a background worker executes in order. This page lists the routes
defined in `open-security-responder/app/main.py` and how to reach them through the
gateway.

In the examples, `<host>` is the name you reach the gateway by, and IDs and
credentials are placeholders.

## Table of Contents

- [Base URL and routing](#base-url-and-routing)
- [Authentication and permissions](#authentication-and-permissions)
- [Endpoint summary](#endpoint-summary)
- [List playbooks](#list-playbooks)
- [Execute a playbook](#execute-a-playbook)
- [Read a run](#read-a-run)
- [Cancel a run](#cancel-a-run)
- [Reload playbooks](#reload-playbooks)
- [List connectors](#list-connectors)
- [Who a run acts for](#who-a-run-acts-for)
- [Connector actions](#connector-actions)
- [Configuration](#configuration)
- [Health check](#health-check)
- [Rate limits](#rate-limits)
- [Errors](#errors)

---

## Base URL and routing

The responder serves its API under `/v1/`. The gateway strips
`/api/v1/responder/` and adds `/v1/`:

```text
https://<host>/api/v1/responder/<path>  ->  responder /v1/<path>
```

So `/v1/playbooks` on the service is `https://<host>/api/v1/responder/playbooks`
through the gateway. Set up a shell for the examples:

```bash
CA=open-security-gateway/ssl/wildbox.crt
BASE="https://<host>/api/v1/responder"
```

---

## Authentication and permissions

The gateway authenticates every request and passes the caller's user, team and role
to the responder in trusted headers. Use either credential:

- **JWT bearer token.** Sign in with `POST https://<host>/auth/jwt/login`
  (form-encoded `username` and `password`) and send the `access_token` as
  `Authorization: Bearer <token>`.
- **API key.** Create one with `POST /api/v1/identity/api-keys` or
  `POST /api/v1/identity/teams/{team_id}/api-keys` (see the
  [Identity Service API](../identity/endpoints.md)) and send it as
  `X-API-Key: <key>`.

```bash
TOKEN=$(curl -s --cacert "$CA" -X POST "https://<host>/auth/jwt/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=analyst@example.com" \
  --data-urlencode "password=<password>" | jq -r .access_token)
```

An API key with scopes needs `read` (or `write`) for `GET` requests and `write` for
`POST` and `DELETE`; a key created without scopes, or with `admin`, is unrestricted.

Roles:

- Any team member can list playbooks and connectors, execute a playbook, and read
  or cancel the team's runs.
- Only `owner` and `admin` can reload playbooks (`403` otherwise).
- Runs belong to the team that started them. Another team's run answers `404`, the
  same as a run that does not exist.
- A run acts for the user who started it; see [Who a run acts for](#who-a-run-acts-for).

---

## Endpoint summary

| Method | Gateway path | Service path | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/responder/playbooks` | `/v1/playbooks` | List loaded playbooks |
| `POST` | `/api/v1/responder/playbooks/{playbook_id}/execute` | `/v1/playbooks/{playbook_id}/execute` | Start a run |
| `GET` | `/api/v1/responder/runs/{run_id}` | `/v1/runs/{run_id}` | Read a run |
| `DELETE` | `/api/v1/responder/runs/{run_id}` | `/v1/runs/{run_id}` | Cancel a run |
| `POST` | `/api/v1/responder/playbooks/reload` | `/v1/playbooks/reload` | Reload playbooks from disk (owner/admin) |
| `GET` | `/api/v1/responder/connectors` | `/v1/connectors` | List connectors and their actions |

There is no route to read a single playbook definition and no route to list runs;
none of the list routes takes filter or paging parameters.

---

## List playbooks

`GET /api/v1/responder/playbooks`

```bash
curl -s --cacert "$CA" "$BASE/playbooks" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "playbooks": [
    {
      "playbook_id": "simple_notification",
      "name": "Simple Logging Test",
      "description": "A basic playbook that logs a message for testing the workflow engine; it sends no notification",
      "version": "1.0",
      "author": "Wildbox Security",
      "tags": ["test", "log"],
      "steps_count": 3,
      "trigger_type": "api"
    }
  ],
  "total": 1
}
```

The response lists every playbook the service loaded. The repository ships
`simple_notification`, `triage_ip`, `triage_url`, `hash_evidence`,
`asset_vulnerabilities` and `all_star_e2e` in
`open-security-responder/playbooks/`. `asset_vulnerabilities` takes an
`asset_id` and reads that asset and the vulnerabilities recorded on it from
Guardian, as the user who runs it; it reaches no other service.

---

## Execute a playbook

`POST /api/v1/responder/playbooks/{playbook_id}/execute`

The body is optional. `trigger_data` is an object the playbook's steps read as
`trigger` in their templates (for example `{{ trigger.message }}`); it defaults to
`{}`.

```bash
curl -s --cacert "$CA" -X POST "$BASE/playbooks/simple_notification/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"trigger_data": {"message": "hello from the API"}}'
```

**Response (202 Accepted)**:

```json
{
  "run_id": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
  "playbook_id": "simple_notification",
  "playbook_name": "Simple Logging Test",
  "status": "accepted",
  "status_url": "/api/v1/responder/runs/6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
  "message": "Playbook 'Simple Logging Test' execution started"
}
```

`status_url` is where to [read the run](#read-a-run): its path on the gateway,
without scheme or host, to resolve against the address you called
(`https://<host>` + `status_url`). It is always
`/api/v1/responder/runs/{run_id}`; no request header changes it.

An unknown `playbook_id` answers `404`. The run is recorded with the user the
gateway authenticated (user, team and role), and its steps act for that user; see
[Who a run acts for](#who-a-run-acts-for).

---

## Read a run

`GET /api/v1/responder/runs/{run_id}`

```bash
curl -s --cacert "$CA" "$BASE/runs/<run-id>" \
  -H "Authorization: Bearer $TOKEN"
```

Abridged response for a finished run of `simple_notification` (three steps; only
the first is shown in `step_results`, and the log list is shortened):

```json
{
  "run_id": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
  "playbook_id": "simple_notification",
  "playbook_name": "Simple Logging Test",
  "status": "completed",
  "start_time": "2026-10-03T09:15:02.118000",
  "end_time": "2026-10-03T09:15:04.461000",
  "trigger_data": {"message": "hello from the API"},
  "step_results": [
    {
      "step_name": "log_message",
      "status": "completed",
      "start_time": "2026-10-03T09:15:02.201000",
      "end_time": "2026-10-03T09:15:02.233000",
      "output": {"<key>": "<value returned by the system.log action>"},
      "error": null,
      "duration_seconds": 0.032
    }
  ],
  "context": {
    "trigger": {"message": "hello from the API"},
    "run": {
      "id": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
      "playbook_id": "simple_notification",
      "started_at": "2026-10-03T09:15:02.118000+00:00"
    },
    "steps": {
      "log_message": {"output": {"<key>": "<value>"}, "status": "completed", "duration": 0.032}
    }
  },
  "logs": [
    "[2026-10-03T09:15:02.120000] INFO: Playbook 'Simple Logging Test' queued for execution"
  ],
  "error": null,
  "duration_seconds": 2.343
}
```

The timestamps and IDs above are illustrative. The fields come from
`PlaybookExecutionResult` in `app/models.py`:

| Field | Description |
| --- | --- |
| `status` | `queued`, `pending`, `running`, `cancelling`, `completed`, `failed` or `cancelled` |
| `step_results` | One entry per step the worker reached, with its own `status`, `output`, `error` and timing. A step its `condition` skipped has an entry too: `status` `completed`, `output` `{"skipped": true, "reason": "condition_failed"}` |
| `context` | The run's template context: `trigger`, `run` and the outputs of finished steps under `steps` |
| `logs` | Log lines recorded during the run |
| `error` | The failure reason when `status` is `failed` |

Run records are kept for `EXECUTION_RETENTION_DAYS` days (30 by default), then
expire. When the service starts, it closes any run still recorded as `running`,
`queued` or `cancelling` whose worker has not updated it for 15 minutes: a
`cancelling` run is recorded as `cancelled`, the others as `failed`.

---

## Cancel a run

`DELETE /api/v1/responder/runs/{run_id}`

```bash
curl -s --cacert "$CA" -X DELETE "$BASE/runs/<run-id>" \
  -H "Authorization: Bearer $TOKEN"
```

The answer is the status the run is in afterward. **Response (202 Accepted)**,
for a running run:

```json
{
  "run_id": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
  "status": "cancelling",
  "message": "Cancel requested. The step in progress runs to its end and is recorded as it ends; no further step will start. The run's status becomes 'cancelled' when the worker stops it."
}
```

| Run was | Status code | `status` |
| --- | --- | --- |
| `queued` or `pending` | `200` | `cancelled`: no step runs |
| `running` | `202` | `cancelling`: the step in progress runs to its end, no further step starts, then the run reads `cancelled` |
| `cancelling` | `202` | `cancelling`: the first request stands |
| `completed`, `failed` or `cancelled` | `200` | Its status, unchanged |

- **A step in progress is not interrupted.** Its call to another service has been
  sent and may already have taken effect, so it is recorded as it ended in
  `step_results`; the run's log names the steps that did not run.
- **A cancelled run stays cancelled.** The worker's status writes are
  compare-and-set against the run's status and its cancel request, so it cannot
  write `completed` or `failed` over a cancel. A cancel that arrives after the run's
  last write answers `200` with `completed` or `failed` and changes nothing.
- **The request is durable.** It is stored in Redis with the run, and the worker
  checks it before the run starts and before every step. A run another team owns
  answers `404`, as an unknown run does.

---

## Reload playbooks

`POST /api/v1/responder/playbooks/reload` (owner or admin)

Reloads the playbook files from disk and returns what was loaded:

```json
{
  "message": "Playbooks reloaded successfully",
  "total_loaded": 6,
  "playbooks": ["simple_notification", "triage_ip", "triage_url", "hash_evidence", "asset_vulnerabilities", "all_star_e2e"]
}
```

---

## List connectors

`GET /api/v1/responder/connectors`

Lists the connectors registered in the service (`system`, `wildbox`, `data` and
`api`) and the actions each one offers. Playbook steps call an action as
`connector.action`.

```bash
curl -s --cacert "$CA" "$BASE/connectors" \
  -H "Authorization: Bearer $TOKEN"
```

Response, shortened to one connector:

```json
{
  "connectors": {
    "data": {
      "name": "data",
      "actions": {
        "search_indicators": "Search threat indicators by value, type and confidence",
        "lookup_indicators": "Look up a list of indicators and report which are known"
      }
    }
  },
  "total": 4
}
```

Each connector is listed with its `name` and its `actions`, nothing else. The
service addresses the connectors call are deployment configuration (see
[Configuration](#configuration)) and are not in the response.

---

## Who a run acts for

A run acts for the user who started it. The execute endpoint records the user the
gateway authenticated (user, team and role), the run is owned by that user's team,
and every request a connector makes for the run carries that user's
`X-Wildbox-User-ID`, `X-Wildbox-Team-ID` and `X-Wildbox-Role` headers with
`X-Gateway-Secret`, and `X-Forwarded-Proto: https`: the headers the gateway itself
puts on a request it forwards for that user (`open-security-responder/app/caller.py`).
Guardian redirects a plain-HTTP request without the last one to `https://`, so a
Guardian action sent without it is answered `301`. The connectors also state
`X-Wildbox-Auth-Type: service`: tools, data and guardian check API-key scopes
themselves and refuse a request that does not say what its credential is. The
scopes of the key that started the run do not travel with it.

- **The services authorize each call for that user.** The tool tasks a run starts,
  the AI analysis tasks it queues and the vulnerabilities it records belong to that
  user and team, and a call the user may not make fails the step. Guardian lets
  only owners and admins create a vulnerability, so `wildbox.create_vulnerability`
  fails when a member runs the playbook. The responder has no identity of its own.
- **A run without a complete caller fails before its first step**, and a connector
  sends nothing when no caller is set or `GATEWAY_INTERNAL_SECRET` is missing.
- **The identity is scoped to the run.** The worker sets it when the run starts and
  resets it when the run ends, however it ends, so the next run in the same worker
  thread does not inherit it.
- **The connectors call the services directly** on the internal network, at the
  `WILDBOX_*_URL` addresses, not through the gateway. Each request is sent once; a
  refusal or an unreachable service fails the step with the service's status, and
  the step's `on_failure` decides what happens next.
- **API keys.** The gateway checks an API key's scopes on the execute request,
  which needs `write`. A `write` key can already run tools and write data
  directly, so a run does not do more than the key could.

---

## Connector actions

The `api`, `wildbox` and `data` connectors call these routes on the services, as
the run's caller. Their parameters are the arguments of the actions in
`open-security-responder/app/connectors/`.

| Action | Service | Route |
| --- | --- | --- |
| `api.run_tool`, `wildbox.run_tool` | tools | `POST /api/tools/{tool}`, body: the tool's input |
| `api.run_tool` with `async_execution: true` | tools | `POST /api/tools/{tool}/async`; returns the task |
| `api.get_execution_status`, `api.cancel_execution` | tools | `GET`, `DELETE /api/tasks/{task_id}` |
| `api.list_tools`, `api.get_tool_info` | tools | `GET /api/tools`, `GET /api/tools/{tool}/info` |
| `wildbox.analyze_ioc` | agents | `POST /v1/analyze` with `{"ioc": {"type", "value"}, "priority"}`; returns the task |
| `wildbox.create_vulnerability` | guardian | `GET /api/v1/assets/assets/?search=`, then `POST /api/v1/vulnerabilities/` |
| `wildbox.get_vulnerabilities` | guardian | `GET /api/v1/vulnerabilities/` |
| `wildbox.get_asset_info` | guardian | `GET /api/v1/assets/assets/{id}/` |
| `wildbox.query_threat_intel`, `data.search_indicators` | data | `GET /api/v1/indicators/search` |
| `data.lookup_indicators` | data | `POST /api/v1/indicators/lookup` |

The `system` connector calls no service. Its actions are `log`, `sleep`,
`validate`, `extract`, `evaluate`, `create_report`, `notification`, `timestamp`
and `uuid`.

- **A tool's parameters** are the tool's input schema, sent as the body itself. A
  tool name or a task ID that is not of the shape the tools service issues fails
  the step before anything is sent.
- **`wildbox.analyze_ioc` returns a task, not a verdict.** The agents service
  analyzes in the background; the user who ran the playbook reads the report at the
  task's `result_url`. A step cannot wait for it. `ioc_type` is one of `ipv4`,
  `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256` or `email`.
- **`wildbox.create_vulnerability`** records the vulnerability against the one
  Guardian asset whose name or IP address is `asset_name`; with none, or more than
  one, the step fails and nothing is created.
- **`system.notification` delivers nothing.** It writes the message to the service
  log, the step's input and output go to the run's record, and it answers `status: logged`, `delivered: false`, with the
  `channel`, `message` and `priority` it was given. No e-mail, webhook or chat
  message leaves the responder; to have an alert reach people, read it from the run.
- **Removed actions.** There are no blacklist, endpoint isolation or ticket actions
  (`add_to_blacklist`, `isolate_endpoint`, `create_ticket` and the data
  connector's blacklist and IOC-writing actions): no service serves what they
  called. A step that names one fails as an unknown action, before any request is
  sent. There is no ticketing or chat connector.

---

## Configuration

Environment variables of the responder API and of its playbook worker
(`python -m dramatiq app.workflow_engine`, which makes the connector calls and runs
in the same container as the API):

| Variable | Default | Description |
| --- | --- | --- |
| `GATEWAY_INTERNAL_SECRET` | none | Checked on the requests the responder receives, and sent with the run's caller on the requests its connectors make. Required |
| `WILDBOX_API_URL` | `http://open-security-tools:8000` | Tools service |
| `WILDBOX_DATA_URL` | `http://open-security-data:8002` | Data service |
| `WILDBOX_GUARDIAN_URL` | `http://open-security-guardian:8013` | Guardian |
| `WILDBOX_AGENTS_URL` | `http://open-security-agents:8006` | Agents service |
| `WILDBOX_SENSOR_URL` | `http://open-security-sensor:8004` | Accepted and unused: no connector calls the sensor |
| `REDIS_URL` | `redis://localhost:6381/0` | Run state and the worker queue |
| `PLAYBOOKS_DIRECTORY` | `./playbooks` | Where the playbook YAML files are loaded from |
| `EXECUTION_RETENTION_DAYS` | `30` | How long run records are kept |
| `ENVIRONMENT` | none | `/docs`, `/redoc` and `/openapi.json` are served only when it is `development`. Required by `docker-compose.yml` |
| `LOG_LEVEL` | `INFO` | Log level of the API |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated origins the service's own CORS headers allow |

The URL defaults are the services' addresses in `docker-compose.yml`, which also
sets them. Each must be an absolute `http` or `https` URL with a host and no query,
or the service does not start (`open-security-responder/app/config.py`).

The responder has no SQL database: runs and the worker queue are in Redis. It
reads no `DATABASE_URL`, and `docker-compose.yml` passes it none.

---

## Health check

The responder's health check is `GET /health` on the service's own port (bound to
`127.0.0.1:8018` in `docker-compose.yml`). It is not under `/v1/`, so the gateway
does not route it (`/api/v1/responder/health` maps to `/v1/health`, which does not
exist). It returns `{"status": "healthy", "timestamp": "..."}`, or
`"status": "unhealthy"` when Redis does not answer.

---

## Rate limits

The responder has no rate limit of its own. The gateway allows each team
`RATE_LIMIT_PER_HOUR` requests per hour (10000 by default), enforced in fixed
60-second windows of one sixtieth of that (166 by default); `X-RateLimit-Limit`,
`X-RateLimit-Remaining` and `X-RateLimit-Reset` describe the current minute window,
and `X-RateLimit-Policy` is `<per hour>;w=3600`. A request over the limit gets
`429`. A `RATE_LIMIT_PER_HOUR` that is not a whole number from 1 to 1000000000
stops the gateway at startup.

---

## Errors

Responder errors use the shared Wildbox error format
(`open-security-shared/errors.py`):

```json
{
  "error": {
    "code": 404,
    "message": "Playbook 'unknown_playbook' not found",
    "type": "HTTPException",
    "request_id": "<request id>"
  }
}
```

| Status | Meaning |
| --- | --- |
| `202` | Playbook run accepted, or a running run is being canceled |
| `401` | No valid credential (answered by the gateway) |
| `403` | Role or API key scope does not allow the request, or the caller has no complete user and team identity |
| `404` | Unknown playbook, or a run that does not exist or belongs to another team |
| `422` | The request body is not valid |
| `429` | Gateway rate limit exceeded |
| `500` | The service failed to handle the request |

---

## Related Documentation

- [Identity Service API](../identity/endpoints.md) - Sign-in and API keys
- [Guardian Service API](../guardian/endpoints.md) - Asset and vulnerability management
- [Tools Service API](../tools/endpoints.md) - Tool execution
- [Authentication guide](../../guides/authentication.md) - Tokens and API keys through the gateway
- [Security Policy](../../security/policy.md) - Authentication requirements
