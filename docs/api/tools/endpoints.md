# Tools Service API

**Gateway paths**: `https://<host>/api/v1/tools...` (proxied to the service's
`/api/tools...`) and `https://<host>/api/v1/tasks...` (proxied to the
service's `/api/tasks...`)
**Authentication**: through the gateway only, with a JWT bearer token or an
API key sent as `X-API-Key`

Host names, IDs and keys in the examples are placeholders.

## Overview

The tools service runs the security tools found under
`open-security-tools/app/tools` (52 on 2 October 2026). Each tool is a
plugin with a name, metadata, an input schema and an output schema; the
service discovers them at startup and exposes one run endpoint per tool. The
catalog is whatever `GET /api/v1/tools` returns on your deployment: this
page does not list the tools.

A tool runs in one of two ways:

- **Synchronously**: `POST /api/v1/tools/{tool_name}` answers with the
  tool's output.
- **Asynchronously**: `POST /api/v1/tools/{tool_name}/async` queues the run
  and answers with a task ID that its submitter reads, cancels and lists
  under `/api/v1/tasks`.

### TLS Certificate Verification

Tools that connect over HTTPS verify the certificate chain and the host name.
When verification fails, the scan returns `success: false` with the reason
(for example `self-signed certificate`) and sends no further request; it does
not retry without verification. Tool inputs built on the shared input schema
accept `verify_ssl` (default `true`). Setting it to `false` lets that one scan
read content from whoever answers the connection, including an interceptor,
so its results can no longer be trusted.

`ssl_analyzer`, `ca_analyzer` and `pki_certificate_manager` exist to inspect
certificates, including broken ones: they read the certificate over an
unverified handshake, also attempt a verified one, and report an untrusted
certificate as a finding.

### Network Target Policy

Before a tool runs, the service checks where it would connect
(`enforce_target_policy` in `open-security-tools/app/target_policy.py`). It
runs the URL guard on every URL in the input, then checks the host, address
and range fields of the network tools: `port_scanner`,
`network_port_scanner`, `network_vulnerability_scanner`, `network_scanner`,
`iot_security_scanner`, `ssl_analyzer`, `ca_analyzer`,
`pki_certificate_manager`, `database_security_analyzer`, `dns_enumerator`
(its `dns_servers`, and the name servers it attempts a zone transfer from)
and the registry of a `container_security_scanner` image. Unless the
operator allows them, it refuses:

- addresses that are private, loopback, link-local, unspecified, multicast,
  reserved, shared (`100.64.0.0/10`) or otherwise not globally reachable,
  such as the documentation ranges, and IPv4 addresses embedded in IPv6
  ones (IPv4-mapped, 6to4, NAT64);
- a CIDR or address range that contains such an address, and any range of
  more than 1,024 addresses (an IPv4 `/22`), checked before the range is
  expanded;
- a host name that resolves to such an address (every answer is checked)
  or does not resolve; both answer with the same message;
- the deployment's own names: every name without a dot (`wildbox-redis`,
  `postgres`, `gateway`), `localhost`, names ending in `.localhost`,
  `.local`, `.internal`, `.localdomain` or `.home.arpa`, and the cloud
  metadata names;
- spellings that are not canonical (`127.1`), and values with whitespace
  or control characters.

How a refusal reaches the caller depends on the path: the synchronous run
answers **400** with the reason in `error.message`, an asynchronous run
ends as a task with status `failed` and the reason in `error`, and a
`security_automation_orchestrator` step that names a refused target fails.
The reason names the policy, for example
`Target '10.0.0.5' is a private, loopback, link-local, multicast, reserved or otherwise internal address (network target policy; operators can allow internal targets with TOOLS_ALLOWED_INTERNAL_TARGETS)`.

`TOOLS_ALLOWED_INTERNAL_TARGETS` (empty by default) opens internal targets
for every caller of every network tool. It is a comma-separated list of
CIDR ranges with their host bits zero, IP addresses and host names, for
example `10.20.0.0/16,192.168.50.0/24,lab-dc01`. An address is allowed
inside a listed range; a range when all its internal addresses are inside
listed ranges; a host name when it is listed exactly (no subdomains) or
when all its internal addresses are inside listed ranges. Set it in `.env`:
`docker-compose.yml` passes it to both the `api` service and the
`tools-worker`, which checks asynchronous runs. An entry that is not a
CIDR range, an IP address or a host name stops both at startup. The range
limit of 1,024 addresses per input still applies to allowed ranges.

The check resolves a name, and most tools resolve it again when they
connect: a name whose DNS answer changes between the two lookups can
still reach an internal address in that window.

`network_scanner` takes `network` as an IP address, a CIDR range or a
last-octet range written `a.b.c.10-20`, at most 1,024 addresses; it
refuses a larger range before any probe. It pings each host (`scan_type`
`ping`, the default) and, with `scan_type` `tcp`, also tries a TCP connect
to common ports on the hosts that answer. `timeout` (seconds per probe,
1 to 30, default 3) and `max_threads` (concurrent probes, 1 to 100,
default 50) bound the scan.

## Table of Contents

- [Authentication](#authentication)
- [Endpoint Summary](#endpoint-summary)
- [Tool Catalog](#tool-catalog)
- [Tool Execution](#tool-execution)
- [Asynchronous Tasks](#asynchronous-tasks)
- [Health and Internal Endpoints](#health-and-internal-endpoints)
- [Rate Limits](#rate-limits)
- [Errors](#errors)
- [Examples](#examples)

## Authentication

Every request goes through the gateway. The gateway validates the
credential with the identity service, then forwards the caller to the tools
service as `X-Wildbox-User-ID`, `X-Wildbox-Team-ID` and `X-Wildbox-Role`
headers, together with the `X-Gateway-Secret` proof of origin. The service
answers 401 to a request that does not carry those headers, so its own port
is not an entry point. Its `API_KEY` setting is not a credential: the direct
`X-API-Key` path was removed in #565.

Get a token with the gateway login route:

```bash
CA=open-security-gateway/ssl/wildbox.crt
TOKEN=$(curl -s --cacert "$CA" -X POST https://<host>/auth/jwt/login \
  --data-urlencode "username=$ADMIN_EMAIL" \
  --data-urlencode "password=$ADMIN_PASSWORD" | jq -r .access_token)

curl -s --cacert "$CA" https://<host>/api/v1/tools \
  -H "Authorization: Bearer $TOKEN"
```

Or create an API key (`POST /api/v1/identity/api-keys`, or
`POST /api/v1/identity/teams/{team_id}/api-keys` for a team key) and send
it as `X-API-Key: <key>`. The
[Authentication and sessions guide](../../guides/authentication.md) covers
both credentials.

A JWT is not limited by scopes. An API key with scopes needs the following
ones, which the gateway checks before the request reaches the service:

| Request | Required scope |
| --- | --- |
| `GET /api/v1/tools` | `read` |
| `GET /api/v1/tools/{tool_name}/info` | `tools:read` |
| `POST /api/v1/tools/{tool_name}`, `POST /api/v1/tools/{tool_name}/async` | `tools:execute` |
| `GET /api/v1/tasks`, `GET /api/v1/tasks/{task_id}` | `tools:read` |
| `DELETE /api/v1/tasks/{task_id}` | `tools:execute` |

`GET /api/v1/tools` has no subpath, so the gateway maps it to the generic
`read` scope rather than `tools:read`. A key missing the scope gets
403 `insufficient_scope`.

## Endpoint Summary

| Method | Gateway path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/tools` | List the tools |
| `GET` | `/api/v1/tools/{tool_name}/info` | Metadata and JSON schemas of one tool |
| `POST` | `/api/v1/tools/{tool_name}` | Run a tool and wait for its output |
| `POST` | `/api/v1/tools/{tool_name}/async` | Queue a run, get a task ID |
| `GET` | `/api/v1/tasks` | The caller's tasks of the last day |
| `GET` | `/api/v1/tasks/{task_id}` | Status and result of one task |
| `DELETE` | `/api/v1/tasks/{task_id}` | Cancel a pending or running task |

The gateway answers any other `/api/...` path with
404 `{"error":"endpoint_not_found", ...}`, and `/tools/` (the removed
standalone tools UI) with 404 as well.

## Tool Catalog

### GET /api/v1/tools

The tools this deployment loaded. No query parameters, no pagination.

```bash
curl -s --cacert "$CA" https://<host>/api/v1/tools \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK)**: a JSON array, one object per tool.

```json
[
  {
    "name": "hash_generator",
    "display_name": "Hash Generator",
    "description": "Generate and analyze various cryptographic hashes with security recommendations",
    "version": "1.0.0",
    "author": "Wildbox Security",
    "category": "cryptography",
    "endpoint": "/api/tools/hash_generator"
  }
]
```

| Field | Description |
| --- | --- |
| `name` | Tool name, the `{tool_name}` of every other route |
| `display_name` | From the tool's metadata; the name in title case when the tool sets none |
| `description` | From the tool's metadata; `No description available` when absent |
| `version`, `author` | From the tool's metadata; `unknown` when absent |
| `category` | From the tool's metadata; `general` when absent |
| `endpoint` | The run path on the service (`/api/tools/{name}`). Through the gateway the same tool runs at `/api/v1/tools/{name}` |

### GET /api/v1/tools/{tool_name}/info

The tool's metadata and the JSON Schema of its input and output. A client
builds the request body from `input_schema`.

```bash
curl -s --cacert "$CA" https://<host>/api/v1/tools/hash_generator/info \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK)**:

```json
{
  "name": "hash_generator",
  "display_name": "Hash Generator",
  "description": "Generate and analyze various cryptographic hashes with security recommendations",
  "version": "1.0.0",
  "author": "Wildbox Security",
  "category": "cryptography",
  "endpoint": "/api/tools/hash_generator",
  "input_schema": {"title": "HashGeneratorInput", "type": "object", "properties": {"...": "..."}},
  "output_schema": {"title": "HashGeneratorOutput", "type": "object", "properties": {"...": "..."}}
}
```

The metadata keys are the tool's own `TOOL_INFO` entries, so they vary from
tool to tool; entries that are classes or functions are left out. `name`,
`endpoint`, `input_schema` and `output_schema` are always present.
`input_schema` and `output_schema` are the Pydantic JSON Schemas of the
models the run endpoint validates with and answers with; either is `null`
when the tool has no such model.

**404** when no tool has that name.

## Tool Execution

### POST /api/v1/tools/{tool_name}

Run a tool and wait for its output. The request body is a JSON object
matching the tool's `input_schema`.

```bash
curl -s --cacert "$CA" -X POST https://<host>/api/v1/tools/hash_generator \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"input_text": "wildbox", "hash_types": ["sha256"]}'
```

**Response (200 OK)**: an object of the tool's output schema. The service
sets `tool_name` and `execution_time` (seconds) on it. Most tools' outputs
also carry `success`; a tool that ran but could not do its job (for example
a TLS verification failure) answers 200 with `success: false` and the reason.

The service refuses a run with these statuses:

| Status | When | `error.message` |
| --- | --- | --- |
| 400 | A URL or a network target in the input is refused (see [Network Target Policy](#network-target-policy)) | The policy's reason |
| 404 | No tool has that name | `Not Found` |
| 403 | The tool acts on behalf of the caller and the caller is not authorized for it (today `sql_injection_scanner`, which also needs an authenticated caller) | The authorization reason |
| 408 | The run exceeded its time limit | `Tool execution timed out` |
| 422 | The body is not a JSON object | `Request validation failed` |
| 422 | The body does not match the input schema | `Input validation failed`; `error.details.errors` lists `loc`, `msg` and `type` for each field. Submitted values are not echoed back |
| 500 | The tool failed | `Tool execution failed` |

The time limit is the input's `timeout` field when the tool's schema has
one (the shared input schema defaults it to 30 seconds, 300 at most),
otherwise the service's `TOOL_TIMEOUT` (default 300 seconds). The gateway,
however, waits 60 seconds for the service to answer
(`proxy_read_timeout` in `open-security-gateway/nginx/includes/proxy_params.conf`):
a run that takes longer gets a 504 from the gateway while the tool keeps
running. Use the asynchronous endpoint for anything that can take a minute.

## Asynchronous Tasks

### POST /api/v1/tools/{tool_name}/async

Queue a run and return at once. The body is the same tool input as for the
synchronous endpoint.

```bash
curl -s --cacert "$CA" -X POST https://<host>/api/v1/tools/hash_generator/async \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"input_text": "wildbox", "hash_types": ["sha256"]}'
```

**Response (202 Accepted)**:

```json
{
  "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "status": "accepted",
  "tool_name": "hash_generator",
  "status_url": "/api/v1/tasks/1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "message": "Task submitted successfully. Use task_id to check status."
}
```

The submit endpoint does not check the tool name or the input: an unknown
tool, an input that fails validation, or a target the network target
policy refuses all show up later as a task with status `failed` and the
reason in `error`. A tool that refuses the caller shows up as status `refused`.

The service records who submitted the task before queuing it. It answers
**503** (`Asynchronous execution is unavailable`) when it cannot record the
owner or queue the task (Redis or the task queue unreachable).

A queued run is stopped after 9 minutes (Celery soft limit 540 seconds,
hard limit 600 seconds in `open-security-tools/app/celery_app.py`) and then
reports status `timeout`.

### Task Visibility

A task belongs to the user who submitted it. Only that user can read,
cancel or list it. For anyone else, a teammate or an administrator
included, it does not exist: reading or canceling it answers 404, the same
answer as for an unknown task ID, so the response does not confirm that a
task exists, and it is not in their list. A task without an owner record,
such as one submitted before owners were recorded, is not readable.

Owner records expire after a day; a task's result is kept for an hour after
the task finishes (`result_expires=3600`). The task endpoints have their
own prefix, `/api/v1/tasks`, because under `/api/v1/tools/` the segment
after the prefix is a tool name.

### GET /api/v1/tasks/{task_id}

Status, and result once finished, of one of the caller's tasks.

```bash
curl -s --cacert "$CA" https://<host>/api/v1/tasks/1b4e28ba-2fa1-41d2-883f-0016d3cca427 \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK), waiting**:

```json
{
  "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "state": "PENDING",
  "tool_name": "hash_generator",
  "submitted_at": 1790000000.0,
  "status": "pending",
  "message": "Task is waiting to be executed"
}
```

**Response (200 OK), finished**:

```json
{
  "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "state": "SUCCESS",
  "tool_name": "hash_generator",
  "submitted_at": 1790000000.0,
  "status": "completed",
  "error": null,
  "result": {"success": true, "hash_results": ["..."], "tool_name": "hash_generator", "execution_time": 0.012, "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427"},
  "duration": 0.012,
  "completed_at": "2026-10-03T10:00:01.234567"
}
```

`state` is the Celery state. `status` is what a client acts on:

| `state` | `status` | Other fields |
| --- | --- | --- |
| `PENDING` | `pending` | `message` |
| `STARTED` or `RUNNING` | `running` | `message`; `info` with the progress fields `tool_name`, `started_at` and `status` when the worker has written them |
| `SUCCESS` | `completed`, `failed`, `timeout` or `refused` (the task finished and reports how the tool ended) | `error`, `result` (the tool's output when completed), `duration`, `completed_at` |
| `FAILURE` | `failed` | `error` (`Task execution failed (<exception class>)`, never the exception message), `message`, `completed_at` |
| `RETRY` | `retrying` | `message`, `info` (the same failure text as `error` above) |
| `REVOKED` | `cancelled` | `message` (`Task was cancelled`), `completed_at` |

Any other state, including a result record the service cannot read, answers
200 with status `unknown` and `message` `The task state cannot be read`
(`state` is `UNKNOWN` when the record is unreadable). The service reads the
task's record once per request (`open-security-tools/app/api/async_router.py`),
so a task canceled while it is being read answers with one of these states,
not with a 500.

**404** for a task the caller did not submit or that does not exist;
**503** (`Asynchronous execution is unavailable`) when the result backend
(Redis) cannot be reached.

### DELETE /api/v1/tasks/{task_id}

Cancel one of the caller's pending, running or retrying tasks.

```bash
curl -s --cacert "$CA" -X DELETE https://<host>/api/v1/tasks/1b4e28ba-2fa1-41d2-883f-0016d3cca427 \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK)**:

```json
{
  "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
  "status": "cancelled",
  "message": "Task cancellation requested"
}
```

The answer means the cancellation was sent to the worker; reading the task
afterward reports status `cancelled` once the worker has revoked it.

**400** (`Task cannot be cancelled (current state: ...)`) for a task that
has finished or was already canceled; **404** for a task the caller did not
submit or that does not exist; **503** when Redis cannot be reached.

### GET /api/v1/tasks

The caller's tasks of the last day, newest first.

| Query parameter | Type | Description |
| --- | --- | --- |
| `limit` | integer | 1 to 100 (default 50) |

```bash
curl -s --cacert "$CA" "https://<host>/api/v1/tasks?limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK)**:

```json
{
  "tasks": [
    {
      "task_id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
      "tool_name": "hash_generator",
      "submitted_at": 1790000000.0,
      "state": "SUCCESS",
      "status": "completed",
      "status_url": "/api/v1/tasks/1b4e28ba-2fa1-41d2-883f-0016d3cca427"
    }
  ],
  "count": 1
}
```

## Health and Internal Endpoints

These endpoints exist only on the tools service itself. The gateway does
not route them (`/api/v1/tools/health` reaches `/api/tools/health` on the
service, the run path of a tool named `health`, not this endpoint), and the
service does not authenticate them. In the default
`docker-compose.yml` the service port is published on `127.0.0.1:8000`
only, so they are reachable from the Docker host and the internal network,
for health probes and operators.

### GET /health

```bash
curl -s http://127.0.0.1:8000/health
```

**Response (200 OK)**:

```json
{
  "status": "healthy",
  "service": "tools",
  "version": "1.0.0",
  "timestamp": 1790000000.0,
  "response_time_ms": 0.01,
  "environment": "development",
  "tools_count": 52,
  "available_tools": ["api_security_analyzer", "..."],
  "active_executions": 0,
  "max_concurrent_tools": 10,
  "default_timeout": 300
}
```

`status` is `degraded` (with `error`) when the service cannot read its
execution state. The gateway's own `https://<host>/health` reports on the
gateway, not on this service.

### Other Internal Endpoints

| Path | Content |
| --- | --- |
| `/metrics` | Prometheus exposition format: request counts and durations by route (`wildbox_http_requests_total`, `wildbox_http_request_duration_seconds`) and synchronous tool executions by tool and outcome (`wildbox_tool_executions_total`; asynchronous runs happen in the worker, which is not scraped). `monitoring/prometheus.yml` scrapes it |
| `/openapi.json` | The service's OpenAPI document |
| `/api` | Service name, version and tool names |

None of them is part of the public API, and `/health` and these three are
the only routes that answer without the gateway's identity: every other
route under `/api/` answers 401 to a request that does not carry it.

The service has no `/api/system/` routes. `info`, `metrics`,
`operational-metrics` and `health-aggregate` existed there, without
authentication, until they were removed
([#646](https://github.com/fabriziosalmi/wildbox/issues/646)); a request
for one of them answers 404. What they reported is available elsewhere:

| Was in | Now |
| --- | --- |
| `info`: tool names | `GET /api/v1/tools`, through the gateway |
| `info`: environment, concurrency and timeout settings | `GET /health`, above |
| `metrics`, `operational-metrics`: counters of synchronous executions (which stayed at zero) | `wildbox_tool_executions_total` in `/metrics` |
| `health-aggregate`: the health of the other services (it reported a healthy stack as `degraded`) | Each service's own health check (`docker compose ps`), and the `up` series Prometheus records for every service it scrapes |

## Rate Limits

The gateway applies two limits to tools and task requests:

- **Per team**: `RATE_LIMIT_PER_HOUR` requests per hour (default 10000),
  enforced in fixed 60-second windows of one sixtieth of it, rounded down
  and at least 1: 166 requests per team with the default
  (`open-security-gateway/nginx/lua/auth_handler.lua`). Every authenticated
  response carries `X-RateLimit-Limit` (the per-minute figure),
  `X-RateLimit-Remaining` and `X-RateLimit-Reset`, which describe the
  current minute, and `X-RateLimit-Policy: <per hour>;w=3600`. Past the
  limit the gateway answers 429 with `Retry-After` and
  `{"error": "rate_limit_exceeded", "message": "Rate limit exceeded", "limit_per_hour": 10000, "retry_after_seconds": ...}`.
  `RATE_LIMIT_PER_HOUR` is set in `.env` and passed to the gateway by
  `docker-compose.yml`; it must be a whole number from 1 to 1,000,000,000,
  and any other value stops the gateway at startup.
- **Per client IP**: the server-wide nginx `limit_req` zone `global`,
  100 requests per second with a burst of 10, answered with 429.

The tools service applies no request rate limit of its own: every request
reaches it through the gateway, already counted against the caller's team.
`RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW`, which the service read and
never enforced, no longer exist
([#646](https://github.com/fabriziosalmi/wildbox/issues/646)); setting them
in `.env` has no effect. What the service does limit is the cost of a call:
`MAX_CONCURRENT_TOOLS` synchronous runs at a time (10), `TOOL_TIMEOUT`
seconds per run (300), and, for the tools that act for a caller, a number
of runs per caller per hour (one for a destructive test), counted in each
process's memory.

## Errors

The gateway answers its own refusals with
`{"error": "<code>", "message": "..."}`:

| Status | `error` | Cause |
| --- | --- | --- |
| 400 | `invalid_token` | Token longer than 4096 characters |
| 401 | `authentication_required` | No bearer token and no `X-API-Key` |
| 401 | `invalid_token` | Token or key invalid, expired or revoked |
| 403 | `insufficient_scope` | API key without the required scope; the body names `required_scope` |
| 403 | `team_membership_ended` | The user was removed from the team the credential is for |
| 403 | `PASSWORD_CHANGE_REQUIRED` | The account must change its initial password first |
| 404 | `endpoint_not_found` | Path not routed by the gateway |
| 429 | `rate_limit_exceeded` | Per-team limit; see [Rate Limits](#rate-limits) |
| 503 | `service_unavailable` | The gateway could not reach the identity service; `Retry-After` is set |

A 504 means the service did not answer within 60 seconds (see
[Tool Execution](#tool-execution)).

The tools service answers its errors in the shape every Wildbox service
uses:

```json
{
  "error": {
    "code": 404,
    "message": "Task not found",
    "type": "HTTPException",
    "request_id": "6f1c2d..."
  }
}
```

`details` is added when there is more to say, such as the field errors of a
422. `request_id` matches the `X-Request-ID` the gateway set, for finding
the request in the logs.

| Status | Where |
| --- | --- |
| 400 | Run: target refused by the network target policy. Cancel: task already finished or canceled |
| 403 | Run: tool refused the caller |
| 404 | Unknown tool; task not found or not the caller's |
| 408 | Synchronous run timed out |
| 422 | Request body missing, not an object, or not matching the input schema |
| 500 | Tool failed |
| 503 | Asynchronous execution unavailable (Redis, the result backend or the task queue down) |

## Examples

### Run a Tool Asynchronously and Wait for Its Result

```bash
CA=open-security-gateway/ssl/wildbox.crt

TASK_ID=$(curl -s --cacert "$CA" -X POST https://<host>/api/v1/tools/hash_generator/async \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"input_text": "wildbox", "hash_types": ["sha256"]}' | jq -r '.task_id')

echo "Task submitted: $TASK_ID"

while true; do
  TASK=$(curl -s --cacert "$CA" "https://<host>/api/v1/tasks/$TASK_ID" \
    -H "Authorization: Bearer $TOKEN")
  STATUS=$(echo "$TASK" | jq -r '.status')
  echo "Status: $STATUS"

  if [ "$STATUS" != "pending" ] && [ "$STATUS" != "running" ] && [ "$STATUS" != "retrying" ]; then
    echo "$TASK" | jq '{status, error, result}'
    break
  fi
  sleep 2
done
```

### Queue Several Lookups and List Them

```bash
CA=open-security-gateway/ssl/wildbox.crt

for domain in example.com example.org; do
  curl -s --cacert "$CA" -X POST "https://<host>/api/v1/tools/whois_lookup/async" \
    -H "X-API-Key: $WILDBOX_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"$domain\"}" | jq -r '.task_id'
done

curl -s --cacert "$CA" "https://<host>/api/v1/tasks" \
  -H "X-API-Key: $WILDBOX_API_KEY" \
  | jq '.tasks[] | {task_id, tool_name, status}'
```

## Related Documentation

- [Authentication and sessions](../../guides/authentication.md) - Tokens and API keys
- [Security Policy](../../security/policy.md) - Authentication requirements
- [API Reference Hub](../../api-reference.html) - All service endpoints
- [Guardian Service API](../guardian/endpoints.md) - Asset management
- [Responder Service API](../responder/endpoints.md) - Incident response
