# Agents Service API

> **Hand-written reference.** Checked against the code of the agents service
> (`open-security-agents/app/main.py`) and the gateway configuration
> (`open-security-gateway/nginx/conf.d/wildbox_gateway.conf`). Where this page
> and a running service disagree, the service is right: please open an issue.
>
> All IDs, keys and host names in the examples are fictitious placeholders.

**Gateway path**: `https://<host>/api/v1/agents/...`, proxied to the service's `/v1/...`
**Authentication**: an API key in the `X-API-Key` header (see [Authentication](#authentication))
**LLM provider**: Anthropic (Claude) only

---

## Overview

The agents service analyzes one indicator of compromise (IOC) at a time. A
request queues a Celery task; the task runs a LangChain tool-calling agent on
a Claude model, which calls Wildbox tools (WHOIS, DNS, reputation, and the
others listed under [Analysis tools](#analysis-tools)) and returns a verdict,
a confidence score, evidence and a Markdown report.

## Table of Contents

- [Authentication](#authentication)
- [Configuration](#configuration)
- [Threat Analysis](#threat-analysis)
- [Analysis Tools](#analysis-tools)
- [Service Routes Outside the Gateway](#service-routes-outside-the-gateway)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)
- [Task Limits](#task-limits)
- [Examples](#examples)

---

## Authentication

### Through the gateway: API key only

Every agents route is reached through the gateway. The examples use
`--cacert open-security-gateway/ssl/wildbox.crt`, the certificate the
gateway serves by default.

The `/api/v1/agents/` route authenticates with its own inline code, not with
the gateway's shared handler, and reads **only** the `X-API-Key` header:

- no `X-API-Key` header: `401` with `{"error":"unauthorized","message":"API key required","code":"NO_API_KEY"}`.
  This is also the answer to a request that carries only a JWT bearer token;
- a key identity refuses: `401` with `"code":"INVALID_API_KEY"`;
- identity unreachable: `503` with `"error":"service_unavailable"`.

A JWT bearer token therefore does not work on this route today. Issue
[#630](https://github.com/fabriziosalmi/wildbox/issues/630) tracks moving the
route to the shared handler, so that it accepts a JWT like every other route.

Create an API key with `POST https://<host>/api/v1/identity/api-keys` (a user
key) or `POST https://<host>/api/v1/identity/teams/{team_id}/api-keys` (a team
key), using a JWT from `POST https://<host>/auth/jwt/login`.

```bash
CA=open-security-gateway/ssl/wildbox.crt
curl --cacert "$CA" -X POST https://<host>/api/v1/agents/analyze \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "domain", "value": "suspicious-domain.com"}}'
```

### How the caller reaches the service

After identity accepts the key, the route's inline code removes any
client-supplied `X-Wildbox-User-ID`, `X-Wildbox-Team-ID`, `X-Wildbox-Role`,
`Authorization` and `X-API-Key` headers and sets the three `X-Wildbox-*`
request headers from identity's answer. The shared proxy settings
(`open-security-gateway/nginx/includes/proxy_params.conf`) add
`X-Gateway-Secret`, the `GATEWAY_INTERNAL_SECRET` proof of origin.

> **Known defect.** The same proxy settings also define `X-Wildbox-User-ID`,
> `X-Wildbox-Team-ID` and `X-Wildbox-Role` from the variables
> `$wildbox_user_id`, `$wildbox_team_id` and `$wildbox_role`. Only the shared
> handler fills those variables; the agents route's inline code does not, so
> they stay empty. nginx sends the proxy settings' value instead of the
> request header of the same name, and drops a header whose value is empty,
> so the agents service receives no caller identity from this route and
> answers `403`. Moving the route to the shared handler, as
> [#630](https://github.com/fabriziosalmi/wildbox/issues/630) proposes, fixes
> this as well.

The service authenticates every route below with the shared dependency
`open_security_shared.gateway_auth.get_user_from_gateway_headers`. It refuses
a request whose `X-Gateway-Secret` does not match its own
`GATEWAY_INTERNAL_SECRET` (`403`), a request without a user or team ID
(`403`), and answers `503` when `GATEWAY_INTERNAL_SECRET` is not set. A
request sent to the service's own port without these headers is refused: the
gateway is the only entry point.

### Caller identity in tool calls

The analysis runs on behalf of the caller. `POST /v1/analyze` passes the
caller's user ID, team ID and role to the Celery task, and every tool call the
agent makes sends them to the tools service as `X-Wildbox-User-ID`,
`X-Wildbox-Team-ID` and `X-Wildbox-Role`, with `X-Gateway-Secret`. The tools
service then applies the caller's own team scope and role.

There is no service-wide key. The `INTERNAL_API_KEY` that the client used to
send as `X-API-Key` is no longer read: the tools service stopped accepting it
in #566, and the fallback was removed in #567. If the caller identity or
`GATEWAY_INTERNAL_SECRET` is missing, the tool call fails in the agents
service instead of reaching the tools service.

`POST /v1/analyze` refuses with `403` a caller without both a user ID and a
team ID, before any task state is written or any work is queued (#594). The
worker refuses such a task as well.

---

## Configuration

Set in `docker-compose.yml` for the `agents` service:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | empty | Claude API key. The service starts without it; analysis tasks fail until it is set. |
| `ANTHROPIC_MODEL` | `claude-opus-4-8` | Claude model the agent uses. |
| `GATEWAY_INTERNAL_SECRET` | from `.env` | Verifies the gateway's proof of origin and authenticates tool calls. Required. |
| `WILDBOX_API_URL` | `http://api:8000` | The tools service the agent calls. |
| `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | Redis database 4, with `REDIS_PASSWORD` | Task state and the Celery queue. |

Anthropic is the only provider: the agent is built on `ChatAnthropic`
(`open-security-agents/app/agents/threat_enrichment_agent.py`).

---

## Threat Analysis

### POST /api/v1/agents/analyze

Submit an IOC for analysis. Served by the service's `POST /v1/analyze`.

**Authentication**: required
**Rate limit**: 5 requests per minute (see [Rate Limiting](#rate-limiting))

**Request body**:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `ioc` | object | Yes | The indicator to analyze |
| `ioc.type` | string | Yes | One of `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`, `email` |
| `ioc.value` | string | Yes | The value; validated against a pattern for its type |
| `priority` | string | No | `low`, `normal` or `high`; default `normal` |

The value patterns, from `open-security-agents/app/schemas.py`:

- `ipv4`: four dot-separated groups of one to three digits;
- `ipv6`: 2 to 40 hexadecimal digits and colons;
- `domain`: labels separated by dots, ending in a top-level domain of 2 to 6 letters;
- `url`: an `http`, `https` or `ftp` URL;
- `md5`, `sha1`, `sha256`: 32, 40 or 64 lowercase hexadecimal digits;
- `email`: an address with a domain.

A value that does not match its type is refused with `422`.

**Request**:

```bash
CA=open-security-gateway/ssl/wildbox.crt
curl --cacert "$CA" -X POST https://<host>/api/v1/agents/analyze \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc": {"type": "ipv4", "value": "203.0.113.10"},
    "priority": "high"
  }'
```

**Response (202 Accepted)**:

```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "created_at": "2026-10-03T10:00:00Z",
  "started_at": null,
  "completed_at": null,
  "progress": null,
  "error": null,
  "result_url": "/v1/analyze/550e8400-e29b-41d4-a716-446655440000"
}
```

`result_url` is the service-side path. Through the gateway, read the result at
`/api/v1/agents/analyze/{task_id}`.

---

### GET /api/v1/agents/analyze/{task_id}

Return the status of a task, or its result once it has completed.

**Authentication**: required. Only the user who submitted the task can read
it; another user gets `403`. A task with no owner record answers `404`.

`task_id` must be a lowercase UUID; any other value is refused with `422`.

```bash
CA=open-security-gateway/ssl/wildbox.crt
curl --cacert "$CA" https://<host>/api/v1/agents/analyze/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-Key: your-api-key"
```

**Response while the task is queued or running (200 OK)**:

```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "created_at": "2026-10-03T10:00:00Z",
  "started_at": "2026-10-03T10:00:05Z",
  "completed_at": null,
  "progress": "Running AI analysis...",
  "error": null,
  "result_url": "/v1/analyze/550e8400-e29b-41d4-a716-446655440000"
}
```

`status` is `pending`, `running` or `failed` here. A failed task carries
`"error": "Analysis failed. Please retry or contact support."`; the details
are in the service logs.

**Response once the task has completed (200 OK)**: the analysis result, which
has no `status` field:

```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "ioc": {"type": "ipv4", "value": "203.0.113.10"},
  "verdict": "Suspicious",
  "confidence": 0.75,
  "executive_summary": "Short summary of the findings.",
  "evidence": [
    {
      "source": "reputation_check_tool",
      "finding": "Description of the finding",
      "severity": "medium",
      "data": null
    }
  ],
  "recommended_actions": ["Block the address at the firewall"],
  "full_report": "# Threat Analysis Report\n...",
  "analysis_duration": 45.2,
  "tools_used": ["reputation_check_tool", "geolocation_lookup_tool"]
}
```

`verdict` is one of `Malicious`, `Suspicious`, `Benign` or `Informational`;
`confidence` is between 0 and 1.

**Response (404 Not Found)**: the task does not exist or has expired (see
[Task Limits](#task-limits)).

---

### DELETE /api/v1/agents/analyze/{task_id}

Cancel a queued or running task.

**Authentication**: required. Canceling another user's task answers `403`.

```bash
CA=open-security-gateway/ssl/wildbox.crt
curl --cacert "$CA" -X DELETE https://<host>/api/v1/agents/analyze/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:

```json
{"message": "Task cancelled successfully"}
```

**Response (404 Not Found)**: the task does not exist or has expired.

---

## Analysis Tools

The agent has nine tools (`ALL_TOOLS` in
`open-security-agents/app/tools/langchain_tools.py`). The model chooses which
ones to call for each IOC; the system prompt suggests a set per IOC type.

| Tool | What it calls |
| --- | --- |
| `port_scan_tool` | tools service `network_port_scanner` |
| `whois_lookup_tool` | tools service `whois_lookup` |
| `reputation_check_tool` | tools service `threat_intelligence_aggregator` |
| `dns_lookup_tool` | tools service `dns_enumerator` |
| `url_analysis_tool` | tools service `url_analyzer` |
| `hash_lookup_tool` | tools service `malware_hash_checker` |
| `geolocation_lookup_tool` | tools service `ip_geolocation` |
| `threat_intel_query_tool` | data service `GET /api/v1/threat-intel/query` at `WILDBOX_DATA_URL` |
| `vulnerability_search_tool` | guardian `GET /api/v1/vulnerabilities/search` at `WILDBOX_GUARDIAN_URL` |

Tool calls to the tools service go to `POST {WILDBOX_API_URL}/api/tools/<name>`
and only to the names in this table: any other tool name is refused before a
request is made.

`docker-compose.yml` sets `WILDBOX_API_URL` only. `WILDBOX_DATA_URL` and
`WILDBOX_GUARDIAN_URL` keep their defaults, `http://localhost:8001` and
`http://localhost:8013`, which inside the agents container are not the data
and guardian services, so `threat_intel_query_tool` and
`vulnerability_search_tool` return an error result unless you set both.

---

## Service Routes Outside the Gateway

The gateway maps `/api/v1/agents/<path>` to `/v1/<path>` on the service.
These service routes are not under `/v1/`, so the gateway does not reach them:

| Route | Authentication | Notes |
| --- | --- | --- |
| `GET /health` | none | Redis, Celery and Anthropic key status. Used by the container health check. |
| `GET /stats` | gateway headers | Task counters. `/api/v1/agents/stats` maps to `/v1/stats`, which does not exist (#630). |
| `GET /` | none | Service name, version and links. |
| `/docs`, `/redoc`, `/openapi.json` | none | Disabled when `ENVIRONMENT=production`. |

The service port is bound to `127.0.0.1` on the host. `/health` answers on
it, from the host or inside the container; `/stats` needs the gateway headers
and the proof of origin, so it answers `403` there.

---

## Error Codes

| Code | Meaning |
| --- | --- |
| 202 | Analysis task queued |
| 400 | The request could not be turned into a task |
| 401 | From the gateway: no `X-API-Key` (`NO_API_KEY`), or a key identity refuses (`INVALID_API_KEY`) |
| 403 | No complete caller identity (#594); a task owned by another user; or a request without the gateway's identity headers or proof of origin (see the known defect under [Authentication](#authentication)) |
| 404 | Task not found or expired |
| 422 | Request body or `task_id` failed validation |
| 429 | Rate limit exceeded |
| 500 | The task state could not be read |
| 503 | Redis or the Celery broker unavailable; or, from the gateway, identity unreachable |

Errors raised by the service use the canonical Wildbox error body:

```json
{
  "error": {
    "code": 403,
    "message": "A user and team identity is required to run an analysis",
    "type": "HTTPException",
    "request_id": "..."
  }
}
```

The gateway's own `401` and `503` answers use the flat bodies shown under
[Authentication](#authentication).

---

## Rate Limiting

`POST /v1/analyze` is limited to **5 requests per minute** by the service
(`@limiter.limit("5/minute")`). The limiter keys on the client address the
service sees. Behind the gateway that is the gateway's address, so the five
requests per minute are shared by all callers together, not counted per user.

The gateway's per-team limit of 10000 requests per hour is applied by its
shared authentication handler, which this route does not use (#630). The
gateway's per-address request limit still applies.

---

## Task Limits

From `open-security-agents/app/config.py` and the agent executor:

- **Maximum analysis time**: 10 minutes. The Celery hard time limit is 600
  seconds, the soft limit 570 seconds, and the agent itself stops after
  `max_analysis_time_minutes` (10) minutes.
- **Maximum agent iterations**: 15.
- **Result retention**: task state and results expire after 1 hour (3600
  seconds); after that the task answers `404`.
- **Worker concurrency**: the container starts one Celery worker with
  `--concurrency=2`.

---

## Examples

### Submit and poll

```bash
CA=open-security-gateway/ssl/wildbox.crt
HOST=wildbox.example.com
KEY=your-api-key

TASK_ID=$(curl -s --cacert "$CA" -X POST "https://$HOST/api/v1/agents/analyze" \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "domain", "value": "suspicious-domain.com"}, "priority": "high"}' \
  | jq -r '.task_id')

while true; do
  RESULT=$(curl -s --cacert "$CA" "https://$HOST/api/v1/agents/analyze/$TASK_ID" \
    -H "X-API-Key: $KEY")
  # A completed result has a verdict and no status field.
  if echo "$RESULT" | jq -e '.verdict' > /dev/null; then
    echo "$RESULT" | jq '{verdict, confidence, recommended_actions}'
    break
  fi
  if [ "$(echo "$RESULT" | jq -r '.status')" = "failed" ]; then
    echo "$RESULT" | jq '.error'
    break
  fi
  sleep 5
done
```

### Analyze the addresses of critical Guardian assets

Guardian is reached through the gateway as well. Its asset list is paginated
(50 per page) and filters on `criticality`. Mind the agents rate limit of 5
analysis requests per minute.

```bash
CA=open-security-gateway/ssl/wildbox.crt
HOST=wildbox.example.com
KEY=your-api-key

IPS=$(curl -s --cacert "$CA" \
  "https://$HOST/api/v1/guardian/assets/assets/?criticality=critical" \
  -H "X-API-Key: $KEY" | jq -r '.results[].ip_address // empty')

for ip in $IPS; do
  curl -s --cacert "$CA" -X POST "https://$HOST/api/v1/agents/analyze" \
    -H "X-API-Key: $KEY" \
    -H "Content-Type: application/json" \
    -d "{\"ioc\": {\"type\": \"ipv4\", \"value\": \"$ip\"}}" | jq -r '.task_id'
  sleep 13
done
```

---

## Related Documentation

- [Security Policy](../../security/policy.md) - Authentication requirements
- [API Reference Hub](../../api-reference.html) - All service endpoints
- [Quickstart Guide](../../guides/quickstart.md) - Getting started with APIs
- [Guardian Service API](../guardian/endpoints.md) - Asset and vulnerability management
- [Data Service API](../data/endpoints.md) - Threat intelligence data
