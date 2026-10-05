# Agents Service API

> **Hand-written reference.** Checked against the code of the agents service
> (`open-security-agents/app/main.py`) and the gateway configuration
> (`open-security-gateway/nginx/conf.d/wildbox_gateway.conf`). Where this page
> and a running service disagree, the service is right: please open an issue.
>
> All IDs, keys and host names in the examples are fictitious placeholders.

**Gateway path**: `https://<host>/api/v1/agents/...`, proxied to the service's `/v1/...`; `/api/v1/agents/stats` to the service's `/stats`
**Authentication**: a session token (JWT) or an API key, as on every gateway route (see [Authentication](#authentication))
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
- [Statistics](#statistics)
- [Analysis Tools](#analysis-tools)
- [Service Routes Outside the Gateway](#service-routes-outside-the-gateway)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)
- [Task Limits](#task-limits)
- [Examples](#examples)

---

## Authentication

### Through the gateway: a session token or an API key

Every agents route is reached through the gateway. The examples use
`--cacert open-security-gateway/ssl/wildbox.crt`, the certificate the
gateway serves by default.

The agents routes authenticate with the gateway's shared handler,
`auth_handler.authenticate()`, like every other route (#636). Send either
credential:

- a session token (JWT) in `Authorization: Bearer <token>`, from
  `POST https://<host>/auth/jwt/login`;
- an API key in `X-API-Key`. Create one with
  `POST https://<host>/api/v1/identity/api-keys` (a user key) or
  `POST https://<host>/api/v1/identity/teams/{team_id}/api-keys` (a team key).

```bash
CA=open-security-gateway/ssl/wildbox.crt

# A session token
curl --cacert "$CA" -X POST https://<host>/api/v1/agents/analyze \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "domain", "value": "suspicious-domain.com"}}'

# An API key
curl --cacert "$CA" -X POST https://<host>/api/v1/agents/analyze \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "domain", "value": "suspicious-domain.com"}}'
```

An API key with a scope list needs `tools:read` to read a task or the
statistics (`GET`) and `tools:execute` to submit or cancel one; without it the
gateway answers `403` with `"error":"insufficient_scope"` and the
`required_scope`. A session token carries no scopes.

The gateway's own refusals:

- no credential: `401` with
  `{"error":"authentication_required","message":"Valid authentication token required"}`;
- a credential identity refuses, or a revoked session or API key: `401` with
  `"error":"invalid_token"`;
- an account that must change its initial password: `403` with
  `"error":"PASSWORD_CHANGE_REQUIRED"`;
- a user removed from the team the credential resolves to: `403` with
  `"error":"team_membership_ended"`;
- over the per-team rate limit: `429` (see [Rate Limiting](#rate-limiting));
- identity unreachable: `503` with `"error":"service_unavailable"` and
  `Retry-After`.

### How the caller reaches the service

After identity accepts the credential, the shared handler removes any
client-supplied `X-Wildbox-User-ID`, `X-Wildbox-Team-ID`, `X-Wildbox-Role`,
`Authorization` and `X-API-Key` headers and sets the caller's user, team and
role from identity's answer. The shared proxy settings
(`open-security-gateway/nginx/includes/proxy_params.conf`) send them to the
service as `X-Wildbox-User-ID`, `X-Wildbox-Team-ID` and `X-Wildbox-Role`, with
`X-Gateway-Secret`, the `GATEWAY_INTERNAL_SECRET` proof of origin.

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
| `WILDBOX_API_URL` | `http://api:8000` | The tools service the agent calls. Set it in `.env` as `WILDBOX_API_URL`. |
| `WILDBOX_DATA_URL` | `http://open-security-data:8002` | The data service, for `threat_intel_query_tool`. Set it in `.env` as `AGENTS_WILDBOX_DATA_URL`. |
| `WILDBOX_GUARDIAN_URL` | `http://open-security-guardian:8013` | Guardian, for `vulnerability_search_tool`. Set it in `.env` as `AGENTS_WILDBOX_GUARDIAN_URL`. The host must be in Guardian's `ALLOWED_HOSTS`. |
| `ANALYZE_RATE_LIMIT` | `5/minute` | Analysis submissions each user may make, in the `limits` notation; several limits are separated by `;`, for example `5/minute;50/day`. Must not be empty. |
| `ANALYZE_TEAM_RATE_LIMIT` | empty (no ceiling) | Optional ceiling for all users of one team together, in the same notation. |
| `AGENT_TEAM_DATA_TOOLS` | empty (neither) | The [team-data tools](#team-data-tools) the model is given: `threat_intel_query_tool`, `vulnerability_search_tool`, or both, comma-separated. Read that section before setting it. Any other value stops the service at start. |
| `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | Redis database 4, with `REDIS_PASSWORD` | Task state, the Celery queue and the rate limit counters. |

The service refuses to start when a service URL is not an absolute `http` or
`https` URL with a host, or when a rate limit cannot be parsed or names an
amount below 1 (`open-security-agents/app/config.py`). The service URLs default,
in the service itself, to the same addresses `docker-compose.yml` sets.

`ANALYZE_RATE_LIMIT_STORAGE_URI` is read by the service and not passed by
`docker-compose.yml`. Empty, the default, keeps the rate limit counters in
`REDIS_URL`; `memory://` keeps them in the API process, where a restart clears
them. Any other value but a Redis URL (`redis://`, or its TLS form) stops the
service at start.

Anthropic is the only provider: the agent is built on `ChatAnthropic`
(`open-security-agents/app/agents/threat_enrichment_agent.py`).

---

## Threat Analysis

### POST /api/v1/agents/analyze

Submit an IOC for analysis. Served by the service's `POST /v1/analyze`.

**Authentication**: required
**Rate limit**: 5 requests per minute per user by default (see [Rate Limiting](#rate-limiting))

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
it. Another user's task, a task with no owner record and a task that does not
exist all answer the same `404`, so the answer does not reveal whether a task
ID is live (#659).

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

**Response (404 Not Found)**: the task does not exist, has expired (see
[Task Limits](#task-limits)), or belongs to another user.

---

### DELETE /api/v1/agents/analyze/{task_id}

Cancel a queued or running task.

**Authentication**: required. The ownership check is the one the read
uses, and it runs before anything is revoked: another user's task, or a task
with no owner record, answers `404` and is not canceled (#659).

```bash
CA=open-security-gateway/ssl/wildbox.crt
curl --cacert "$CA" -X DELETE https://<host>/api/v1/agents/analyze/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-Key: your-api-key"
```

**Response (200 OK)**:

```json
{"message": "Task cancelled successfully"}
```

**Response (404 Not Found)**: the task does not exist, has expired, or
belongs to another user.

**Response (503 Service Unavailable)**: Redis or the Celery broker could not
be reached; the task may still be running.

---

## Statistics

### GET /api/v1/agents/stats

Task counters for the whole service, not for the caller's team. Served by the
service's `GET /stats`, outside its `/v1` tree: the gateway routes this exact
path there (#636).

**Authentication**: required; an API key needs `tools:read`.

```bash
CA=open-security-gateway/ssl/wildbox.crt
curl --cacert "$CA" https://<host>/api/v1/agents/stats \
  -H "Authorization: Bearer your-jwt-token"
```

**Response (200 OK)**:

```json
{
  "total_analyses": 42,
  "pending_tasks": 0,
  "running_tasks": 1,
  "completed_today": 0,
  "failed_today": 0,
  "average_duration": null,
  "uptime_seconds": 86400.0
}
```

`average_duration` is always `null`. `completed_today` and `failed_today` count
the tasks that ended since 00:00 UTC of the current date: the worker keeps one
counter per UTC date, which expires two days later
(`open-security-agents/app/stats.py`). `total_analyses` counts submissions
since the Redis data was last cleared. `503` when Redis or the Celery broker
cannot be reached.

---

## Analysis Tools

The service has nine tools (`ALL_TOOLS` in
`open-security-agents/app/tools/langchain_tools.py`). The model is given the
seven that look the IOC up outside; the two that read data Wildbox holds for
the team are given to it only when the operator opts in
([Team-data tools](#team-data-tools)). The model chooses which tools to call
for each IOC; the system prompt suggests a set per IOC type.

### Lookup tools

Always given to the model.

| Tool | What it calls | What it sends |
| --- | --- | --- |
| `port_scan_tool` | tools service `network_port_scanner` | `target`, `ports` (`1-1000`), `scan_type` (`tcp`) |
| `whois_lookup_tool` | tools service `whois_lookup` | `domain` |
| `reputation_check_tool` | tools service `threat_intelligence_aggregator` | `indicator`, `indicator_type` (`ip`, `domain`, `url`, `hash` or `email`) |
| `dns_lookup_tool` | tools service `dns_enumerator` | `target_domain`, `record_types` (one type), basic mode, no zone transfer attempt |
| `url_analysis_tool` | tools service `url_analyzer` | `shortened_url`, `follow_redirects` |
| `hash_lookup_tool` | tools service `malware_hash_checker` | `hash_value` |
| `geolocation_lookup_tool` | tools service `ip_geolocation` | `ip_address` |

Tool calls to the tools service go to `POST {WILDBOX_API_URL}/api/tools/<name>`
and only to the names in this table: any other tool name is refused before a
request is made. `url_analysis_tool` follows the URL's redirects; it takes no
screenshot.

### Team-data tools

**Off by default.** The model is given one only when `AGENT_TEAM_DATA_TOOLS`
names it. With the setting empty, neither tool is in the model's tool list,
the prompt does not mention them, and the service makes no request to the data
service or to Guardian.

| Tool | What it calls | What it sends |
| --- | --- | --- |
| `threat_intel_query_tool` | data service `GET /api/v1/indicators/search` at `WILDBOX_DATA_URL` | `q`, `limit` (25), optional `indicator_type` |
| `vulnerability_search_tool` | guardian `GET /api/v1/vulnerabilities/` at `WILDBOX_GUARDIAN_URL` | `search` |

To give the model both, set in `.env` and recreate the agents container:

```bash
AGENT_TEAM_DATA_TOOLS=threat_intel_query_tool,vulnerability_search_tool
```

Either name alone gives the model that tool only. Any other value stops the
service at start.

**What turning one on sends to the model provider.** Every tool output is part
of the conversation with Claude, so it is sent to Anthropic. The model writes
the search text itself and can search several times in one analysis. For each
search:

- `threat_intel_query_tool`: the number of matches and up to 25 indicators of
  the user's team and of the feeds shared by every team, whose value or
  description contains the text. For each: type, value, threat types,
  confidence, severity, description, tags, first and last seen, whether it is
  active, and whether its value is exactly the text searched.
- `vulnerability_search_tool`: the number of matches and up to 25
  vulnerabilities Guardian records for the user's team, whose title,
  description, CVE ID or asset name contains the text. For each: title, CVE ID,
  severity, status, priority, risk score, CVSS score, **asset name** and type,
  due date, whether it is overdue, and creation date. A member gets those
  assigned to or created by them; an owner or admin, all of the team's. It is
  not a public CVE database.

Row IDs, source IDs, indicator metadata and Guardian's page links are not
returned to the model.

**The injection risk.** With a team-data tool on, the team's data sits in the
model's context beside text the lookup tools fetched from the internet: WHOIS
records, DNS answers, redirect chains and response headers of the URL under
analysis. Whoever controls that text can write it as instructions to the model,
and the model holds tools that reach outside (`url_analysis_tool`,
`dns_lookup_tool`, `whois_lookup_tool`), whose arguments it chooses. A page
written for the purpose can ask the model to search the team's vulnerabilities
and pass what it finds out in such an argument. The system prompt tells the
model that tool output is data and not to put the team's records in another
tool's arguments; that is a request to the model, not a control. Turn a
team-data tool on only if the indicators your users submit, and the data the
tool returns, make that acceptable.

### How every tool behaves

- **Every call is made as the user who submitted the analysis.** The agents
  service calls the services directly on the internal network, and each request
  carries that user's `X-Wildbox-User-ID`, `X-Wildbox-Team-ID` and
  `X-Wildbox-Role` with `X-Gateway-Secret`, the headers the gateway puts on a
  request it forwards. The service has no key of its own and sees nothing the
  user would not see through the gateway.
- **A tool that fails returns an error to the model, never data:**
  `{"success": false, "error": "..."}` with the status the service answered. An
  unreachable service, an answer that is not the expected JSON and an IOC or DNS
  record type the service does not have are errors too. The message names the
  service, not its address.

---

## Service Routes Outside the Gateway

The gateway maps `/api/v1/agents/<path>` to `/v1/<path>` on the service, and
`/api/v1/agents/stats` to `/stats` (see [Statistics](#statistics)). These
service routes are not under `/v1/`, so the gateway does not reach them:

| Route | Authentication | Notes |
| --- | --- | --- |
| `GET /health` | none | Redis, Celery and Anthropic key status. Used by the container health check. |
| `GET /` | none | Service name, version and links. |
| `/docs`, `/redoc`, `/openapi.json` | none | Served only when `ENVIRONMENT` is `development`. |

The service port is bound to `127.0.0.1` on the host. `/health` answers on
it, from the host or inside the container; `/stats` and the `/v1` routes need
the gateway headers and the proof of origin, so they answer `403` there.

---

## Error Codes

| Code | Meaning |
| --- | --- |
| 202 | Analysis task queued |
| 400 | The request could not be turned into a task |
| 401 | From the gateway: no credential (`authentication_required`), or a credential identity refuses or that has been revoked (`invalid_token`) |
| 403 | From the gateway: an API key without the required scope (`insufficient_scope`), a pending password change (`PASSWORD_CHANGE_REQUIRED`) or a team the user was removed from (`team_membership_ended`). From the service: no complete caller identity (#594), or a request without the gateway's identity headers or proof of origin |
| 404 | Task not found, expired, or owned by another user |
| 422 | Request body or `task_id` failed validation |
| 429 | The gateway's per-team limit, or the service's analysis limit per user or per team |
| 500 | The task state could not be read |
| 503 | Redis or the Celery broker unavailable, or the rate limit counters cannot be reached; or, from the gateway, identity unreachable (with `Retry-After`) |

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

The gateway's own `401`, `403`, `429` and `503` answers use the flat bodies
shown under [Authentication](#authentication) and [Rate Limiting](#rate-limiting).

---

## Rate Limiting

Two limits apply to `POST /api/v1/agents/analyze`.

**The service's analysis limit** (#659), from
`open-security-agents/app/rate_limit.py`:

- `ANALYZE_RATE_LIMIT` (default `5/minute`) per user. The key is the user ID
  of the caller the gateway authenticated, read after the proof of origin has
  been verified; no forwarded header is read, so a caller cannot move to
  another bucket.
- `ANALYZE_TEAM_RATE_LIMIT`, when set, a ceiling for all users of one team
  together. The per-user limit is checked first, so a request over it is not
  counted against the team.

Over either limit the service answers `429`, and the body names the limit that
was hit, per user or per team. The counters are kept in the service's Redis
(`REDIS_URL`), so they survive a restart of the container. When Redis cannot be
reached the submission is refused with `503`, not accepted uncounted.

**The gateway's per-team limit** applies to every agents route, as to every
authenticated gateway route. `RATE_LIMIT_PER_HOUR` (default 10000, set on the
gateway; the gateway does not start when it is not a whole number from 1 to
1,000,000,000) is enforced in 60-second windows of
`floor(RATE_LIMIT_PER_HOUR / 60)` requests per team, 166 with the default.
Every authenticated response carries `X-RateLimit-Limit` (the per-minute
figure), `X-RateLimit-Remaining`, `X-RateLimit-Reset` and
`X-RateLimit-Policy` (`10000;w=3600`). Over the limit the gateway answers
`429` with `Retry-After`:

```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded",
  "limit_per_hour": 10000,
  "retry_after_seconds": 42
}
```

The gateway's per-address request limit applies as well.

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
(50 per page) and filters on `criticality`. Mind the agents rate limit, by
default 5 analysis requests per minute per user.

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
