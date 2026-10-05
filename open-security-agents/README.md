# Open Security Agents

AI threat-enrichment service for the Wildbox platform. It takes one
indicator of compromise (IOC), lets a Claude model investigate it with
Wildbox security tools, and returns a verdict with evidence and a Markdown
report. Analyses run asynchronously in a Celery worker.

## Architecture

```text
client --> gateway (/api/v1/agents/...) --> FastAPI (port 8006)
                                               |
                                               | Celery task (Redis)
                                               v
                                         Celery worker
                                               |
                       +-----------------------+----------------------+
                       |                                              |
                 Claude (Anthropic API)                Wildbox services, called with
                 via langchain-anthropic               the caller's gateway identity
```

- `app/main.py`: the HTTP API. It validates the request, records the task
  in Redis and queues it.
- `app/worker.py`: the Celery task `run_threat_enrichment_task`, which runs
  the agent.
- `app/agents/threat_enrichment_agent.py`: a LangChain tool-calling agent on
  `ChatAnthropic` (at most 15 iterations), followed by a structured report
  step that grounds the evidence in the tool outputs.
- `app/tools/`: the LangChain tools and the client that calls the other
  Wildbox services.

In the Wildbox stack the `agents` service in the root `docker-compose.yml`
runs both the API and the worker in one container
(`scripts/entrypoint.sh`), on Redis database 4.

## Authentication

The service accepts only requests that come through the gateway. The gateway
routes `/api/v1/agents/*` authenticate like every other service route
(`auth_handler.authenticate()`): a session JWT in `Authorization: Bearer` or
an API key in `X-API-Key`, with the gateway's revocation, password-change,
scope and per-team rate-limit checks (#636). The request is forwarded to
`/v1/*` with `X-Wildbox-User-ID`, `X-Wildbox-Team-ID`, `X-Wildbox-Role` and
the shared `GATEWAY_INTERNAL_SECRET`, which the service checks with the shared
`open_security_shared.gateway_auth` dependency (`app/auth.py`).

## Caller identity

Every analysis runs as the user who submitted it:

- `POST /v1/analyze` refuses with 403 a caller without a complete user and
  team identity, before it writes anything or queues work.
- The task records its owner (`task:{task_id}:user_id`) and receives the
  caller's user, team and role. The worker sets that identity for the
  duration of the task only, and refuses a task without one, so a task never
  reuses the identity of the previous task on the same worker (#596).
- Every tool call sends that identity as `X-Wildbox-*` headers together with
  `GATEWAY_INTERNAL_SECRET`, so downstream services apply the caller's team
  scope. Without `GATEWAY_INTERNAL_SECRET` every tool call fails.
- Only the owner can read or cancel a task. A task that belongs to another
  user, or whose owner record is missing, answers `404`, so task ids cannot be
  probed (#659).

## API

Paths are given as the gateway exposes them (prefix
`https://localhost/api/v1/agents`) and as the service serves them.

| Method | Gateway path | Service path | Description |
| --- | --- | --- | --- |
| POST | `/api/v1/agents/analyze` | `/v1/analyze` | Queue an analysis; answers 202 with the task id. Rate-limited per user, see below |
| GET | `/api/v1/agents/analyze/{task_id}` | `/v1/analyze/{task_id}` | Task status, or the full result once it completed |
| DELETE | `/api/v1/agents/analyze/{task_id}` | `/v1/analyze/{task_id}` | Revoke a pending or running task |
| GET | `/api/v1/agents/stats` | `/stats` | Task counters |
| GET | none | `/health` | Redis, Celery and Anthropic key status |

`task_id` must be a UUID. `/health` is not routed by the gateway; it is
reachable on `127.0.0.1:8006` on the host. The
interactive API documentation (`/docs`, `/redoc`) and the schema
(`/openapi.json`) are served on port 8006 only when `ENVIRONMENT` is
`development`.

### Submit an analysis

```bash
curl -s --cacert open-security-gateway/ssl/wildbox.crt \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"ioc": {"type": "domain", "value": "example.com"}, "priority": "normal"}' \
  https://localhost/api/v1/agents/analyze
```

```json
{
  "task_id": "0d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6",
  "status": "pending",
  "created_at": "2026-10-03T10:00:00Z",
  "result_url": "/v1/analyze/0d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6"
}
```

`ioc.type` is one of `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`,
`sha256` or `email`; the value is checked against a pattern for its type.
`priority` (`low`, `normal`, `high`) is stored with the task.

### Read the result

While the task runs, `GET` returns its status (`pending`, `running`,
`failed`). Once it completed it returns the result:

| Field | Content |
| --- | --- |
| `verdict` | `Malicious`, `Suspicious`, `Benign` or `Informational` |
| `confidence` | 0 to 1 |
| `executive_summary` | Short summary |
| `evidence` | Items with `source` (tool), `finding`, `severity`, `data` |
| `recommended_actions` | List of actions |
| `full_report` | Markdown report |
| `tools_used`, `analysis_duration` | Tools the agent called; duration in seconds |

Task records and results expire after one hour (`task_result_expires`).

## Tools

The agent has nine LangChain tools (`app/tools/langchain_tools.py`):

| Tool | Calls |
| --- | --- |
| `port_scan_tool` | tools service, `network_port_scanner` |
| `whois_lookup_tool` | tools service, `whois_lookup` |
| `reputation_check_tool` | tools service, `threat_intelligence_aggregator` |
| `dns_lookup_tool` | tools service, `dns_enumerator` |
| `url_analysis_tool` | tools service, `url_analyzer` |
| `hash_lookup_tool` | tools service, `malware_hash_checker` |
| `geolocation_lookup_tool` | tools service, `ip_geolocation` |
| `threat_intel_query_tool` | data service, `/api/v1/threat-intel/query` |
| `vulnerability_search_tool` | guardian, `/api/v1/vulnerabilities/search` |

Tools-service calls go to `{WILDBOX_API_URL}/api/tools/{tool}` and only to
the tools in the fixed `TOOL_ENDPOINT_MAP` of `app/tools/wildbox_client.py`.
The data and guardian endpoints the last two tools call do not exist on
those services at present, so those tools return an error to the agent.

## Configuration

Settings are read from the environment (`app/config.py`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | none | Claude API key. Without it the service starts, `/health` reports `not_configured` and analyses fail |
| `ANTHROPIC_MODEL` | `claude-opus-4-8` | Model id |
| `ANTHROPIC_TEMPERATURE` | `0.1` | Sampling temperature |
| `ANTHROPIC_MAX_TOKENS` | `4096` | Maximum output tokens |
| `GATEWAY_INTERNAL_SECRET` | none | Required. Verifies incoming gateway requests and authenticates tool calls |
| `REDIS_URL` | `redis://localhost:6379/0` | Task state |
| `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Celery |
| `WILDBOX_API_URL` | `http://localhost:8000` | Tools service |
| `WILDBOX_DATA_URL` | `http://localhost:8001` | Data service (the data service listens on 8002; set this explicitly) |
| `WILDBOX_GUARDIAN_URL` | `http://localhost:8013` | Guardian |
| `LOG_LEVEL` | `INFO` | Log level |
| `DEBUG` | `false` | Debug flag |
| `ENVIRONMENT` | `development` | `/docs`, `/redoc` and `/openapi.json` are served only when it is `development` |
| `CORS_ORIGINS` | empty | Comma-separated allowed origins |
| `ANALYZE_RATE_LIMIT` | `5/minute` | Analyses each user may submit, in the `limits` notation (`5/minute;50/day` for several) |
| `ANALYZE_TEAM_RATE_LIMIT` | empty (no ceiling) | Optional ceiling for all users of one team together |

The analysis limits are counted per user as identified by the gateway, not
per client address (#659). The service refuses to start when either value
cannot be parsed; a request over a limit answers `429`.

The root `docker-compose.yml` sets `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`
(default `claude-opus-4-8`), `GATEWAY_INTERNAL_SECRET`, `WILDBOX_API_URL`
(`http://api:8000`) and the Redis URLs.

## Development

The `docker-compose.yml` in this directory runs the service on its own with
a local Redis: `agents-api` (port 8006), `celery-worker` and `celery-flower`
(port 5555 on localhost). It needs `GATEWAY_INTERNAL_SECRET` and
`FLOWER_PASSWORD`, and `ANTHROPIC_API_KEY` for analyses. Requests to it
still need the gateway identity headers, so use the full stack for
end-to-end work.

```bash
# Unit tests (no services needed)
make test

# Analysis through the gateway (needs the whole stack running)
make test-e2e
```

To add a tool, define it in `app/tools/langchain_tools.py`, add it to
`ALL_TOOLS`, and add the call in `app/tools/wildbox_client.py` (for a
tools-service tool, an entry in `TOOL_ENDPOINT_MAP`).

## License

Part of the Wildbox platform; see the repository [LICENSE](../LICENSE).
