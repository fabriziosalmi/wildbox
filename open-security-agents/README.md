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
  scope. Without `GATEWAY_INTERNAL_SECRET` every tool call fails. The call
  states `X-Wildbox-Auth-Type: service`: the tools service checks an API
  key's `tools:execute` scope itself and refuses a request that does not
  say what its credential is. The scopes of the key that started the
  analysis do not travel with the call; the gateway checked `tools:execute`
  when the analysis was submitted (#637).
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
  "result_url": "/api/v1/agents/analyze/0d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6"
}
```

`ioc.type` is one of `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`,
`sha256` or `email`; the value is checked against a pattern for its type.
`priority` (`low`, `normal`, `high`) is stored with the task.

### Read the result

While the task runs, `GET` returns its status (`pending`, `running`,
`failed`). A failed task has no report: `error` says why (no model key,
the model unreachable or refusing, a timeout, a report the model did not
produce), in the words of `app/failures.py`, and the task counts in
`failed_today`. Nothing but the model's structured report produces a
verdict. Once the task completed, `GET` returns the result:

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

The service has nine LangChain tools (`app/tools/langchain_tools.py`). The
model is always given the seven that look the IOC up outside:

| Tool | Calls | What the model gets |
| --- | --- | --- |
| `port_scan_tool` | tools service, `network_port_scanner` | Open TCP ports (1-1000) and services |
| `whois_lookup_tool` | tools service, `whois_lookup` | A domain's registration |
| `reputation_check_tool` | tools service, `threat_intelligence_aggregator` | The aggregated threat score of an IOC of a given type |
| `dns_lookup_tool` | tools service, `dns_enumerator` | The records of one DNS type |
| `url_analysis_tool` | tools service, `url_analyzer` | A URL's redirect chain and where it ends (no screenshot) |
| `hash_lookup_tool` | tools service, `malware_hash_checker` | What the malware sources report on a file hash |
| `geolocation_lookup_tool` | tools service, `ip_geolocation` | Country, city, ISP of an address |

Tools-service calls go to `{WILDBOX_API_URL}/api/tools/{tool}` and only to
the tools in the fixed `TOOL_ENDPOINT_MAP` of `app/tools/wildbox_client.py`.

### Team-data tools (off by default)

Two tools read data Wildbox holds for the user's team. The model is given
one only when `AGENT_TEAM_DATA_TOOLS` names it; by default it has neither,
the prompt does not mention them, and no request goes to the data service
or to Guardian.

| Tool | Calls | What the model gets, for each search it makes |
| --- | --- | --- |
| `threat_intel_query_tool` | data service, `GET /api/v1/indicators/search` | The number of matches and up to 25 indicators of the team and of the shared feeds: type, value, threat types, confidence, severity, description, tags, dates |
| `vulnerability_search_tool` | guardian, `GET /api/v1/vulnerabilities/` | The number of matches and up to 25 vulnerabilities Guardian records for the team: title, CVE ID, severity, status, priority, scores, asset name and type, due date |

```bash
# .env: give the model both (either name alone gives that one)
AGENT_TEAM_DATA_TOOLS=threat_intel_query_tool,vulnerability_search_tool
```

Any other value stops the service at start. Before you set it:

- **It sends that data to the model provider.** Every tool output is part
  of the conversation, so what these tools return goes to Anthropic. The
  model writes the search text and can search several times per analysis.
- **It opens an injection path.** The data then sits in the model's context
  beside text the lookup tools fetched from the internet (WHOIS records,
  DNS answers, the redirects and headers of the URL under analysis), and
  the model holds tools that reach outside with arguments it chooses. Text
  written to instruct the model can ask it to search the team's records
  and pass them out in such an argument. The prompt tells the model not
  to; that is a request, not a control.

### How every tool behaves

Every tool calls its service directly, as the user who submitted the
analysis: the request carries that user's gateway identity
(`X-Wildbox-User-ID`, `X-Wildbox-Team-ID`, `X-Wildbox-Role`) with
`GATEWAY_INTERNAL_SECRET`, so the service answers for that user and team
and the agents service has no key that sees more. A call that fails returns
`{"success": false, "error": ...}` to the model, with the service's status
and without its address; it is never turned into an empty result.

A tool's description is all the model knows about it, so it says what the
service does and no more. When you add a tool or change what one sends, add
it to `TOOLS` in `tests/unit/test_tool_contracts.py`: the test checks the
request against the route, the query parameters and the input model in the
target service's source, and fails for a tool that is not in the table.

## Configuration

Settings are read from the environment (`app/config.py`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | none | Claude API key. Without it the service starts, `/health` reports `not_configured`, submissions are accepted and each task fails at once, saying that AI analysis is not configured |
| `ANTHROPIC_MODEL` | `claude-opus-4-8` | Model id |
| `ANTHROPIC_TEMPERATURE` | `0.1` | Sampling temperature |
| `ANTHROPIC_MAX_TOKENS` | `4096` | Maximum output tokens |
| `GATEWAY_INTERNAL_SECRET` | none | Required. Verifies incoming gateway requests and authenticates tool calls |
| `REDIS_URL` | `redis://localhost:6379/0` | Task state |
| `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Celery |
| `WILDBOX_API_URL` | `http://api:8000` | Tools service |
| `WILDBOX_DATA_URL` | `http://open-security-data:8002` | Data service, for `threat_intel_query_tool` |
| `WILDBOX_GUARDIAN_URL` | `http://open-security-guardian:8013` | Guardian, for `vulnerability_search_tool`; the host must be in Guardian's `ALLOWED_HOSTS` |
| `LOG_LEVEL` | `INFO` | Log level |
| `DEBUG` | `false` | Debug flag |
| `ENVIRONMENT` | `development` | `/docs`, `/redoc` and `/openapi.json` are served only when it is `development` |
| `CORS_ORIGINS` | empty | Comma-separated allowed origins |
| `ANALYZE_RATE_LIMIT` | `5/minute` | Analyses each user may submit, in the `limits` notation (`5/minute;50/day` for several) |
| `ANALYZE_TEAM_RATE_LIMIT` | empty (no ceiling) | Optional ceiling for all users of one team together |
| `AGENT_TEAM_DATA_TOOLS` | empty (neither) | The team-data tools the model is given: `threat_intel_query_tool`, `vulnerability_search_tool` or both; see [Team-data tools](#team-data-tools-off-by-default) |
| `ANALYZE_RATE_LIMIT_STORAGE_URI` | empty (`REDIS_URL`) | Where the limit counters are kept: empty for the service's Redis, `memory://` for the API process (the unit tests use it) |

The service URLs default to the services' addresses in the root
`docker-compose.yml`; each must be an absolute `http` or `https` URL with a
host, or the service does not start.

The analysis limits are counted per user as identified by the gateway, not
per client address (#659). The service refuses to start when either value
cannot be parsed; a request over a limit answers `429`. The counters are in
Redis, so a restart does not reset them; when Redis cannot be reached a
submission answers `503`.

`GET /stats` reports `completed_today` and `failed_today` for the current
UTC date (`app/stats.py`): one Redis counter per date, expiring after two
days.

The root `docker-compose.yml` sets `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`
(default `claude-opus-4-8`), `GATEWAY_INTERNAL_SECRET`, `WILDBOX_API_URL`
(`http://api:8000`), `WILDBOX_DATA_URL` and `WILDBOX_GUARDIAN_URL` (from
`AGENTS_WILDBOX_DATA_URL` and `AGENTS_WILDBOX_GUARDIAN_URL` in `.env`),
`ANALYZE_RATE_LIMIT`, `ANALYZE_TEAM_RATE_LIMIT`, `AGENT_TEAM_DATA_TOOLS`
(empty) and the Redis URLs.

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
