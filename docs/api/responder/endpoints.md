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

---

## Endpoint summary

| Method | Gateway path | Service path | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/responder/playbooks` | `/v1/playbooks` | List loaded playbooks |
| `POST` | `/api/v1/responder/playbooks/{playbook_id}/execute` | `/v1/playbooks/{playbook_id}/execute` | Start a run |
| `GET` | `/api/v1/responder/runs/{run_id}` | `/v1/runs/{run_id}` | Read a run |
| `DELETE` | `/api/v1/responder/runs/{run_id}` | `/v1/runs/{run_id}` | Mark a run canceled |
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
      "name": "Simple Notification Test",
      "description": "A basic playbook that logs a message for testing the workflow engine",
      "version": "1.0",
      "author": "Wildbox Security",
      "tags": ["test", "notification"],
      "steps_count": 3,
      "trigger_type": "api"
    }
  ],
  "total": 1
}
```

The response lists every playbook the service loaded. The repository ships
`simple_notification`, `triage_ip`, `triage_url` and `all_star_e2e` in
`open-security-responder/playbooks/`.

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
  "playbook_name": "Simple Notification Test",
  "status": "accepted",
  "status_url": "/v1/runs/6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
  "message": "Playbook 'Simple Notification Test' execution started"
}
```

`status_url` is the service path. Through the gateway, read the run at
`/api/v1/responder/runs/{run_id}`.

An unknown `playbook_id` answers `404`.

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
  "playbook_name": "Simple Notification Test",
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
    "[2026-10-03T09:15:02.120000] INFO: Playbook 'Simple Notification Test' queued for execution"
  ],
  "error": null,
  "duration_seconds": 2.343
}
```

The timestamps and IDs above are illustrative. The fields come from
`PlaybookExecutionResult` in `app/models.py`:

| Field | Description |
| --- | --- |
| `status` | `queued`, `pending`, `running`, `completed`, `failed` or `cancelled` |
| `step_results` | One entry per step that ran, with its own `status`, `output`, `error` and timing |
| `context` | The run's template context: `trigger`, `run` and the outputs of finished steps under `steps` |
| `logs` | Log lines recorded during the run |
| `error` | The failure reason when `status` is `failed` |

Run records are kept for 30 days by default, then expire. When the service starts,
it marks as `failed` any run still recorded as `running` or `queued` whose worker
has not updated it for 15 minutes.

---

## Cancel a run

`DELETE /api/v1/responder/runs/{run_id}`

```bash
curl -s --cacert "$CA" -X DELETE "$BASE/runs/<run-id>" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "message": "Execution '6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f' cancelled successfully",
  "status": "cancelled"
}
```

A run that is already `completed`, `failed` or `cancelled` is left unchanged and
the response reports its status. Canceling only marks the stored run record: it does
not stop a worker that is already executing the run's steps, and that worker can
still record its own final status afterward.

---

## Reload playbooks

`POST /api/v1/responder/playbooks/reload` (owner or admin)

Reloads the playbook files from disk and returns what was loaded:

```json
{
  "message": "Playbooks reloaded successfully",
  "total_loaded": 4,
  "playbooks": ["simple_notification", "triage_ip", "triage_url", "all_star_e2e"]
}
```

---

## List connectors

`GET /api/v1/responder/connectors`

Lists the connectors registered in the service and the actions each one offers.
Playbook steps call an action as `connector.action`.

```bash
curl -s --cacert "$CA" "$BASE/connectors" \
  -H "Authorization: Bearer $TOKEN"
```

Response shape:

```json
{
  "connectors": {
    "<connector-name>": {
      "name": "<connector-name>",
      "config": {},
      "actions": {
        "<action-name>": "<description>"
      }
    }
  },
  "total": 4
}
```

Connector configuration is not covered here: it is being reworked in
[issue #616](https://github.com/fabriziosalmi/wildbox/issues/616).

---

## Health check

The responder's health check is `GET /health` on the service's own port (bound to
`127.0.0.1:8018` in `docker-compose.yml`). It is not under `/v1/`, so the gateway
does not route it (`/api/v1/responder/health` maps to `/v1/health`, which does not
exist). It returns `{"status": "healthy", "timestamp": "..."}`, or
`"status": "unhealthy"` when Redis does not answer.

---

## Rate limits

The responder has no rate limit of its own. The gateway allows 10000 requests per
hour per team, enforced in fixed 60-second windows of 166 requests;
`X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset` describe the
current minute window, and `X-RateLimit-Policy` is `10000;w=3600`. A request over
the limit gets `429`. The `RATE_LIMIT_PER_HOUR` variable is currently ignored
([issue #627](https://github.com/fabriziosalmi/wildbox/issues/627)).

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
| `202` | Playbook run accepted |
| `401` | No valid credential (answered by the gateway) |
| `403` | Role or API key scope does not allow the request |
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
