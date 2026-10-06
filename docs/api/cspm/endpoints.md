# CSPM Service API

CSPM (Cloud Security Posture Management) is the FastAPI service that scans a cloud
account with a fixed set of checks and reports the results and the compliance
frameworks each check maps to. It scans AWS only. This page lists the routes defined in
`open-security-cspm/app/main.py` and how to reach them through the gateway.

In the examples, `<host>` is the name you reach the gateway by, and IDs, account
numbers and credentials are placeholders.

## Table of Contents

- [Base URL and routing](#base-url-and-routing)
- [Authentication and permissions](#authentication-and-permissions)
- [Endpoint summary](#endpoint-summary)
- [List providers](#list-providers)
- [List checks](#list-checks)
- [Start a scan](#start-a-scan)
- [Start several scans](#start-several-scans)
- [Read a scan's status](#read-a-scans-status)
- [Read a scan's report](#read-a-scans-report)
- [Read a scan's compliance report](#read-a-scans-compliance-report)
- [Cancel a scan](#cancel-a-scan)
- [Team summary](#team-summary)
- [Team compliance summary](#team-compliance-summary)
- [Team compliance findings](#team-compliance-findings)
- [Configuration](#configuration)
- [Health check](#health-check)
- [Rate limits](#rate-limits)
- [Errors](#errors)

---

## Base URL and routing

CSPM serves its API under `/api/v1/`. The gateway replaces `/api/v1/cspm/` with
`/api/v1/`:

```text
https://<host>/api/v1/cspm/<path>  ->  cspm /api/v1/<path>
```

So `/api/v1/scans` on the service is `https://<host>/api/v1/cspm/scans` through the
gateway. Set up a shell for the examples:

```bash
CA=open-security-gateway/ssl/wildbox.crt
BASE="https://<host>/api/v1/cspm"
```

---

## Authentication and permissions

The gateway authenticates every request and passes the caller's user, team and role
to CSPM in trusted headers, with the secret that proves the request came from the
gateway. Use either credential:

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

Scopes and roles:

- **API key scopes are checked by the gateway.** A key limited by scopes needs
  `read` (or `write`) for `GET` requests and `write` for `POST` and `DELETE`
  (`ROUTE_SCOPES` in `open-security-gateway/nginx/lua/auth_handler.lua`); `admin`
  satisfies both. A session token is not limited by scopes. CSPM does not check
  the scopes again: its dependency reads the user, team, role and gateway secret
  only (`get_current_user` in `app/main.py`).
- **No route asks for a role.** Any member of a team can start, read and cancel the
  team's scans.
- **Scans belong to the team that started them.** Reading, reporting on or
  cancelling another team's scan answers `403` (`Access denied`); a scan that does
  not exist answers `404`. The team summaries count the caller's team only.

---

## Endpoint summary

| Method | Gateway path | Service path | Description |
| --- | --- | --- | --- |
| `GET` | `/api/v1/cspm/providers` | `/api/v1/providers` | Providers a scan can name |
| `GET` | `/api/v1/cspm/checks` | `/api/v1/checks` | Check catalog (see the defect under [List checks](#list-checks)) |
| `POST` | `/api/v1/cspm/scans` | `/api/v1/scans` | Start a scan |
| `POST` | `/api/v1/cspm/batch/scans` | `/api/v1/batch/scans` | Start several scans |
| `GET` | `/api/v1/cspm/scans/{scan_id}` | `/api/v1/scans/{scan_id}` | Status of a scan |
| `GET` | `/api/v1/cspm/scans/{scan_id}/report` | `/api/v1/scans/{scan_id}/report` | Report of a completed scan |
| `GET` | `/api/v1/cspm/scans/{scan_id}/compliance` | `/api/v1/scans/{scan_id}/compliance` | Per-framework figures of one scan (see the defect under [Read a scan's compliance report](#read-a-scans-compliance-report)) |
| `DELETE` | `/api/v1/cspm/scans/{scan_id}` | `/api/v1/scans/{scan_id}` | Cancel a scan |
| `GET` | `/api/v1/cspm/dashboard/summary` | `/api/v1/dashboard/summary` | Scan count and findings of the team |
| `GET` | `/api/v1/cspm/compliance/summary` | `/api/v1/compliance/summary` | Compliance of the team's accounts |
| `GET` | `/api/v1/cspm/compliance/findings` | `/api/v1/compliance/findings` | Check verdicts of the team's accounts |

There is no route that lists a team's scans, none that reads a batch by its
`batch_id`, and none that stores cloud credentials: every scan request carries its
own. `scan_id` is a UUID in lowercase; anything else answers `422`.

---

## List providers

`GET /api/v1/cspm/providers`

```bash
curl -s --cacert "$CA" "$BASE/providers" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "providers": [
    {"provider": "aws", "name": "Amazon Web Services", "checks": 22}
  ]
}
```

A provider is listed when CSPM can open a session for it (`SESSION_FACTORIES` in
`app/providers.py`) and loaded at least one enabled check for it. Only AWS has
both. `checks` is the number of checks a scan runs when it names no `check_ids`.
The scan routes refuse every provider that is not in this list.

---

## List checks

`GET /api/v1/cspm/checks`

Query parameters, all optional: `provider` (`aws`, `gcp` or `azure`), `category`
and `severity` (both compared without regard to case).

**Defect: this route answers `500` whenever at least one check matches.** The
catalog entries the check runner returns have no `remediation` field
(`get_available_checks` in `app/checks/runner.py`), and the response model requires
one (`CheckMetadataSchema` in `app/schemas.py`), so building the response fails and
the handler answers:

```json
{
  "error": {
    "code": 500,
    "message": "Failed to list checks",
    "type": "HTTPException",
    "request_id": "<request id>"
  }
}
```

What it does answer today:

| Request | Answer |
| --- | --- |
| No filter, or filters that match a check | `500`, as above |
| Filters that match no check, such as `provider=gcp` | `200` with `{"total_checks": 0, "checks": [], "providers": [], "categories": []}` |
| A `provider` that is not `aws`, `gcp` or `azure` | `500`, as above |

The checks themselves are listed in the
[CSPM README](https://github.com/fabriziosalmi/wildbox/blob/main/open-security-cspm/README.md#checks):
22 AWS checks, in `open-security-cspm/app/checks/aws/`. The number of checks a scan
runs is also in [List providers](#list-providers).

---

## Start a scan

`POST /api/v1/cspm/scans`

```bash
curl -s --cacert "$CA" -X POST "$BASE/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "credentials": {
      "auth_method": "access_key",
      "access_key_id": "<access key id>",
      "secret_access_key": "<secret access key>"
    },
    "account_id": "123456789012",
    "account_name": "Production",
    "regions": ["us-east-1", "eu-west-1"]
  }'
```

Request fields (`ScanRequest` in `app/schemas.py`):

| Field | Required | Description |
| --- | --- | --- |
| `provider` | yes | `aws`. The schema also accepts `gcp` and `azure`, which the route then refuses with `400` |
| `credentials` | yes | The provider's credentials; for AWS, the fields below |
| `account_id` | yes | The account's identifier, as a string. The summaries group scans by provider and `account_id` |
| `account_name` | no | A name for the account, returned in the report |
| `regions` | no | Regions to scan. Without it: `us-east-1`, `us-west-2` and `eu-west-1` |
| `check_ids` | no | Check ids to run. Without it: every enabled check. An id that names no check is ignored |
| `metadata` | no | An object passed to the worker with the task. `requested_by` and `team_id` in it are overwritten with the caller's |

AWS credentials (`AWSCredentials`):

| Field | Required | Description |
| --- | --- | --- |
| `auth_method` | no | `access_key` (default) or `assume_role`; another value answers `422` |
| `access_key_id` | yes | Access key id |
| `secret_access_key` | yes | Secret access key |
| `region` | no | Region of the session, `us-east-1` by default |
| `role_arn` | for `assume_role` | ARN of the IAM role to assume |
| `external_id` | no | External id sent with `assume_role` |

**Response (202 Accepted)**:

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "started",
  "provider": "aws",
  "account_id": "123456789012",
  "started_at": "2026-10-03T10:30:00.118204",
  "estimated_duration_minutes": 15
}
```

- **The API only queues the scan.** It encrypts the credentials into Redis with
  `CSPM_CREDENTIAL_KEY` for five minutes, records the scan for the caller's team and
  queues a Celery task; the `cspm-worker` service runs it and deletes the
  credentials when it starts. The credentials are never returned by any route.
- **`estimated_duration_minutes` is a fixed figure, not a measurement:** 15 for AWS,
  plus 2 for each region beyond three, halved (5 at least) when `check_ids` is given
  (`_estimate_scan_duration` in `app/utils.py`).
- **Credentials are checked when the worker opens the session, not here.** An access
  key id that is not 16 to 128 letters, digits or underscores, or `assume_role`
  without the ARN of an IAM role, is accepted with `202` and the scan then reads
  `failed`. Well-formed keys that AWS rejects do not fail the scan: a check that
  meets an error records a result with status `error`, or no result at all, and the
  scan reads `completed`.
- **Times are UTC without an offset**, here and in every other response.

A provider other than `aws` answers `400`, before anything is stored or queued:

```json
{
  "error": {
    "code": 400,
    "message": "Unsupported provider: gcp. Supported providers: aws.",
    "type": "HTTPException",
    "request_id": "<request id>"
  }
}
```

---

## Start several scans

`POST /api/v1/cspm/batch/scans`

```bash
curl -s --cacert "$CA" -X POST "$BASE/batch/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scans": [
      {"provider": "aws", "account_id": "111111111111",
       "credentials": {"access_key_id": "<id>", "secret_access_key": "<secret>"}},
      {"provider": "aws", "account_id": "222222222222",
       "credentials": {"access_key_id": "<id>", "secret_access_key": "<secret>"}}
    ]
  }'
```

`scans` is a list of scan requests, each with the fields of
[Start a scan](#start-a-scan). **Response (200 OK)**:

```json
{
  "batch_id": "4d8836d6-b1b9-4256-9d58-9df16ab1f66d",
  "total_scans": 2,
  "scans": [
    {
      "scan_id": "f91e7425-0611-40f4-afca-a7a05ed32404",
      "provider": "aws",
      "account_id": "111111111111",
      "task_id": "f91e7425-0611-40f4-afca-a7a05ed32404",
      "status": "started"
    },
    {
      "scan_id": "8a040509-fa95-48e6-9c87-129436237146",
      "provider": "aws",
      "account_id": "222222222222",
      "task_id": "8a040509-fa95-48e6-9c87-129436237146",
      "status": "started"
    }
  ],
  "started_at": "2026-10-03T10:30:00.226235"
}
```

- Each scan is started exactly as `POST /scans` starts one, and is read, reported on
  and cancelled by its own `scan_id`. `task_id` is the same value.
- A batch that names a provider other than `aws` is refused whole with `400`; none
  of its scans is stored or queued.
- An empty `scans` list is accepted and answers `200` with `total_scans` 0.
- The request also accepts `parallel_execution_limit` and `metadata`. Neither is
  used: every scan is queued at once, and the worker's concurrency decides how many
  run together.
- `batch_id` is recorded with each scan and is not a key to read anything by.

---

## Read a scan's status

`GET /api/v1/cspm/scans/{scan_id}`

```bash
curl -s --cacert "$CA" "$BASE/scans/<scan-id>" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "running",
  "provider": "aws",
  "account_id": "123456789012",
  "started_at": "2026-10-03T10:30:00.117873",
  "completed_at": null,
  "progress": {
    "current_status": "initializing",
    "total_checks": null,
    "completed_checks": null,
    "current_region": null
  }
}
```

| Field | Description |
| --- | --- |
| `status` | `queued` until a worker takes the scan, `running` while it runs, then `completed`, `failed` or `cancelled`. `unknown` when the task is in a state the route does not map |
| `completed_at` | Set only when `status` is `completed` |
| `progress` | Set only while `status` is `running`. `current_status` is `running` when the worker took the task and `initializing` once it opened the session; the worker reports no counts, so `total_checks`, `completed_checks` and `current_region` are always `null` |

A scan fails when its credentials expired before a worker took it (five minutes after
it was queued), when no session can be opened with them, or when it exceeds its time
limit (`SCAN_TIMEOUT_SECONDS`). The response does not say which: the reason is in the
worker's log.

A scan is kept for `CSPM_REPORT_RETENTION_DAYS` days (90 by default) from the last
time it was written; after that its id answers `404`.

---

## Read a scan's report

`GET /api/v1/cspm/scans/{scan_id}/report`

The report the worker stored when the scan completed. Abridged to one result:

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "provider": "aws",
  "account_id": "123456789012",
  "account_name": "Production",
  "regions": ["us-east-1", "eu-west-1"],
  "started_at": "2026-10-03T10:30:04.070242",
  "completed_at": "2026-10-03T10:41:12.904416",
  "status": "completed",
  "total_checks": 4,
  "passed_checks": 1,
  "failed_checks": 2,
  "error_checks": 1,
  "skipped_checks": 0,
  "not_implemented_checks": 0,
  "critical_findings": 0,
  "high_findings": 1,
  "medium_findings": 0,
  "low_findings": 0,
  "info_findings": 0,
  "compliance_score": 33.33333333333333,
  "results": [
    {
      "check_id": "AWS_CLOUDTRAIL_001",
      "resource_id": "<resource id>",
      "resource_type": "<resource type>",
      "resource_name": null,
      "region": "us-east-1",
      "status": "failed",
      "message": "<what the check found>",
      "details": {},
      "remediation": "<how to fix it>",
      "compliance_frameworks": ["CIS AWS Foundations", "PCI DSS"],
      "timestamp": "2026-10-03T10:30:09.070362"
    }
  ],
  "summary": {
    "duration_seconds": 668.834174,
    "checks_by_status": {"passed": 1, "failed": 2, "error": 1, "skipped": 0, "not_implemented": 0},
    "findings_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "unknown": 1},
    "compliance_frameworks": {
      "CIS AWS Foundations": {"total": 4, "passed": 1, "failed": 2, "compliance_percentage": 25.0},
      "PCI DSS": {"total": 4, "passed": 1, "failed": 2, "compliance_percentage": 25.0}
    },
    "recommendations": ["<how to fix it>"]
  }
}
```

The figures above are illustrative. The fields come from `ScanReportSchema` in
`app/schemas.py` and `ScanReport` in `app/checks/framework.py`:

| Field | Description |
| --- | --- |
| `total_checks` and the `*_checks` counts | Count results, not checks: a check gives one result per resource it inspected, in each region |
| `critical_findings` to `info_findings` | Failed results, by the severity their check declares |
| `compliance_score` | `passed_checks / (passed_checks + failed_checks) * 100`; results that errored, were skipped or are not implemented do not count |
| `results[].status` | `passed`, `failed`, `error`, `skipped` or `not_implemented` |
| `summary.findings_by_severity.unknown` | Failed results whose check is not in the catalog. The count has no top-level field in this response |
| `summary.compliance_frameworks` | Per framework: `total` counts every result tagged with it, whatever its status |
| `summary.recommendations` | The five most frequent remediation texts among failed results |

| Scan is | Answer |
| --- | --- |
| Completed | `200` with the report |
| Queued, running, failed or cancelled before it completed | `400`, `Scan is not completed` |
| Completed, and its stored report cannot be read | `500`, `Scan report not available` |

---

## Read a scan's compliance report

`GET /api/v1/cspm/scans/{scan_id}/compliance`

Optional query parameter: `framework`, the exact name of one framework.

**Defect: this route answers `500` for every completed scan.** The handler gives
`generated_at` a date and time (`get_compliance_report` in `app/main.py`) where the
response model declares a string (`ComplianceReportResponse` in `app/schemas.py`),
so building the response fails:

```json
{
  "error": {
    "code": 500,
    "message": "Failed to generate compliance report",
    "type": "HTTPException",
    "request_id": "<request id>"
  }
}
```

For a scan that has not completed it answers as
[the report route](#read-a-scans-report) does: `400`, `403` or `404`.

The same per-framework figures are in the report itself, under
`summary.compliance_frameworks`, and for the team's accounts together in
[Team compliance summary](#team-compliance-summary).

---

## Cancel a scan

`DELETE /api/v1/cspm/scans/{scan_id}`

```bash
curl -s --cacert "$CA" -X DELETE "$BASE/scans/<scan-id>" \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK)**:

```json
{"message": "Scan cancelled successfully"}
```

The route revokes the scan's task, terminating it if a worker is running it, and
records the scan as `cancelled`. **It does not look at the scan's state first:** a
scan that already completed or failed is recorded as `cancelled` too. Its stored
report stays readable and keeps counting in the team summaries.

---

## Team summary

`GET /api/v1/cspm/dashboard/summary`

Query parameter: `days`, from 1 to 365, 30 by default.

```json
{
  "total_scans": 4,
  "last_scan_at": "2026-10-03T10:30:00.848581",
  "summary_period_days": 30,
  "accounts_assessed": 1,
  "compliance_score": 33.3,
  "total_findings": 2,
  "critical_findings": 0,
  "high_findings": 1,
  "medium_findings": 0,
  "low_findings": 0,
  "info_findings": 0,
  "unknown_severity_findings": 1
}
```

| Field | Description |
| --- | --- |
| `total_scans`, `last_scan_at` | Every scan of the team that is still kept, whatever its status and whatever `days` says |
| `accounts_assessed` | Accounts with a stored report of a scan started in the period |
| `compliance_score` | Passed share of the `passed` and `failed` results, to one decimal; `null` when there are none |
| `total_findings` and the severity counts | Failed results, by the severity their check declares today |
| `unknown_severity_findings` | Failed results whose check is no longer in the catalog |

Every figure but the first two comes from the newest report of each of the team's
accounts (an account is a provider and an `account_id`) among the scans started in
the last `days` days. With no such report the counts are 0 and `compliance_score` is
`null`: nothing was assessed, which is not 0%.

---

## Team compliance summary

`GET /api/v1/cspm/compliance/summary`

Query parameters: `days` (1 to 365, 30 by default) and `provider`, which keeps the
scans of one provider.

```json
{
  "total_resources": 3,
  "compliant_resources": 1,
  "non_compliant_resources": 2,
  "overall_score": 33.3,
  "frameworks": [
    {
      "name": "CIS AWS Foundations",
      "total_checks": 3,
      "passed_checks": 1,
      "failed_checks": 2,
      "compliance_percentage": 33.3,
      "last_assessment": "2026-10-03T10:41:12.904416"
    }
  ],
  "scans_considered": 1,
  "summary_period_days": 30,
  "provider_filter": null,
  "last_updated": "2026-10-03T10:41:12.904416"
}
```

| Field | Description |
| --- | --- |
| `total_resources` | Distinct resources (account and `resource_id`) with at least one `passed` or `failed` result |
| `non_compliant_resources` | Resources with at least one `failed` result |
| `overall_score` | Passed share of the `passed` and `failed` results, to one decimal; `null` when there are none |
| `frameworks` | One entry per framework name the results carry, sorted by name. `total_checks` counts `passed` and `failed` results only, unlike `summary.compliance_frameworks` in a report |
| `scans_considered` | Reports the figures come from: the newest of each account in the period |
| `last_updated` | Completion time of the newest of those scans |

With no report in the period every count is 0, `frameworks` is empty and
`overall_score` and `last_updated` are `null`.

---

## Team compliance findings

`GET /api/v1/cspm/compliance/findings`

One entry per `passed` or `failed` result in the reports the
[compliance summary](#team-compliance-summary) reads, newest scan first.

| Parameter | Default | Description |
| --- | --- | --- |
| `days` | `30` | Period, 1 to 365 |
| `provider` | none | Keep the scans of one provider |
| `framework` | none | Keep the results tagged with this exact framework name |
| `severity` | none | `critical`, `high`, `medium`, `low` or `info`, in lowercase |
| `status` | none | `passed` or `failed` |
| `limit` | `100` | Page size, 1 to 1000 |
| `offset` | `0` | Results to skip |

```bash
curl -s --cacert "$CA" "$BASE/compliance/findings?status=failed&limit=1" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "findings": [
    {
      "finding_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479:0",
      "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "check_id": "AWS_CLOUDTRAIL_001",
      "title": "CloudTrail Enabled in All Regions",
      "frameworks": ["CIS AWS Foundations", "PCI DSS"],
      "resource_id": "<resource id>",
      "resource_type": "<resource type>",
      "region": "us-east-1",
      "status": "failed",
      "severity": "high",
      "description": "<what the check found>",
      "remediation": "<how to fix it>",
      "last_checked": "2026-10-03T10:30:09.070362"
    }
  ],
  "total_count": 2,
  "limit": 1,
  "offset": 0,
  "has_more": true
}
```

- `finding_id` is the scan's id and the position of the result in its report. It is
  not stable across scans, and no route reads a finding by it.
- `title` and `severity` come from the check's metadata as the service has it now.
  A result whose check is no longer in the catalog has its `check_id` as `title` and
  `severity` `null`.
- A filter value that matches nothing gives an empty page, not an error.

---

## Configuration

Environment variables the CSPM API and its worker read (`app/config.py`,
`app/credential_crypto.py` and `open-security-shared/gateway_auth.py`). The worker
is the `cspm-worker` service, built from the same directory; it needs the same
values except `GATEWAY_INTERNAL_SECRET`.

| Variable | Default | Description |
| --- | --- | --- |
| `SECRET_KEY` | none | Required, at least 32 characters: the service does not start without it. `docker-compose.yml` sets it from `CSPM_SECRET_KEY`. Also the credential key when `CSPM_CREDENTIAL_KEY` is not set |
| `CSPM_CREDENTIAL_KEY` | `SECRET_KEY` | Encrypts a scan's cloud credentials in Redis. Required by `docker-compose.yml` |
| `GATEWAY_INTERNAL_SECRET` | none | Checked on every request under `/api/v1/`. Without it they answer `503` |
| `REDIS_URL` | `redis://localhost:6379/0` | Scan records, team indexes and reports. Database 3 in `docker-compose.yml` |
| `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | The scan queue and the state of queued and running scans. Database 3 in `docker-compose.yml` |
| `SCAN_TIMEOUT_SECONDS` | `3600` | Time limit of one scan, 120 to 86400; the API and the worker do not start otherwise. `docker-compose.yml` sets it from `CSPM_SCAN_TIMEOUT_SECONDS` |
| `CSPM_REPORT_RETENTION_DAYS` | `90` | Days a scan's record, index entry and report are kept, 1 to 3650; the API and the worker do not start otherwise |
| `MAX_CONCURRENT_SCANS` | `5` | Check executions that run at once within one scan |
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Origins the service's own CORS middleware allows, as a JSON list |
| `LOG_LEVEL` | `INFO` | Log level |
| `ENVIRONMENT` | none | `/docs`, `/redoc` and `/openapi.json` are served on the service port only when it is `development`. Required by `docker-compose.yml` |
| `HOST`, `PORT`, `WORKERS`, `DEBUG` | `0.0.0.0`, `8019`, `4`, `false` | Read only when the module is run directly (`python -m app.main`); the image starts `uvicorn` on port 8019 |

How the worker runs scans, its time limit and concurrency, and the Redis memory the
reports need are described in the
[CSPM README](https://github.com/fabriziosalmi/wildbox/blob/main/open-security-cspm/README.md#the-scan-worker).

---

## Health check

CSPM's health checks are on the service's own port (bound to `127.0.0.1:8019` in
`docker-compose.yml`), without authentication. They are not under `/api/v1/`, so the
gateway does not route them (`/api/v1/cspm/health` maps to `/api/v1/health`, which
does not exist).

- `GET /health/live` answers `{"status": "alive"}` while the process runs.
- `GET /health` asks Redis and the Celery workers:

```json
{
  "status": "healthy",
  "timestamp": "2026-10-03T10:30:00.670356",
  "version": "0.1.6",
  "uptime_seconds": 3600.3,
  "checks": {"redis": "healthy", "celery": "healthy", "api": "healthy"}
}
```

`status` is `degraded`, still with `200`, when Redis answers and no worker does.
When Redis cannot be reached the route answers `500` in the
[error format](#errors), not a health body.

---

## Rate limits

CSPM has no rate limit of its own. The gateway's limit per team applies to these
routes as to every other; a request over it gets `429` from the gateway. See the
[gateway README](https://github.com/fabriziosalmi/wildbox/blob/main/open-security-gateway/README.md).

---

## Errors

CSPM errors use the shared Wildbox error format (`open-security-shared/errors.py`):

```json
{
  "error": {
    "code": 404,
    "message": "Scan not found",
    "type": "HTTPException",
    "request_id": "<request id>"
  }
}
```

A `422` adds `error.details`, a list with one entry per invalid field (`type`, `loc`
and `msg`). A request that did not come through the gateway adds `error.details`
with the reason in `error.details.code`: `GATEWAY_AUTH_REQUIRED`,
`GATEWAY_SECRET_REQUIRED` or `INVALID_GATEWAY_HEADERS`.

| Status | Meaning |
| --- | --- |
| `200` | The request succeeded. Batch scans and a cancellation answer `200` |
| `202` | A single scan was queued |
| `400` | A provider that cannot be scanned; a report asked of a scan that has not completed; malformed identity headers |
| `401` | No valid credential (answered by the gateway) |
| `403` | The scan belongs to another team; the API key's scopes do not allow the request (answered by the gateway); or the request did not come through the gateway |
| `404` | A scan that does not exist or is past its retention, or a path the service does not serve |
| `422` | The body, a query parameter or the `scan_id` is not valid |
| `429` | Gateway rate limit exceeded |
| `500` | The service failed to handle the request. Also the answer of the two routes marked as defects above, and of every route when Redis cannot be reached |
| `503` | `GATEWAY_INTERNAL_SECRET` is not set in the service |

`POST /scans` has a `503` (`Task queue temporarily unavailable`) for a connection
error, but the errors the Redis client and the Celery broker raise are not of the
types it catches, so a request made while Redis is unreachable answers `500`.

---

## Related Documentation

- [Identity Service API](../identity/endpoints.md) - Sign-in and API keys
- [Guardian Service API](../guardian/endpoints.md) - Asset and vulnerability management
- [Authentication guide](../../guides/authentication.md) - Tokens and API keys through the gateway
- [Security Policy](../../security/policy.md) - Authentication requirements
