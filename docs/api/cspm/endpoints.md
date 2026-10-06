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
| `GET` | `/api/v1/cspm/checks` | `/api/v1/checks` | Check catalog |
| `POST` | `/api/v1/cspm/scans` | `/api/v1/scans` | Start a scan |
| `POST` | `/api/v1/cspm/batch/scans` | `/api/v1/batch/scans` | Start several scans |
| `GET` | `/api/v1/cspm/scans/{scan_id}` | `/api/v1/scans/{scan_id}` | Status of a scan |
| `GET` | `/api/v1/cspm/scans/{scan_id}/report` | `/api/v1/scans/{scan_id}/report` | Report of a completed scan |
| `GET` | `/api/v1/cspm/scans/{scan_id}/compliance` | `/api/v1/scans/{scan_id}/compliance` | Per-framework figures of one scan |
| `DELETE` | `/api/v1/cspm/scans/{scan_id}` | `/api/v1/scans/{scan_id}` | Cancel a queued or running scan |
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

Query parameters, all optional: `provider`, `category` and `severity`, each
compared without regard to case.

```bash
curl -s --cacert "$CA" "$BASE/checks?category=data%20protection" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "total_checks": 1,
  "checks": [
    {
      "check_id": "AWS_S3_003",
      "title": "S3 Bucket Versioning Enabled",
      "description": "Ensure S3 buckets have versioning enabled to protect against accidental deletion or modification of objects.",
      "provider": "aws",
      "service": "S3",
      "category": "Data Protection",
      "severity": "medium",
      "compliance_frameworks": [
        "CIS AWS Foundations Benchmark v1.4.0 - 2.1.3",
        "AWS Security Best Practices",
        "SOC 2",
        "NIST CSF"
      ],
      "references": [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/versioning-workflows.html"
      ],
      "remediation": "Enable S3 bucket versioning: 1. Go to S3 console. 2. Select the bucket. 3. Go to Properties tab. 4. Click on 'Bucket Versioning'. 5. Enable versioning. 6. Consider enabling MFA delete for additional protection.",
      "enabled": true
    }
  ],
  "providers": ["aws"],
  "categories": ["Data Protection"]
}
```

| Field | Description |
| --- | --- |
| `total_checks` | Number of checks listed, after the filters |
| `checks[]` | What each check declares in its own metadata (`CheckMetadata` in `app/checks/framework.py`). `remediation` is the text a result of the check carries in a report; `severity` is `critical`, `high`, `medium`, `low` or `info` |
| `providers`, `categories` | The providers and categories of the checks listed, sorted |

A filter value that matches no check, such as `provider=gcp` or a provider the
service has never had, gives `200` with
`{"total_checks": 0, "checks": [], "providers": [], "categories": []}`, not an
error.

A category has one spelling, written with `and`: the catalog has 10, among them
`Logging and Monitoring` and `Identity and Access Management`. Up to 0.12.0 each of
those two was also spelled with `&` on some of its checks, so `categories` listed
both spellings and the filter gave the checks of the one asked for. The `category`
filter also takes `&` for `and` and any spacing: `category=Logging%20%26%20Monitoring`,
a value kept from an earlier answer, gives the same three checks as
`category=logging%20and%20monitoring`. A scan's report and the team's findings do
not carry a check's category, so nothing stored holds the old spelling.

Without a filter the route lists the 22 AWS checks in
`open-security-cspm/app/checks/aws/`, which the
[CSPM README](https://github.com/fabriziosalmi/wildbox/blob/main/open-security-cspm/README.md#checks)
also lists by service. The number of checks a scan runs is also in
[List providers](#list-providers).

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
- The scans are queued one after the other. If the task queue stops taking them
  partway, the answer is `503`: the scan that could not be queued is not recorded,
  the ones after it are not tried, and the ones before it are queued and will run.
  The `503` carries no `scan_id`: those scans count in the team's summaries, and
  no route lists them.
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
      "CIS AWS Foundations": {"total": 4, "passed": 1, "failed": 2, "compliance_percentage": 33.33333333333333},
      "PCI DSS": {"total": 4, "passed": 1, "failed": 2, "compliance_percentage": 33.33333333333333}
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
| `summary.compliance_frameworks` | Per framework: `total` counts every result tagged with it, whatever its status; `compliance_percentage` is `passed / (passed + failed) * 100`, and `0` without a verdict |
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

```bash
curl -s --cacert "$CA" "$BASE/scans/<scan-id>/compliance" \
  -H "Authorization: Bearer $TOKEN"
```

For the scan of the [report above](#read-a-scans-report):

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "account_id": "123456789012",
  "generated_at": "2026-10-03T10:45:02.118204",
  "frameworks": [
    {
      "framework": "CIS AWS Foundations",
      "total_checks": 4,
      "passed_checks": 1,
      "failed_checks": 2,
      "compliance_percentage": 33.33333333333333
    },
    {
      "framework": "PCI DSS",
      "total_checks": 4,
      "passed_checks": 1,
      "failed_checks": 2,
      "compliance_percentage": 33.33333333333333
    }
  ],
  "overall_score": 33.33333333333333,
  "recommendations": ["<how to fix it>"]
}
```

| Field | Description |
| --- | --- |
| `generated_at` | When this answer was made, not when the scan ran |
| `frameworks` | One entry per framework name the scan's results carry; with `framework`, that one only, and an empty list when no result carries it |
| `frameworks[].total_checks` | Every result tagged with the framework, whatever its status, as `summary.compliance_frameworks` in the report counts them. A result that errored or was skipped is in the total and in neither of the other two counts |
| `frameworks[].compliance_percentage` | `passed_checks / (passed_checks + failed_checks) * 100`, as `compliance_score` in the report; `0` when the framework has no result with a verdict |
| `overall_score` | The passed share over the frameworks listed: the sum of their `passed_checks` over the sum of their `passed_checks` and `failed_checks`, times 100. A result tagged with two frameworks counts twice. `0` when no framework is listed, or none has a verdict |
| `recommendations` | `summary.recommendations` of the report |

The two percentages are over the results that have a verdict, as
`compliance_score` in the report and the
[team compliance summary](#team-compliance-summary) are. Up to 0.12.0 they were
over `total_checks`, so a result that errored or was skipped lowered them as a
failed one does, and the scan above read 25% here and 33.3% in its report.

Two differences from the team summary remain:

- `total_checks` counts every result here, and `passed` and `failed` results only
  there.
- With no verdict at all the percentages are `0` here, and `compliance_score` in
  the report is `0.0`, where the team summary answers `null`.

`summary.compliance_frameworks` in a report is computed when the scan completes:
the report of a scan that completed on 0.12.0 or earlier keeps the percentage over
`total` it was stored with, and this route, which computes from the results,
answers the new figure for the same scan.

For a scan that has not completed it answers as
[the report route](#read-a-scans-report) does: `400`, `403` or `404`.

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

For a scan that is `queued` or `running`, the route revokes the scan's task,
terminating it if a worker is running it, records the scan as `cancelled` and
deletes the scan's encrypted credentials from Redis if no worker took them yet.

| Scan is | Answer |
| --- | --- |
| Queued or running | `200`, as above; its status then reads `cancelled` |
| Completed, failed or already cancelled | `409`, `Scan is already completed and cannot be cancelled` (with the scan's own status) |
| Finished by the worker while the cancellation was on its way | `409`, `Scan finished before it could be cancelled` |
| Another team's | `403`, whatever its state |

```json
{
  "error": {
    "code": 409,
    "message": "Scan is already completed and cannot be cancelled",
    "type": "HTTPException",
    "request_id": "<request id>"
  }
}
```

- **A `409` changes nothing.** The scan keeps its status, its times and its report,
  and the report keeps counting in the team summaries.
- **A cancelled scan is not run.** Celery keeps a revocation in the memory of the
  workers that were up when it was sent, so a scan cancelled while no worker ran, or
  before a worker restarted, is still delivered. The worker reads the scan's stored
  status before it opens a session, and returns without running a scan that reads
  `cancelled`.
- A scan cancelled while it ran has no report: `GET .../report` answers `400`. That
  holds when the revocation does not stop the worker in time and the scan runs to
  its end: the scan stays `cancelled` and the report is not stored.
- **A scan ends once.** The cancellation, the worker's completion and its failure
  each read the scan's status and write the new one in one Redis transaction
  (`WATCH`/`MULTI`): of two that cross, the first to write decides, and the other
  changes nothing. A completed scan's report and status are written together.

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

The status code says what the body says, so a probe that reads only the code
(`curl -f` in the Compose health check, `make health`) is told the same thing:

| `status` | Code | When | `checks` |
| --- | --- | --- | --- |
| `healthy` | `200` | Redis answers and a worker does | all `healthy` |
| `degraded` | `200` | Redis answers and no worker does, or the broker cannot be reached | `celery` is `unhealthy` |
| `unhealthy` | `503` | Redis cannot be reached | `redis` is `unhealthy`; the workers are not asked, and `celery` is `unknown` |
| `unhealthy` | `503` | The check itself failed | `{"api": "unhealthy", "error": "Health check failed"}` |

- The `503` carries this same body, not the [error format](#errors). The cause is in
  the service's log, not in the body.
- `degraded` stays `200` so that the `cspm` container does not read unhealthy while
  its worker starts or restarts: the API reads and queues, and scans wait. The
  worker has its own health check in `docker-compose.yml`.
- Compose marks an unhealthy container and does not restart it, and no service
  waits for `cspm` to be healthy.
- The route waits one second for the workers' replies, so it takes about that long
  whenever Redis answers. It waits in a thread: the service answers other requests,
  `/health/live` included, in the meantime.
- It answers within 4 seconds whatever Redis and the broker do, inside the 5
  seconds `make health` waits and the 10 of the Compose health check. A check that
  has not answered by then is `unhealthy` in `checks`: `503` for Redis, `degraded`
  for the workers.
- A Redis that accepts the connection and never answers (a paused container, a host
  that stopped) is `unhealthy` after 3 seconds: the API gives Redis 2 seconds to
  accept a connection and 3 to send a reply. See
  [When Redis does not answer](#when-redis-does-not-answer).

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
| `409` | A cancellation of a scan that already completed, failed or was cancelled |
| `422` | The body, a query parameter or the `scan_id` is not valid |
| `429` | Gateway rate limit exceeded |
| `500` | The service failed to handle the request |
| `503` | Redis or the task queue cannot be reached (`Scan store or task queue temporarily unavailable`); or `GATEWAY_INTERNAL_SECRET` is not set in the service |

When Redis cannot be reached, every route that reads or writes it answers `503` in
this format, and so does a scan the broker cannot take; the cause is in the
service's log. A scan that could not be queued is not recorded: its credentials,
its record and its entry in the team's index are removed, so it does not read
`queued` afterwards. `GET /providers` and `GET /checks` read nothing from Redis and
answer as usual. [`GET /health`](#health-check) answers `503` with its own body.

### When Redis does not answer

A Redis that is down refuses the connection, and the `503` is immediate. One that
accepts the connection and then sends nothing is given a limited time by the API:

| Client | Variable | Connection | Each reply |
| --- | --- | --- | --- |
| Scan store | `REDIS_URL` | 2 s | 3 s |
| Task queue | `CELERY_BROKER_URL` | 2 s | 3 s |
| State of scans in progress | `CELERY_RESULT_BACKEND` | 2 s | 3 s |

- The route then answers `503`, as when Redis is down. Measured with a server that
  accepts and never answers in all three roles: every route and `/health` in 3
  seconds. With the store answering and the other two not: `POST /scans` in 6
  seconds, `GET` and `DELETE /scans/{scan_id}` in 3.
- `socket_timeout` and `socket_connect_timeout` in the query string of `REDIS_URL`
  (in seconds) replace the store's two limits, and in `CELERY_RESULT_BACKEND` the
  backend's. The broker's are not read from its URL.
- The limits are the API's. The worker keeps Celery's own: it waits on its broker
  connection for as long as no scan is queued.

---

## Related Documentation

- [Identity Service API](../identity/endpoints.md) - Sign-in and API keys
- [Guardian Service API](../guardian/endpoints.md) - Asset and vulnerability management
- [Authentication guide](../../guides/authentication.md) - Tokens and API keys through the gateway
- [Security Policy](../../security/policy.md) - Authentication requirements
