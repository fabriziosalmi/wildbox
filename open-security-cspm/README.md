# Open Security CSPM

Cloud Security Posture Management service for the Wildbox platform. It runs
security checks against cloud accounts and reports their results and the
compliance frameworks each check maps to. It scans AWS only; see
[Providers](#providers).

## Overview

- FastAPI service on port 8019 (`app/main.py`), reached through the gateway
  at `/api/v1/cspm/`.
- Scans run in a separate Celery worker (`cspm-worker`); see
  [The scan worker](#the-scan-worker).
- Scan metadata, team indexes and reports are kept in Redis (database 3 in
  the Wildbox stack); see
  [Scan retention and Redis memory](#scan-retention-and-redis-memory).
- Cloud credentials are encrypted with `CSPM_CREDENTIAL_KEY` before they are
  written to Redis, kept for five minutes at most, and deleted when the
  worker starts the scan.

```text
dashboard / API client
        |  https://localhost/api/v1/cspm/...
        v
gateway (authentication) --> cspm API (8019) --> Redis db 3 (queue, metadata, reports)
                                                      |
                                                      v
                                        cspm-worker (Celery) --> AWS APIs
```

## Providers

Only AWS is scanned. `GET /api/v1/providers` lists the providers cspm can
scan, with the number of checks a scan of each runs:

| Provider | Scans | Services checked |
| --- | --- | --- |
| AWS | yes | S3, EC2, IAM, RDS, VPC, CloudTrail, KMS, Lambda, SNS, SQS |

A provider is supported when `app/providers.py` has a session factory for it
(`SESSION_FACTORIES`) and the check runner loaded at least one enabled,
implemented check for it (`app/checks/<provider>/`). The scan endpoints,
`GET /api/v1/providers` and the dashboard's scan form all read that one
registry. `POST /api/v1/scans` and `POST /api/v1/batch/scans` refuse any
other provider (the request schema still accepts `gcp` and `azure`) with a
400 that names the supported ones, before they store credentials or queue
anything; a batch that names one is refused whole.

The GCP and Azure checks that used to ship returned the same invented
resources on every run and could never run anyway, because no GCP or Azure
session existed; they were removed (#612). To add a provider, add its
session factory and its checks together.

AWS credentials use `auth_method` `access_key` (access key id and secret) or
`assume_role` (the same plus `role_arn` and an optional `external_id`).

## Checks

There are 22 AWS checks, one class per file under `app/checks/aws/`:

| Service | Check ids |
| --- | --- |
| CloudTrail | `AWS_CLOUDTRAIL_001` enabled, `AWS_CLOUDTRAIL_002` log file validation, `AWS_CLOUDTRAIL_003` multi-region |
| EC2 | `AWS_EC2_001` EBS encryption |
| IAM | `AWS_IAM_001` root MFA, `AWS_IAM_002` unused access keys, `AWS_IAM_003` password policy, `AWS_IAM_005` unused credentials, `AWS_IAM_006` inline user policies |
| KMS | `AWS_KMS_001` key rotation, `AWS_KMS_002` key permissions |
| Lambda | `AWS_LAMBDA_001` environment encryption, `AWS_LAMBDA_002` public access |
| RDS | `AWS_RDS_003` Multi-AZ |
| S3 | `AWS_S3_001` public buckets, `AWS_S3_003` versioning, `AWS_S3_004` MFA delete |
| SNS | `AWS_SNS_001` topic encryption |
| SQS | `AWS_SQS_001` queue encryption |
| VPC | `AWS_VPC_001` flow logs, `AWS_VPC_002` default security group, `AWS_VPC_003` security groups open to the internet |

`GET /api/v1/checks` returns each check's metadata: title, description,
service, category, severity, compliance frameworks, references and
remediation (see [Check catalog](#check-catalog)). The number of checks is
also in `GET /api/v1/providers`. A scan runs every check in every requested
region; without `regions` it uses `us-east-1`, `us-west-2` and `eu-west-1`.

### Compliance frameworks

Each check declares the frameworks it maps to in `compliance_frameworks`.
The values in use are `AWS Security Best Practices`, `SOC 2`, `NIST CSF`,
`PCI DSS`, `HIPAA`, `GDPR`, `AWS Well-Architected Framework`,
`CIS AWS Foundations`, and CIS AWS Foundations Benchmark v1.4.0 entries that
name a section (for example
`CIS AWS Foundations Benchmark v1.4.0 - 2.1.5`). The compliance endpoints
group results by these exact strings, so each CIS section is reported as its
own entry. The mapping says which checks relate to a framework; it does not
cover a framework's full set of controls.

## Running

In the Wildbox stack, from the repository root:

```bash
docker compose up -d cspm cspm-worker
```

The root `docker-compose.yml` requires `ENVIRONMENT`, `CSPM_SECRET_KEY`,
`CSPM_CREDENTIAL_KEY` and `REDIS_PASSWORD`, and passes
`GATEWAY_INTERNAL_SECRET`, without which every `/api/v1/*` route answers
503. The
service listens on `127.0.0.1:8019` on the host; its `/health` and
`/health/live` answer there without authentication.

## Authentication

Every `/api/v1/*` route requires the gateway's identity headers
(`X-Wildbox-User-ID`, `X-Wildbox-Team-ID`, `X-Wildbox-Role`) and the shared
`GATEWAY_INTERNAL_SECRET`, checked by `open_security_shared.gateway_auth`.
Call the API through the gateway with a JWT or an API key; the gateway maps
`/api/v1/cspm/<path>` to `/api/v1/<path>` on the service:

```bash
curl --cacert open-security-gateway/ssl/wildbox.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://localhost/api/v1/cspm/providers
```

Scans belong to the caller's team. Reading, cancelling or reporting on
another team's scan answers 403.

## API

Service paths; through the gateway, replace `/api/v1/` with
`/api/v1/cspm/`. The reference, with every field and status code, is
[docs/api/cspm/endpoints.md](../docs/api/cspm/endpoints.md).

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/v1/scans` | Start a scan (202) |
| GET | `/api/v1/scans/{scan_id}` | Scan status |
| GET | `/api/v1/scans/{scan_id}/report` | Full report of a completed scan |
| GET | `/api/v1/scans/{scan_id}/compliance` | Per-framework results of one scan; optional `framework` filter |
| DELETE | `/api/v1/scans/{scan_id}` | Cancel a queued or running scan; 409 for one that already ended |
| POST | `/api/v1/batch/scans` | Start several scans |
| GET | `/api/v1/providers` | Providers that can be scanned |
| GET | `/api/v1/checks` | Check catalog; optional `provider`, `category`, `severity` filters |
| GET | `/api/v1/dashboard/summary` | Team summary; `days` 1 to 365, default 30 |
| GET | `/api/v1/compliance/summary` | Team compliance; `days`, `provider` |
| GET | `/api/v1/compliance/findings` | Check verdicts; `framework`, `severity`, `status`, `days`, `provider`, `limit`, `offset` |
| GET | `/health` | Redis and Celery status; 503 when unhealthy (see [Health](#health)) |
| GET | `/health/live` | Liveness: 200 while the process runs |

`scan_id` must be a UUID. The interactive documentation (`/docs`, `/redoc`,
`/openapi.json`) is served only when `ENVIRONMENT` is `development`, on the
service port and not through the gateway; `DEBUG` does not change it.

### Start a scan

**POST** `/api/v1/scans`

```json
{
  "provider": "aws",
  "credentials": {
    "auth_method": "access_key",
    "access_key_id": "AKIA...",
    "secret_access_key": "...",
    "region": "us-east-1"
  },
  "account_id": "123456789012",
  "account_name": "Production Account",
  "regions": ["us-east-1", "us-west-2"],
  "check_ids": null,
  "metadata": {}
}
```

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "started",
  "provider": "aws",
  "account_id": "123456789012",
  "started_at": "2026-10-03T10:30:00",
  "estimated_duration_minutes": 15
}
```

`estimated_duration_minutes` is a fixed heuristic from the provider and the
number of regions and checks, not a measurement.

### Scan status

**GET** `/api/v1/scans/{scan_id}`

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "running",
  "provider": "aws",
  "account_id": "123456789012",
  "started_at": "2026-10-03T10:30:00",
  "completed_at": null,
  "progress": {
    "current_status": "initializing",
    "total_checks": null,
    "completed_checks": null,
    "current_region": null
  }
}
```

`status` is `queued`, `running`, `completed`, `failed` or `cancelled`
(`unknown` for a task state the route does not map). `progress` is set only
while the scan runs: `current_status` is `running` or `initializing`, and
the worker reports no counts, so the other three fields are always `null`.
`completed_at` is set only once the scan completed.

### Scan report

**GET** `/api/v1/scans/{scan_id}/report`

The report the worker stored when the scan completed, kept for
`CSPM_REPORT_RETENTION_DAYS`. A scan that has not completed answers 400.
The report carries `scan_id`, `provider`, `account_id`, `account_name`,
`regions`, `started_at`, `completed_at`, `status`, the counts
`total_checks`, `passed_checks`, `failed_checks`, `error_checks`,
`skipped_checks`, `not_implemented_checks`, the failed findings by severity
(`critical_findings` to `info_findings`), `compliance_score` and `results`.
Each result looks like this:

```json
{
  "check_id": "AWS_S3_001",
  "resource_id": "my-public-bucket",
  "resource_type": "S3Bucket",
  "resource_name": null,
  "region": "us-east-1",
  "status": "failed",
  "message": "S3 bucket is publicly accessible",
  "details": {},
  "remediation": "Configure S3 bucket to block public access",
  "compliance_frameworks": ["CIS AWS Foundations Benchmark v1.4.0 - 2.1.5", "SOC 2"],
  "timestamp": "2026-10-03T10:41:12"
}
```

### Dashboard summary

**GET** `/api/v1/dashboard/summary?days=30`

`total_scans` and `last_scan_at` count the scans the team started that are
still kept (`CSPM_REPORT_RETENTION_DAYS`, 90 days by default; see
[Scan retention and Redis memory](#scan-retention-and-redis-memory)). Every
other figure comes from the newest completed scan
of each of the team's accounts in the period, the reports
`/api/v1/compliance/summary` reads; a failed check's severity is the one its
check declares. With no completed scan the counts are 0 and
`compliance_score` is `null`: nothing was assessed, which is not 0%.

```json
{
  "total_scans": 3,
  "last_scan_at": "2026-10-03T08:12:44.120391",
  "summary_period_days": 30,
  "accounts_assessed": 2,
  "compliance_score": 71.4,
  "total_findings": 6,
  "critical_findings": 1,
  "high_findings": 2,
  "medium_findings": 2,
  "low_findings": 1,
  "info_findings": 0,
  "unknown_severity_findings": 0
}
```

### Batch scans

**POST** `/api/v1/batch/scans`

```json
{
  "scans": [
    {
      "provider": "aws",
      "credentials": {"auth_method": "access_key", "access_key_id": "...", "secret_access_key": "..."},
      "account_id": "111111111111",
      "regions": ["us-east-1"]
    },
    {
      "provider": "aws",
      "credentials": {"auth_method": "access_key", "access_key_id": "...", "secret_access_key": "..."},
      "account_id": "222222222222",
      "regions": ["us-west-2"]
    }
  ]
}
```

Each scan of a batch is started exactly as `POST /api/v1/scans` starts one:
its credentials are encrypted, and its metadata and team index entry are
written, so it counts in the team's summaries and is read by id like any
other scan. The team is always the caller's; a `team_id` in a scan's
`metadata` is ignored. The request also accepts `parallel_execution_limit`,
which is not used: every scan is queued at once and the workers'
concurrency decides how many run together.

A scan the task queue does not take, single or in a batch, is answered 503
and is not recorded: its credentials, its metadata and its index entry are
removed, where it used to read `queued` until its retention ended. A batch
is queued whole or not at all: the scans after the one that failed are not
tried, and the ones queued before it are withdrawn (records and credentials
removed, tasks revoked), so none of them runs. Until 0.12.2 they stayed
queued and ran, under ids the 503 did not give. If the store does not
answer that removal either, the 503 lists the scans still queued in
`error.details.queued_scans`.

### Supported providers

**GET** `/api/v1/providers`

The providers a scan can be submitted for, from the registry described in
[Providers](#providers); `checks` is the number of checks a scan runs when
it names no `check_ids`. Through the gateway it is
`/api/v1/cspm/providers`, with the same authentication as every other cspm
route.

```json
{
  "providers": [
    { "provider": "aws", "name": "Amazon Web Services", "checks": 22 }
  ]
}
```

A scan, single or in a batch, that names another provider is refused with
400:

```json
{
  "error": {
    "code": 400,
    "message": "Unsupported provider: gcp. Supported providers: aws.",
    "type": "HTTPException",
    "request_id": "6f1c2d..."
  }
}
```

Every error has this body, the one all Wildbox FastAPI services share
(`open_security_shared.errors`): `error.code` is the HTTP status and
`error.message` a sentence. A request that did not come through the gateway
also carries the reason as data, in `error.details.code`
(`GATEWAY_AUTH_REQUIRED`, `GATEWAY_SECRET_REQUIRED`,
`INVALID_GATEWAY_HEADERS`).

### Check catalog

**GET** `/api/v1/checks`

Every loaded check with what it declares: `check_id`, `title`,
`description`, `provider`, `service`, `category`, `severity`,
`compliance_frameworks`, `references`, `remediation` and `enabled`, with
`total_checks` and the `providers` and `categories` of the checks listed,
both sorted. `remediation` is the check's own text, the one a result of the
check carries. The filters `provider`, `category` and `severity` compare
without regard to case; a value that matches no check, such as
`provider=gcp`, gives an empty list.

A category has one spelling in the catalog, written with `and`
(`Logging and Monitoring`, `Identity and Access Management`); a unit test
fails when two categories differ only by `&` for `and`, case or spacing.
The `category` filter takes either: `Logging & Monitoring`, the spelling two
of the three CloudTrail checks had up to 0.12.0, still finds all three.
The five checks of the IAM service are one category,
`Identity and Access Management`; until 0.12.2 two of them were in a
category of their own, `Access Management`, a name the filter still takes
and answers with all five. `Access Control` (the policy of a KMS key, an S3
bucket or a Lambda function) is a different category and stays.

### Compliance report of one scan

**GET** `/api/v1/scans/{scan_id}/compliance`

```json
{
  "scan_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "account_id": "123456789012",
  "generated_at": "2026-10-03T10:45:02.118204",
  "frameworks": [
    {
      "framework": "SOC 2",
      "total_checks": 4,
      "passed_checks": 1,
      "failed_checks": 2,
      "compliance_percentage": 33.33333333333333
    }
  ],
  "overall_score": 33.33333333333333,
  "recommendations": ["Configure S3 bucket to block public access"]
}
```

One entry per framework the scan's results are tagged with, or only the one
named by `framework`. `total_checks` counts every result tagged with the
framework, whatever its status, as `summary.compliance_frameworks` in the
report does, so `passed_checks` and `failed_checks` add up to less when a
check errored. The two percentages are over the results with a verdict
(`passed_checks` and `failed_checks`), as the report's `compliance_score`
is, and `0` when there is none; up to 0.12.0 they were over `total_checks`,
so a check that errored or was skipped lowered them as a failed one does.
`generated_at` is UTC without an offset, like every other
time in these answers. A scan that has not completed answers as the report
route does.

### Cancel a scan

**DELETE** `/api/v1/scans/{scan_id}`

Revokes the task of a scan that is `queued` or `running`, terminating it if
a worker is running it, and records the scan as `cancelled`:

```json
{ "message": "Scan cancelled successfully" }
```

A scan that already completed, failed or was cancelled answers 409
(`Scan is already completed and cannot be cancelled`) and is left as it is:
its status, its times and its report. So does one the worker finished while
the cancellation was on its way (`Scan finished before it could be
cancelled`).

A cancelled scan is not run, whether or not the revocation reached a
worker: Celery keeps revocations in the memory of the workers that were up,
so the worker reads the scan's stored status before it opens a session, and
the route deletes the scan's encrypted credentials from Redis.

A scan ends once. The cancellation, the worker's completion and its failure
each read the scan's status and write the new one in one Redis transaction
(`WATCH`/`MULTI`, `_end_scan` in `app/scan_store.py`): of two that cross,
the first to write decides and the other changes nothing. A scan cancelled
while a worker ran it stays `cancelled` when the worker reaches the end all
the same, and its report is not stored; a completed scan's report and
status are written together.

### Health

`GET /health` answers with the status code what its body says, for the
probes that read only the code (`curl -f` in the Compose health check,
`make health`):

| `status` | Code | When |
| --- | --- | --- |
| `healthy` | 200 | Redis answers and a worker does |
| `degraded` | 200 | Redis answers and no worker does: the API reads and queues, scans wait. `checks.celery` is `unhealthy` |
| `unhealthy` | 503 | Redis cannot be reached (`checks.redis` is `unhealthy`; the workers are not asked, and `checks.celery` is `unknown`), or the check itself failed |

```json
{
  "status": "healthy",
  "timestamp": "2026-10-03T10:30:00.670356",
  "version": "0.1.6",
  "uptime_seconds": 3600.3,
  "checks": { "redis": "healthy", "celery": "healthy", "api": "healthy" }
}
```

`degraded` stays 200 on purpose: the worker is another container with its
own health check, and the API container must not read unhealthy while its
worker starts or restarts. Compose marks an unhealthy container and does
not restart it; no service waits for cspm to be healthy.

The workers are given a second to reply, on every probe. The route waits
for Redis and for them in a thread, so the service answers its other
requests in the meantime, and until a deadline of 4 seconds
(`HEALTH_DEADLINE_SECONDS` in `app/main.py`), inside the 5 seconds
`make health` waits and the 10 of the Compose health check: a check that
has not answered by then is `unhealthy` in `checks`.

### When Redis cannot be reached

Every route that reads or writes Redis, and every scan the broker cannot
take, answers 503 in the error body above, with the message
`Scan store or task queue temporarily unavailable`. The cause is in the
service's log. `GET /api/v1/providers` and `GET /api/v1/checks` read nothing
from Redis and answer as usual.

A Redis that is down refuses the connection and the 503 is immediate. One
that accepts it and then sends nothing (a paused container, a host that
stopped) used to hold the route, and the whole API with it, for as long as
the caller waited. The API now gives each of its three clients (the scan
store, the Celery broker and the result backend) 2 seconds to open a
connection and 3 for each reply (`app/connections.py`), and opens a
connection that failed once, not three or twenty times. Measured with a
server that accepts and never answers: every route and `/health` answer 503
in 3 seconds; with the store answering and the queue not, `POST
/api/v1/scans` in 6. `socket_timeout` and `socket_connect_timeout` in the
query string of `REDIS_URL` or `CELERY_RESULT_BACKEND` replace the two
limits of that client. The worker keeps Celery's own waits for its broker
and its result backend.

The worker's own scan store client has the same two limits (until 0.12.2 it
had none: a Redis that never answered held a scan's task without end, at its
first read or at its last write, with the account already scanned). A limit
can fail the write that ends a scan, so that write is made up to four times,
1, 3 and 9 seconds apart, and the worker logs each attempt that fails:
`Scan <id>: its report could not be written, attempt 2 of 4 (TimeoutError):
trying again in 3 seconds`. When the report cannot be stored the scan ends
as `failed`, with `"failure_reason": "report_not_stored"` in its record. When
Redis stays away for those four attempts as well (25 seconds at most for
each write), the worker goes on to its next task and logs `Scan <id> failed
and could not be marked failed`: the scan keeps the status it had, and its
record expires with `CSPM_REPORT_RETENTION_DAYS` like any other.

The routes that ask Redis or the queue are plain functions, which FastAPI
runs in threads: requests that wait do so side by side, and `/health/live`,
`GET /api/v1/providers` and `GET /api/v1/checks`, which ask nothing, answer
from the event loop meanwhile. Until 0.12.2 every route made its Redis call
in the event loop, so one waiting request held all the others: with five
waiting, `/health/live` answered after 15 seconds instead of at once.

## Configuration

Settings are read from the environment (`app/config.py`); the root
`docker-compose.yml` sets the ones marked "stack".

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | none | Required, at least 32 characters; the service does not start without it. Stack: from `CSPM_SECRET_KEY` |
| `CSPM_CREDENTIAL_KEY` | falls back to `SECRET_KEY` | Encrypts cloud credentials in Redis. Required by the stack |
| `GATEWAY_INTERNAL_SECRET` | none | Required; verifies that requests come from the gateway |
| `REDIS_URL` | `redis://localhost:6379/0` | Scan metadata, indexes and reports. Stack: database 3 |
| `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Celery. Stack: database 3 |
| `HOST`, `PORT`, `WORKERS` | `0.0.0.0`, `8019`, `4` | Used only by `python -m app.main`; the image runs `uvicorn` on port 8019 |
| `MAX_CONCURRENT_SCANS` | `5` | Check executions run at once within one scan |
| `SCAN_TIMEOUT_SECONDS` | `3600` | Time limit of one scan, 120 to 86400; the API and the worker refuse to start otherwise. Stack: from `CSPM_SCAN_TIMEOUT_SECONDS` |
| `CSPM_REPORT_RETENTION_DAYS` | `90` | Days a scan's metadata, index entry and report are kept, 1 to 3650; the API and the worker refuse to start otherwise |
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed origins, as a JSON list |
| `DEBUG` | `false` | Auto-reload and a single worker when the module is run directly (`python -m app.main`) |
| `LOG_LEVEL` | `INFO` | Log level |
| `ENVIRONMENT` | none | `/docs`, `/redoc` and `/openapi.json` are served only when it is `development`; unset or empty is not. Required by the stack |

The `docker-compose.yml` in this directory is for standalone development.
It does not set `GATEWAY_INTERNAL_SECRET` or `CSPM_CREDENTIAL_KEY`, so use
the root stack to run scans end to end.

### The scan worker

The API runs no scan itself. `POST /api/v1/scans` and each scan of
`POST /api/v1/batch/scans` encrypt the credentials into Redis for five
minutes, write the scan's metadata and queue a Celery task, and a worker
runs it. In the Wildbox stack that worker is the `cspm-worker` service in
`docker-compose.yml`, built from this directory like `cspm`. Until it
existed every scan stayed `queued` and the compliance pages, the overview
and the reports had no data (#601).

| | |
| --- | --- |
| Command | `celery -A app.worker:celery_app worker --concurrency=2 -Q celery` |
| Queue | `celery`, Redis database 3 (`CELERY_BROKER_URL`). Every task (`run_cspm_scan`, `get_available_checks`, `health_check`) is routed there by `TASK_QUEUES` in `app/worker.py`; a unit test checks that the service's `-Q` lists exactly those queues |
| Settings | the API's: `SECRET_KEY`, `CSPM_CREDENTIAL_KEY` (it decrypts the credentials), `REDIS_URL`, `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND` with the Redis password, `CSPM_REPORT_RETENTION_DAYS` (it writes the reports) and `SCAN_TIMEOUT_SECONDS` |
| Health check | `celery inspect ping` against its own node name |
| Stop | `stop_grace_period` equals the scan time limit, so a stop lets running scans finish |
| Networks (production) | `data` for Redis and `egress` for the cloud provider APIs |

A scan reads `queued` until a worker takes it, `running` while it runs, and
then `completed`, with its report stored as described below, or `failed`.
It fails when its credentials expired before a worker took it (five minutes
after it was queued), when no session can be opened with them, or when it
exceeds its time limit. The session factory refuses AWS credentials that
cannot be valid, such as an access key id that is not 16 to 128 letters,
digits or underscores, or `assume_role` without an IAM role ARN, before it
creates any boto3 session, so such a scan fails without a request to AWS.
Well-formed keys are only checked by the calls the checks make, so a scan
with keys AWS rejects completes, with the rejected calls recorded by the
checks. GCP and Azure scans are refused when they are submitted (see
[Providers](#providers)); one queued by an earlier release fails when the
worker takes it.

**Time limit.** `CSPM_SCAN_TIMEOUT_SECONDS` in `.env` (default 3600, from
120 to 86400) is passed to both services as `SCAN_TIMEOUT_SECONDS`. The
worker stops a scan after that long (the soft limit, a minute earlier, lets
it fail cleanly) and is given that long to stop, so `docker compose stop`
or `down` can wait that long while a scan runs. Tasks are acknowledged when
they finish, and Redis gives an unacknowledged task to another worker ten
minutes after the time limit, so a scan is never run twice; a worker killed
mid-scan has its scan delivered again then, and it fails because its
credentials were deleted when it started.

**Concurrency and scaling.** Each worker process runs one scan at a time
and takes the next only when it is done (`worker_prefetch_multiplier=1`),
so `--concurrency` is the number of scans one container runs at once. The
default is two processes in one CPU and 1 GB. A scan spends most of its time waiting for the
provider's API. Scans that wait in the queue are the sign to add capacity:

- **One worker, higher concurrency.** Raise `--concurrency` and the
  container's CPU and memory limits with it, after measuring a worker's
  memory under your own scans (`docker stats`). Simplest; every scan still
  shares one container's limits.
- **Several workers.** `docker compose up -d --scale cspm-worker=3`. The
  service has no fixed container name, every replica consumes the same
  queue and Redis hands each scan to exactly one of them. Use this to
  spread scans over CPUs or hosts, or to keep scanning while one worker
  restarts.

More concurrent scans of one cloud account also mean more calls to its API
at once, and providers throttle API calls per account. The API only queues
scans and reads Redis, so more API capacity does not run more scans.

### Scan retention and Redis memory

When a scan completes, the worker stores its report in Redis under the scan
(`scan:{id}:report`) and marks the scan's metadata (`scan:{id}:metadata`)
completed. Both, and the scan's entry in its team's index
(`cspm:team:{team}:scan_index`, a sorted set scored by expiry), are kept for
`CSPM_REPORT_RETENTION_DAYS` days (90 by default) from the last time the scan
was written: when it started, completed, failed or was cancelled. Expired
index entries are pruned whenever the index is read or written.
`GET /api/v1/scans/{id}/report`, `/api/v1/compliance/summary`,
`/api/v1/compliance/findings` and `/api/v1/dashboard/summary` read reports
from there and nowhere else.

Before this, reports were read from the Celery result backend, whose default
expiry is one day: the compliance pages lost every scan older than a day. The
worker now sets `result_expires` explicitly to twice `SCAN_TIMEOUT_SECONDS`
(two hours by default). The backend only reports the state of queued and
running scans; a finished scan's status comes from its metadata.

Reports are stored as zlib-compressed JSON (base64-encoded). As JSON a report
takes about 720 bytes per check result; stored, synthetic reports of 500 to
10,000 results took 40 to 70 bytes per result. Real reports vary with their
resource names and details, so plan for 100 bytes per result:

```text
memory ≈ results per scan × 100 bytes × scans per day × retention days
```

For example, 10 accounts scanned daily with 2,000 results each is about
2 MB a day, 180 MB at 90 days. The scan metadata and index add well under a
kilobyte per scan.

Redis is shared with every other service and runs with
`--maxmemory-policy noeviction` and `--maxmemory ${REDIS_MAXMEMORY:-1gb}`: when
it is full it refuses writes, for logins and task queues as well as for scans,
rather than dropping keys. Check the memory in use with
`scripts/check_redis_config.py runtime`. If reports would take a sizeable part
of `REDIS_MAXMEMORY`, lower `CSPM_REPORT_RETENTION_DAYS` or raise
`REDIS_MAXMEMORY`, keeping `REDIS_MEMORY_LIMIT` at least twice
`REDIS_MAXMEMORY`.

## Adding a check

The check runner imports every module under `app/checks/<provider>/` and
registers each `BaseCheck` subclass it finds. A check declares its metadata
and returns one result per resource:

```python
from typing import Any, List, Optional

from ...framework import (
    BaseCheck, CheckMetadata, CheckResult, CheckSeverity, CheckStatus, CloudProvider,
)


class CheckExample(BaseCheck):
    def get_metadata(self) -> CheckMetadata:
        return CheckMetadata(
            check_id="AWS_EXAMPLE_001",
            title="Example check",
            description="What the check verifies",
            provider=CloudProvider.AWS,
            service="Example",
            category="Example",
            severity=CheckSeverity.MEDIUM,
            compliance_frameworks=["AWS Security Best Practices"],
            remediation="How to fix a failed resource",
        )

    async def execute(self, session: Any, region: Optional[str] = None) -> List[CheckResult]:
        # session is the boto3 session of the scan
        return [
            self.create_result(
                resource_id="resource-id",
                resource_type="ExampleResource",
                status=CheckStatus.PASSED,
                message="Resource meets the requirement",
                region=region,
            )
        ]
```

Place it in a package under `app/checks/aws/<service>/` with an
`__init__.py`. A check must call the cloud API; scaffolding is marked
`implemented=False` in its metadata and is not loaded.

## Development

The image's lock holds no test tool. Install the runner on top of it, at
the versions the unit-test job uses:

```bash
pip install -r requirements.txt
pip install pytest==9.1.1 pytest-cov==7.1.0 pytest-asyncio==1.4.0
pytest tests/unit/
```

The tests that need a Redis server start a throwaway container and are
skipped where Docker is not running; `WILDBOX_REQUIRE_DOCKER_TESTS=1`, which
CI sets, makes that a failure. `requirements-dev.txt` adds the linters; plain
`pip install -r` refuses it, because `requirements.txt` is hash-pinned and
its own pins are not: use `uv pip install -r requirements-dev.txt`.

## License

Part of the Wildbox platform; see the repository [LICENSE](../LICENSE).
