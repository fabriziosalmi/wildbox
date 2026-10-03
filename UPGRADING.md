# Upgrading

This file records changes that an **existing deployment** has to act on. A fresh
install needs none of it: `make generate-secrets` and the
[Quick Start](https://www.wildbox.io/guides/quickstart/) cover everything here.

## Upgrading to the next release

Changes on `main` since 0.10.0 that an existing deployment has to know about.
Back up first (`make backup`), then work through the list.

### 1. Rebuild every image (required)

The images are built from the repository, and `docker compose up -d` does not
rebuild an image that already exists. Without a rebuild the stack keeps
running 0.10.0 code. This release changes, among others, the dashboard image
(Next.js 16, React 19, node 24 LTS), the gateway base image and the Python
locks of every service.

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
make start-prod
```

Use the same `-f` files you start the stack with.

### 2. identity now reaches Redis with the password (check overrides)

Redis has required a password since 0.10.0, but identity took its `REDIS_URL`
from `.env`, which has none, so every write to the token blacklist failed and
logout revoked nothing. `docker-compose.yml` now builds identity's URL from
`REDIS_PASSWORD` (database 0), as it does for every other service.

- Nothing to do if you never overrode it.
- To point identity at another Redis, set `IDENTITY_REDIS_URL`, including the
  password. The `REDIS_URL` line in `.env` is no longer what identity uses.

### 3. The gateway has an internal listener on port 8081 (do not publish it)

identity asks the gateway to drop a revoked token from its authorization cache
by calling `http://open-security-gateway:8081/internal/gateway/purge-auth-cache`
on the Compose network. The port is not published, and should not be. If you
run identity or the gateway outside the default Compose network, or set
`GATEWAY_INTERNAL_URL` for identity, make sure identity can reach the
gateway's port 8081.

Logout depends on it. identity answers a logout with success only once the
gateway has confirmed that it refuses the token (#571); if the gateway cannot
be reached, or still runs an older image that does not report revoked
sessions, logout answers 503 and the token stays valid. Rebuild and restart
the gateway together with identity (step 1 does), and with more than one
gateway replica note that identity reaches only the one its URL resolves to.
Deactivating a user or an API key still flushes the cache best effort.

### 4. Sessions issued before the upgrade cannot be revoked one by one

Login tokens now carry a `jti`, which logout revokes. Tokens issued before the
upgrade have none: logging out with one answers 400 ("Token carries no jti and
cannot be revoked individually"), and it stays valid until it expires, at
most 30 minutes after it was issued. Users who were logged in can simply log
in again after that. To end every session at once instead, rotate
`JWT_SECRET_KEY` with `scripts/rotate_secrets.sh`, which explains what that
invalidates.

### 5. Failed logins now lock the account

After 5 failed password logins for an email, login answers 429 with
`Retry-After: 900` for 15 minutes, even with the right password; a successful
login before that clears the counter. Scripts or monitors that log in with a
stale password will lock their account. The lock and how to lift it early are
described in
[Authentication and sessions](https://www.wildbox.io/guides/authentication/#failed-login-lockout).

### 6. identity's API documentation is off in production

With `ENVIRONMENT=production` (what `make generate-secrets` writes), identity
no longer serves `/docs`, `/redoc` or `/openapi.json`; they answer 404. Anything
that read identity's OpenAPI schema from a production stack has to read it
from a development one.

### 7. guardian moves to Django 5.2 (one migration, applied at start)

guardian runs Django 5.2 LTS and django-celery-beat 2.8.1. Its container
applies migrations when it starts, which on this upgrade includes
`django_celery_beat.0019`. Watch `docker compose logs guardian` on the first
start.

### 8. Custom responder playbooks must use only known keys

The playbook models now reject unknown keys instead of ignoring them, and the
responder refuses to start if any playbook fails to load ("Failed to load N
playbooks", naming the file and key). Before upgrading, check your own
playbooks in `open-security-responder/playbooks/`:

- step arguments go under `input:`, not `params:`;
- `retry_count` is gone (it was never honoured);
- a top-level `output:` block is not accepted;
- `on_failure: continue` is now honoured: the run records the failure and
  goes on to the next step.

### 9. Scans verify TLS certificates

The security tools now verify certificate chains and host names. A scan of a
host with a self-signed, expired or mismatched certificate returns
`success: false` with the reason instead of results. That is the intended
behavior; fix the certificate. A per-scan `verify_ssl: false` input exists,
but a scan run with it reports content from whoever answered the connection.

### 10. The production overlay segments the networks (Compose 2.24.4+)

`docker-compose.prod.yml` now replaces each service's networks instead of
adding to the flat `wildbox` network: only the gateway and the dashboard share
`frontend`, PostgreSQL and Redis sit on the internal `data` network with the
services that use them, and the dashboard can no longer reach them. The map
is at the top of the file.

- The `!override` tag it uses needs Docker Compose 2.24.4 or later; older
  versions refuse the file. `make start-prod` now calls `docker compose`.
- A service you added in your own overlay on the `wildbox` network no longer
  shares it with the production services; attach it to the network it needs.
- identity no longer receives `CORS_ORIGINS` under the production overlay
  (the comma-separated value made it exit at start-up); it keeps its built-in
  origins, and browsers reach it through the gateway.
- To check a host: `python3 scripts/check_network_segmentation.py config`.

### 11. Files and settings that are gone

- `open-security-tools/requirements-secure.txt` is deleted; nothing in the
  repository installed it. Install from the service's hash-pinned
  `requirements.txt`.
- For forks that run CI: Dependabot no longer opens pip pull requests. The
  weekly `Pip Security Upgrades` workflow does, using a GitHub App token when
  `DEPS_APP_CLIENT_ID` and `DEPS_APP_PRIVATE_KEY` are set and `GITHUB_TOKEN`
  otherwise; the `DEPS_PR_TOKEN` option is removed.
- For forks that customize the dashboard: Next.js 16 renamed
  `src/middleware.ts` to `src/proxy.ts`, and `images.domains` is now
  `images.remotePatterns`.
- guardian's `apps.vulnerabilities.tasks.generate_vulnerability_reports` is
  gone: it did nothing, and nothing called or scheduled it. Reports, the
  vulnerability summary included, come from report templates
  (`POST /api/v1/reports/templates/{id}/generate/`). If you added a periodic
  task for it in the Django admin, delete that row, or the worker logs an
  unregistered task each time beat sends it.
- The blue/green experiment is removed: `docker-compose.blue-green.yml`,
  `haproxy/`, the `blue_green_*.sh` scripts under `scripts/shell-scripts/`
  and the `Blue-Green guardian tasks` workflow. It could not complete a
  deployment for any service (#552): HAProxy routed to services the file did
  not define, the traffic switch rewrote the config into an invalid one, and
  the deploy script called a smoke-test script that did not exist. Nothing
  in `docker-compose.yml` or `docker-compose.prod.yml` used it. If you kept a
  copy, it is not maintained; deploy with `docker-compose.prod.yml` as the
  [deployment guide](https://www.wildbox.io/guides/deployment/) describes.
- The tools service no longer accepts its static `API_KEY` sent directly as
  `X-API-Key` (#565). That path already failed with a server error on every
  call, so nothing that worked before stops working. If a script or
  integration calls the tools service directly on port 8000 with
  `X-API-Key`, send it through the gateway instead
  (`https://<host>/api/v1/tools/...`) with a JWT or a personal API key
  created in the identity service; a direct request without the gateway's
  headers is answered with 401. Keep `API_KEY` in `.env`: the service still
  requires it at start-up.
- identity's `POST /api/v1/admin/teams/{team_id}/invite` is removed (#570)
  and answers 404. It returned "Invitation sent successfully" without
  storing or sending anything, so a script that called it never invited
  anyone; drop the call.
- identity's admin analytics no longer report estimated request counts
  (#570): `summary.api_requests_today` is gone from
  `GET /api/v1/analytics/admin/usage-summary`, and
  `api_usage.estimated_requests_today` and
  `api_usage.estimated_requests_week` from
  `GET /api/v1/analytics/admin/system-stats`. They were API keys used
  times a constant, not counts. A script that reads them must stop; the
  number of keys used in the last day is still there
  (`summary.api_keys_active`, `api_usage.keys_used_today`).
- The gateway's `/api/tools/` alias is removed (#567) and answers 404. It
  served the tools API beside `/api/v1/tools/` with `Deprecation` and
  `Sunset: Wed, 01 Jul 2026` headers. A script that still calls
  `https://<host>/api/tools/...` must call `https://<host>/api/v1/tools/...`;
  nothing else changes in the request or the answer.
- The tools service's standalone web UI is removed (#581). The gateway
  answers `https://<host>/tools/...` with 404, and the service no longer
  serves `/`, `/settings`, `/guide`, `/docs`, `/redoc` or `/static/` on
  port 8000; `/openapi.json` and `/health` stay. Browse the tools on the
  dashboard's `/toolbox` page and run them with
  `POST https://<host>/api/v1/tools/<name>`. Update bookmarks. The gateway
  also stops accepting the `auth_token` cookie in place of an
  `Authorization` header: a client that sent only the cookie to
  `/api/v1/...` must send `Authorization: Bearer <token>`, as the dashboard
  does.
- The agents service no longer reads `INTERNAL_API_KEY` (#567), and
  `docker-compose.yml` no longer passes it. It was a fallback the agents
  client sent as `X-API-Key` when it had no caller identity, which the tools
  service has refused since #566. Remove it from overrides if you like; a
  `.env` file that still sets it loads. The agents service needs
  `GATEWAY_INTERNAL_SECRET` (`docker-compose.yml` passes it): without it,
  every tool call of an analysis fails with `CallerIdentityUnavailable`
  instead of a 401 from the tools service.

- cspm's `GET /api/v1/compliance/summary` and `GET /api/v1/compliance/findings`
  now report the team's completed scans (#572); both returned the same
  invented account to everyone. In the summary, `trend` is gone, each
  framework's `version` and `description` are gone, and
  `total_controls` / `passed_controls` / `failed_controls` are now
  `total_checks` / `passed_checks` / `failed_checks` (they always counted
  check results); `overall_score` and `last_updated` are null when no scan
  completed in the period, and `scans_considered` is new. A finding now
  carries `scan_id`, `check_id`, `title` and a `frameworks` list instead of
  `framework`, `control_id` and `control_title`, and `severity` is null
  when the check is unknown. A script that read the old fields must move
  to the new ones.
- cspm's `GET /api/v1/dashboard/executive-summary` and
  `GET /api/v1/scans/{scan_id}/remediation-roadmap` are removed (#578) and
  answer 404. They read `scan:{id}:results`, which nothing writes, so the
  first reported zeros after any scan and the second was 404 for every
  scan already. Read `GET /api/v1/dashboard/summary` for the figures and
  `GET /api/v1/compliance/findings?status=failed` for the failed checks,
  their severity and remediation.
- cspm's `GET /api/v1/dashboard/summary` (#578) no longer has
  `active_scans`, `completed_scans` or `failed_scans`: they came from a
  status that never changed after a scan started, so every scan was
  "active". Its findings, severity counts and `compliance_score` now come
  from the newest completed scan of each account in the period (new
  `days` query parameter, default 30, echoed as `summary_period_days`), as
  `/api/v1/compliance/summary` computes them; they used to be 0 whatever
  had been scanned. `compliance_score` is null when no scan completed in
  the period. `accounts_assessed`, `info_findings` and
  `unknown_severity_findings` are new. A script that read the removed
  fields must stop, and one that reads `compliance_score` must accept
  null.
- Nine n8n workflows are removed from `open-security-automations/workflows`
  (#592). None of them could run: each called endpoints that do not exist,
  or called a service directly, which the services refuse since #566.

  | Workflow (file) | Why it could not run |
  | --------------- | -------------------- |
  | Security Compliance Automation (`compliance/daily_compliance_check.json`) | called cspm directly under a host name that does not exist; read `compliance_score`, which the summary does not have; posted to `/api/v1/alerts` on a gateway host and port that do not exist, and to cspm's `/api/v1/remediation/auto-fix`, which does not exist |
  | Daily OSINT Report (`intelligence/daily_report.json`) | `/api/data/v1/feeds/rss` and `/api/data/v1/reports`: no such gateway prefix or data endpoint; `/api/agents/v1/analyze`: wrong prefix, and the agents service analyzes an IOC, not free text |
  | Honeypot Alert Classifier (`intelligence/honeypot_classifier.json`) | the same agents call; data `logs/enrich`, `logs/archive` and `iocs`, responder `incidents` and guardian `block-ip` do not exist; it sent Redis commands over HTTP |
  | Threat Intelligence Feed Aggregator (`intelligence/threat_feed_aggregator.json`) | tools `threat-intelligence/indicators/bulk`, guardian `alerts` (on identity's port) and data `threat-intelligence/feed-status` do not exist |
  | Vulnerability Sync and Enrichment (`intelligence/vulnerability_sync.json`) | tools `vulnerabilities/bulk`, cspm `vulnerabilities/scan-trigger`, data `reports/vulnerability` and guardian `alerts` do not exist |
  | CSPM Alert Processor (`monitoring/csmp_alert_processor.json`) | nothing sends to its webhook; guardian `threats`, tools `compliance/findings` and `tickets`, responder `automation/remediate` do not exist |
  | Security Incident Response Orchestrator (`support/incident_response_orchestrator.json`) | tools `alerts`, guardian `incidents` and data `incidents` do not exist |
  | Support Ticket Triage (`support/triage.json`) | the agents call above; data `tickets` and `search/documentation` do not exist |
  | Threat Intelligence Enrichment (`threat-intelligence/ip_enrichment_workflow.json`) | its trigger was a webhook node pointed at the sensor, which has no gateway route; responder `incidents` and `response/isolate` do not exist |

  If you imported one of them into n8n, delete it there: it fails on every
  run. The Executive Security Dashboard workflow stays, rewritten to read
  cspm's `dashboard/summary`, `compliance/summary` and `compliance/findings`
  through the gateway; re-import it with
  `open-security-automations/scripts/import_workflows.sh` and set the
  variables its README lists (`AUTOMATIONS_WILDBOX_API_KEY`,
  `SLACK_WEBHOOK_URL`, `EXECUTIVE_REPORT_EMAIL_FROM`,
  `EXECUTIVE_REPORT_EMAIL_TO`). The import and export scripts now use the
  n8n CLI in the container instead of the REST API with basic auth, which
  n8n 1.x refuses.

### 12. guardian has a Celery worker (`guardian-worker`)

A new service, `guardian-worker`, runs the tasks guardian queues: port scans of
new assets, threat-intel enrichment, alert-rule checks, report generation and
compliance notifications. Before, nothing ran them. It uses guardian's image,
so it is built with the others, and in the production overlay it sits on
`data` and `egress`.

Every task queued since guardian was deployed is still in Redis and runs as
soon as the worker starts, including e-mails and port scans that are now out
of date. To drop that backlog first, run, with the old stack still up:

```bash
docker compose exec guardian celery -A guardian purge -f
```

Its periodic tasks are scheduled by `guardian-beat`, below.

### 13. guardian schedules its periodic tasks (`guardian-beat`, one instance)

guardian's periodic tasks (SLA check, alert rules, risk-score recalculation,
cleanup of expired reports and old history, asset inventory, compliance
reminders) were never scheduled, so none of them ran. A new service,
`guardian-beat`, sends them to `guardian-worker` on the schedule in
`open-security-guardian/guardian/schedule.py`. It uses guardian's image and,
in the production overlay, sits on `data` alone.

- **Run exactly one.** A second `guardian-beat` would send every task twice.
  The service has a fixed container name, so scaling it fails; do not run
  another beat for guardian elsewhere.
- **Expect the first runs.** Within 15 minutes of the upgrade the SLA check
  e-mails the assignee of every vulnerability already past its due date (once
  per vulnerability per 24 hours), and every active alert rule whose
  condition holds notifies. The first nightly runs mark assets not seen for
  30 days inactive, delete reports past their expiry and vulnerability
  history older than a year, and the first 08:00 run reminds about every
  overdue compliance assessment. To hold any of them back, set its variable
  to `off` before starting the stack.
- **Change an interval with its variable**, not in the Django admin: every
  `GUARDIAN_SCHEDULE_*` value (seconds, five crontab fields in UTC, or `off`)
  is written over the admin's value each time `guardian-beat` starts. The
  defaults and the reasons for them are in the
  [deployment guide](https://www.wildbox.io/guides/deployment/#guardians-scheduled-tasks).
- Tasks now go to the queue meant for them (`scanning`, `reporting`,
  `analytics`, `default`) instead of all to `default`, and `guardian-worker`
  no longer listens on `queue_management`, a queue no task ever used. If you
  run your own guardian workers, give them the same `-Q` list as
  `guardian-worker` in `docker-compose.yml`.
- `GUARDIAN_BASE_URL` (optional) prefixes the vulnerability link in the SLA
  and assignment e-mails.

### 14. guardian's alert rules measure real data and stop repeating themselves

Every alert rule was evaluated against 0, whatever it named, and a rule that
fired notified on every sweep. Rules now compute the metric they name, and
notify when they start firing, when they recover, and in between at most once
a day. A migration (`reporting.0002_alert_rule_state`) adds the rule's state
and a notification log; `guardian` applies it when it starts.

- **Check your rules.** A rule whose `data_source` is not one of the metrics
  in the [deployment guide](https://www.wildbox.io/guides/deployment/#alert-rules),
  or whose condition is not `threshold`, is no longer evaluated: each sweep
  logs it as an error and it never fires. Edit it to a supported metric (the
  API now refuses anything else). List them with
  `GET /api/v1/guardian/reports/alerts/` and compare `data_source`.
- **Expect one notification per firing rule.** On the first sweep after the
  upgrade (within 15 minutes) every rule whose condition holds starts firing
  and notifies once. The e-mail template was missing, so no alert e-mail was
  ever actually sent before; set `notification_config.recipients` on a rule,
  or `DEFAULT_NOTIFICATION_RECIPIENTS`, for them to reach someone.
- `GUARDIAN_ALERT_RENOTIFY_INTERVAL` (optional, `guardian-worker`): seconds
  between reminders while a rule keeps firing, default 86400, or `off`.
  Anything else stops the container at start-up.
- `trigger_count` and `last_triggered` now count and date the times a rule
  started firing, not every evaluation that found it firing.

### 15. guardian runs the discovery rules and report schedules users define

Asset discovery rules and report schedules were stored and never run. A new
periodic task, sent by `guardian-beat` every minute
(`GUARDIAN_SCHEDULE_USER_SCHEDULES`, optional), now queues each one when it
is due. No migration; the [deployment guide](https://www.wildbox.io/guides/deployment/#schedules-defined-through-the-api)
describes what can be scheduled.

- **Expect the first runs.** An active report schedule whose `next_run` is
  already past runs within a minute of the upgrade, once, and then continues
  from its next run after now. An enabled `network_scan` discovery rule is
  given its next run from its cron `schedule` and runs from then on. To hold
  one back, pause or disable it before starting the stack.
- **What is not run.** Discovery rules of the other types (cloud API, CMDB
  import, agent report, DNS zone transfer) have no implementation; report
  schedules of a report type without data (risk assessment, remediation
  progress, technical details, trend analysis, custom) or in PDF, CSV or Excel
  format would only produce failed or empty reports. Existing ones are left
  alone and logged by every sweep; the API now refuses new ones, and changes
  to existing ones that keep them unsupported. Such a report generated by
  hand now fails with the reason instead. Scan schedules cannot run at
  all: creating, changing, triggering or enabling one answers 400; delete or
  disable the ones you have.
- **A new volume, `guardian_media`**, holds generated reports, shared by
  `guardian-worker`, which writes them, and `guardian`, which serves their
  downloads. Reports generated before the upgrade were never completed, so
  there is nothing to move.
- Scheduled reports are e-mailed to the schedule's `recipients` when they
  are ready, or to `DEFAULT_NOTIFICATION_RECIPIENTS` if it has none.
- A network scan now finds a host by TCP connection on ports 80, 443, 22 and
  3389 (a refused connection counts as up), not by ping, which was not
  installed in the image. A host that answers only ICMP is not found.

### 16. Rebuild the dashboard image; leave `NEXT_PUBLIC_GATEWAY_URL` empty

`NEXT_PUBLIC_*` is compiled into the dashboard's browser code when the image
is built, and the production Dockerfile took no value for it, so a production
dashboard sent every API call to `http://localhost:80` on the user's machine.
The image now takes `NEXT_PUBLIC_GATEWAY_URL`, `NEXT_PUBLIC_USE_GATEWAY` and
`NEXT_PUBLIC_APP_URL` as build arguments, which `docker-compose.prod.yml`
reads from `.env`.

- **Set `NEXT_PUBLIC_GATEWAY_URL=` (empty) in `.env`** unless the dashboard
  is served from another origin than the gateway. Empty means the dashboard's
  own origin, which is where this stack's gateway serves the API. The
  previous template value, `https://localhost`, would now be compiled into
  the image and work only for a browser on the server itself.
- **Rebuild the dashboard image** after this and after any later change to
  these variables: `docker compose -f docker-compose.yml -f
  docker-compose.prod.yml build dashboard`. Setting them on the running
  container has no effect.
- The per-service `NEXT_PUBLIC_*_API_URL` and `NEXT_PUBLIC_API_BASE_URL`
  variables are read by nothing and can be removed from overrides.

See the [deployment guide](https://www.wildbox.io/guides/deployment/#the-dashboards-browser-settings).

### 17. `PATCH /auth/users/me` no longer changes the password

It changed the password without asking for the current one. It now answers
400 (`UPDATE_USER_INVALID_PASSWORD`) to a request with a `password` field and
changes nothing; an email change needs the current password (section 18). A
script that changes a
user's own password must call
`POST /api/v1/identity/admin/me/change-password` with `current_password` and
`new_password` (at least 12 characters). Administrators resetting another
account's password through `PATCH /auth/users/{id}` are not affected.

### 18. Account changes need the current password; a password change ends the other sessions

identity adds one column, `users.tokens_valid_after` (alembic revision
`a6b7c8d9e0f1`), which it applies itself at start (`alembic upgrade head` in
its entrypoint). The column is nullable and is not backfilled.

- **Sessions open at the upgrade stay valid** until they expire, as before.
  The cutoff only exists once an account's password changes.
- **Rebuild and restart identity and the gateway together** (section 1
  does). A password change now asks the gateway to refuse the account's
  earlier sessions and changes the password only once the gateway has
  confirmed. An older gateway, or one identity cannot reach on port 8081
  (section 3), makes every password change answer 503 and change nothing.
  With more than one gateway replica, only the one identity reaches keeps
  the cutoff; the others refuse those sessions once their cached decisions
  expire (`AUTH_CACHE_TTL`).

API changes that clients and scripts have to follow:

- **`POST /api/v1/identity/admin/me/change-password`** (and
  `PUT /api/v1/identity/admin/me/password`) ends every session of the
  account issued up to the change, **including the token the request was
  made with**. The answer now carries a new one:
  `{"message", "access_token", "token_type": "bearer"}`. A client that
  keeps using the old token gets 401; it must switch to the new one or
  log in again. API keys keep working; revoke them on the API keys page if
  they may be compromised. The reset-password flow and an administrator's
  reset (`PATCH /auth/users/{id}`) end the account's sessions the same way.
- **An email change needs `current_password`**, on `PATCH /auth/users/me`
  and on `PATCH /api/v1/identity/admin/me/profile` (and `PUT
  /api/v1/identity/admin/me`). Without it the answer is 400 and nothing
  changes.
- **A wrong current password counts as a failed login** on change-password,
  account deletion and an email change. After 5 (the login lockout's
  limit), those routes and login answer 429 with `Retry-After: 900`, even
  with the right password. Scripts that retry with a stale password will
  lock their account.
- **`/admin/me/profile` and `PUT /admin/me` refuse `new_password`** with 400.
  Use change-password.
- **A superuser changing their own account through
  `PATCH /auth/users/{own id}`** gets the self-service rules: a `password`
  is refused (400 `UPDATE_USER_INVALID_PASSWORD`), an email change needs
  `current_password`.
- **Password-reset tokens issued before the upgrade no longer work**; they
  do not carry the email that new tokens are bound to. Request a new one.
- **Login tokens carry a fractional `iat`** (seconds since the epoch, as a
  JSON number with a fraction). A client that parses the claim as an integer
  has to accept a number.

### 19. Asynchronous tool tasks are read at `/api/v1/tasks`, by their owner only

`POST /api/v1/tools/{name}/async` queued a task, but nothing could read it:
the gateway did not route the task endpoints (#567). They are now
`GET /api/v1/tasks/{task_id}` (status and result),
`DELETE /api/v1/tasks/{task_id}` (cancel) and `GET /api/v1/tasks` (the
caller's tasks of the last day, newest first, `?limit=1..100`), and the
submit response's `status_url` points at the first. Rebuild the tools
service, its worker and the gateway together (section 1 does).

- **A task belongs to the user who submitted it.** Anyone else, a teammate
  or an administrator included, gets 404 for it, the same answer as for an
  id that does not exist; it does not appear in their list. Operators who
  need every task have Flower.
- **Tasks submitted before the upgrade cannot be read**: they have no owner
  record. Their results expire an hour after they finish anyway; submit
  again.
- **An unknown task id answers 404**, not `"status": "pending"` as before.
  A client that polls an id it mistyped now stops at once.
- **API keys with scopes** need `tools:read` to read and list tasks and
  `tools:execute` to cancel one, as for the tools themselves.
- The owner records live in the tools service's Redis database (the one
  `REDIS_URL` names, `2` in `docker-compose.yml`) under
  `wildbox:tools:task-owner:*` and `wildbox:tools:user-tasks:*`, and expire
  after a day. Without Redis the task endpoints answer 503.

### 20. `trends_change` can be null

`GET /api/v1/dashboard/threat-intel` (data) answers `trends_change: null`
when the previous 24 hours had no indicators; it used to report 100.0 (or
0.0 when both periods were empty). A client that reads the field must
accept null. Every other value is unchanged.

### 21. `users.recent_logins` is gone from identity's system statistics

`GET /api/v1/analytics/admin/system-stats` no longer returns
`users.recent_logins`. It counted users whose record changed in the last
day, not logins, and identity has no login count to put in its place. A
script that reads it must stop; the dashboard never did.

### 22. Team admins can create accounts; those accounts change their password first

identity adds one column, `users.must_change_password` (alembic revision
`b7c8d9e0f1a2`), which it applies itself at start. It is `NOT NULL` with a
default of false, so no existing account is affected.

- **New endpoint:** `POST /api/v1/identity/admin/teams/{team_id}/members`
  with `{"email", "password", "role"}` creates a new account in the team
  (no team of its own). Owners and admins of the team, and superusers, may
  call it; the role must be below the caller's (an owner creates `admin`
  or `member`, an admin creates `member`). 409 means the email is already
  registered. No email is sent: give the new member the initial password
  yourself, privately. See the
  [identity API reference](https://www.wildbox.io/api/identity/endpoints/#create-a-member).
- **Accounts created this way must change the initial password** before
  anything else. Until they do, identity answers 403
  `PASSWORD_CHANGE_REQUIRED` to every route except `GET /auth/users/me`,
  change-password and logout, and the gateway answers 403
  `{"error": "PASSWORD_CHANGE_REQUIRED"}` for every other service. A
  script that uses such an account must first call
  `POST /api/v1/identity/admin/me/change-password` and continue with the
  token it returns.
- **Rebuild and restart identity and the gateway together** (section 1
  does). An older gateway ignores `password_change_required` and would let
  such a session use the other services; an older identity never reports
  it.
- `GET /api/v1/identity/admin/me/activity` lists `team_memberships` oldest
  first. Superusers can now list, rename and remove the members of any
  team.

### 23. New passwords must meet the password policy

identity applies one password rule wherever a password is set (#583):
registration, the reset-password flow, change-password, an
administrator's reset through `PATCH /auth/users/{id}`, the accounts a
team administrator creates (section 22) and the creation of the first
administrator. A password must have 12 to 128 characters,
must not contain the account's email address or the part before the `@`,
and must not be one of the 10,000 most common passwords of that length.
There are no composition rules. Rebuild identity (section 1 does).

- **Existing accounts are not affected.** Their passwords keep working
  and are not checked; the rule applies the next time the password is
  set. Nothing is migrated.
- **`INITIAL_ADMIN_PASSWORD` must comply on a fresh install.** identity
  creates the first administrator only when the account does not exist
  yet; if the password is refused, identity now stops at start with the
  reason (it used to log the failure and run without an administrator).
  `scripts/generate_secrets.py` generates a compliant 24-character value.
  An existing administrator is not affected.
- **Scripts that register accounts or set passwords** with short or
  common values (`password1234`, `qwerty123456`) now get 400; registration
  answers `REGISTER_INVALID_PASSWORD`, reset-password
  `RESET_PASSWORD_INVALID_PASSWORD`, an administrator's reset
  `UPDATE_USER_INVALID_PASSWORD`. Use long random values.
- **The error body of these refusals changed.** fastapi-users' detail
  `{"code", "reason"}` used to be stringified into `error.message` as a
  Python dict literal. `error.message` is now the reason, readable as is,
  and `error.details` holds `{"code", "reason"}`. A client that searched
  `error.message` for the code must read `error.details.code`. This
  applies to every service using `open_security_shared.errors`, for any
  HTTP error whose detail is an object with a `reason`.

### 24. cspm keeps scan reports for 90 days (`CSPM_REPORT_RETENTION_DAYS`)

The compliance summary and findings, the dashboard summary and the cloud
security overview are built from the reports of the team's completed
scans. cspm read them from the Celery result backend, which drops results
after a day, so every scan older than that dropped out of those pages. The
worker now stores each report in Redis under its scan, and keeps the
report, the scan's metadata and its entry in the team's scan index for
`CSPM_REPORT_RETENTION_DAYS` days (#591). Rebuild cspm, and its worker if
you run one (section 1 does).

- **New variable, optional.** `CSPM_REPORT_RETENTION_DAYS` defaults to
  90; `docker-compose.yml` passes it to cspm. It must be a whole number
  from 1 to 3650, or cspm stops at start with the reason. A worker you
  run yourself needs the same value: the worker writes the reports.
- **Size Redis for it.** Redis runs with `noeviction`: when it reaches
  `REDIS_MAXMEMORY` (1 GB by default) it refuses writes for every service
  instead of dropping keys. A stored report takes about 100 bytes per
  check result, so 10 accounts scanned daily with 2,000 results each
  need about 180 MB at 90 days. Check the memory in use with
  `scripts/check_redis_config.py runtime`, then lower the retention or
  raise `REDIS_MAXMEMORY` (and `REDIS_MEMORY_LIMIT`, at least twice as
  much). The cspm README, "Scan retention and Redis memory", has the
  details.
- **Reports of scans completed before the upgrade are not shown.** The
  stored report is the only source. A scan completed before the upgrade
  has its report only in the Celery result backend, for at most a day
  after it completed, and keeps counting in `total_scans` for up to 30
  days, but its findings and score are not in the summaries and
  `GET /api/v1/scans/{id}/report` answers 400. Run the scan again to see
  its findings.
- **Celery results expire after two hours** (twice
  `SCAN_TIMEOUT_SECONDS`), no longer after a day. Finished scans take
  their status from their metadata, which `GET /api/v1/scans/{id}` now
  reads, so a completed scan stays `completed`. A script that read a
  report from the task result must call `GET /api/v1/scans/{id}/report`:
  the result holds a summary of the scan, not the report.
- **Batch scans now work.** `POST /api/v1/batch/scans` stored each scan's
  cloud credentials unencrypted, which the worker cannot read, so every
  batch scan failed; it wrote no scan metadata either, so `GET
  /api/v1/scans/{id}` answered 404 for its scans and they never counted
  in the summaries. Each scan of a batch is now started like a single
  scan. Batch scans started before the upgrade stay unreadable; start
  them again. Unencrypted credentials they left in Redis expired five
  minutes after each batch, but may remain in the append-only file until
  Redis next rewrites it.

### 25. Disabling an API key or an account needs the gateway to confirm

Revoking an API key, deactivating or deleting an account and removing a
member from a team now take effect at the gateway on the next request
(#593): identity has the gateway refuse the keys (and, for an account, its
sessions) before it commits the change. No migration.

- **Rebuild and restart identity and the gateway together** (section 1
  does). The gateway refuses an API-key decision that does not name its key
  (`api_key_id`, which only the new identity reports), so a new gateway with
  an old identity refuses every API key. An old gateway does not know the
  `api_keys` purge body: with it, or with a gateway identity cannot reach
  on port 8081 (section 3), every key revocation, account deactivation or
  deletion and member removal answers 503 and changes nothing. Decisions
  cached before the upgrade are not served; the gateway asks identity again.
- **Scripts that revoke keys or deactivate accounts** must handle 503: the
  change was not made, and repeating it is safe.
- **Deactivating or deleting an account ends its sessions** as well as its
  keys. A deactivated account that is reactivated must log in again.
- **API keys with an expiry work.** They answered 500 at
  `/internal/authorize` (503 at the gateway) on every request; now they work
  until `expires_at` and are refused from then on, cached decision or not.
- With more than one gateway replica, only the one identity reaches keeps
  the markers; the others refuse a revoked key once their cached decision
  expires (`AUTH_CACHE_TTL`), as for logout.

### 26. Removing a member from a team ends their sessions in that team

Removing a member from a team now also ends, at the gateway and in that
team only, the member's sessions issued up to the removal (#613): identity
sends the gateway a `memberships` marker before it commits the removal,
alongside the API keys of section 25. No migration.

- **Rebuild and restart identity and the gateway together**, as section 25
  says. An old gateway does not know the `memberships` purge body: with it,
  every member removal answers 503 and removes nobody.
- **Scripts that remove members** must handle 503: the member was not
  removed, and repeating the removal is safe.
- **A removed member's next request in that team answers 403**
  (`team_membership_ended`), not 401: the session is still valid. The
  request after it is authorized afresh and works in the oldest team the
  user still belongs to; a user with no team left gets 401. A client
  should not end the session on that 403.
- **A session issued before the removal does not work in that team again**,
  even if the user is added back, until it expires (the access-token
  lifetime); a new login does. Sessions in the user's other teams are not
  affected.
- With more than one gateway replica, only the one identity reaches keeps
  the markers, as in section 25.

### 27. cspm has a scan worker (`cspm-worker`)

cspm queued every scan for a Celery worker that `docker-compose.yml` had
commented out, and `docker-compose.prod.yml` had none, so no scan ever ran
(#601). A new service, `cspm-worker`, runs them. It is built from cspm's
directory with cspm's settings, so it is built with the others (section 1),
and in the production overlay it sits on `data` and `egress`.

- **Scans queued before the upgrade end as `failed`.** They are still in
  Redis, and the worker takes them as soon as it starts, but their
  credentials expired five minutes after each was queued. Start them again.
  Nothing has to be purged.
- **New variable, optional.** `CSPM_SCAN_TIMEOUT_SECONDS` (default 3600)
  is the time limit of one scan, passed to cspm and `cspm-worker` as
  `SCAN_TIMEOUT_SECONDS`. It must be from 120 to 86400, or both stop at
  start with the reason; an override that set `SCAN_TIMEOUT_SECONDS`
  outside that range has to change. The worker is given this long to stop,
  so `docker compose stop` and `down` can now wait up to an hour while a
  scan runs.
- **A worker you run yourself** must use the same `SECRET_KEY`,
  `CSPM_CREDENTIAL_KEY`, Redis URLs, `CSPM_REPORT_RETENTION_DAYS` and
  `SCAN_TIMEOUT_SECONDS` as cspm, and consume the queue `celery`
  (`celery -A app.worker:celery_app worker -Q celery`). Remove it if you
  now run `cspm-worker`, or the two share the scans.
- **Expect outbound traffic.** A scan now calls the provider's API from
  `cspm-worker`. Only AWS scans run; GCP and Azure scans are refused
  when they are submitted (section 28).
- `GET /api/v1/scans/{id}` reports a scan a worker has just taken as
  `running`. With a worker of your own it read `unknown` until the scan's
  first progress update.
- cspm's `/health` reports `"status": "healthy"` once the worker answers.
  It reported `degraded` while no worker ran.

### 28. cspm refuses GCP and Azure scans with 400

cspm scans AWS only. It used to accept GCP and Azure scans and fail every
one of them in the worker; it now refuses them when they are submitted
(#612). Rebuild cspm, its worker and the dashboard (section 1 does).

- **API clients get a 400.** `POST /api/v1/scans` with `provider` `gcp`
  or `azure` answers 400 with the message `Unsupported provider: gcp.
  Supported providers: aws.`, where it answered 202 with a scan id that
  later read `failed`. `POST /api/v1/batch/scans` answers 400 when any
  of its scans names such a provider, and starts none of the batch,
  including its AWS scans. Nothing is stored for a refused request.
  Scripts that submit GCP or Azure scans must stop doing so; scripts
  that read `failed` for them get the 400 instead.
- **Ask cspm what it can scan.** `GET /api/v1/cspm/providers` lists the
  supported providers, today `aws`, with the number of checks a scan
  runs. Read it rather than hard-coding a list.
- **The GCP and Azure checks are gone.** `GET /api/v1/checks` no longer
  lists the nine `GCP_*` and `AZURE_*` checks: they returned invented
  resources and never ran, since no GCP or Azure scan ever got a
  session. No stored report contains their results.
- **Malformed AWS keys fail at once.** An AWS scan whose access key id
  is not 16 to 128 letters, digits or underscores, whose secret is
  empty, or that asks for `assume_role` without an IAM role ARN, is
  still accepted, then fails as soon as the worker takes it, without a
  request to AWS. Before, a malformed key reached AWS and the scan
  completed with every check recording the rejected call.
- **GCP or Azure scans queued before the upgrade** fail when the worker
  takes them, as they did before.

### 29. Network tools refuse internal targets (`TOOLS_ALLOWED_INTERNAL_TARGETS`)

The tools that scan a host, an address or a range now refuse internal
targets before they run (#614), as the tools that fetch a URL already
did. Refused: private, loopback, link-local, unspecified, multicast,
reserved and shared (`100.64.0.0/10`) addresses; a CIDR or address range
with any such address in it; a host name that resolves to one, or does
not resolve; and the deployment's own names (every name without a dot,
such as `wildbox-redis`, plus `localhost`, `*.local`, `*.internal` and
the cloud metadata names). Rebuild the tools service and its worker
(section 1 does).

- **If you scan an internal lab, set the allowlist.**
  `TOOLS_ALLOWED_INTERNAL_TARGETS` takes comma-separated CIDR ranges, IP
  addresses and host names, for example
  `TOOLS_ALLOWED_INTERNAL_TARGETS=10.20.0.0/16,192.168.50.0/24,lab-dc01`.
  It is empty by default. `docker-compose.yml` passes it to `api` and
  `tools-worker`; a deployment of its own must give it to both. A range
  must have its host bits zero (`10.20.0.0/16`, not `10.20.0.1/16`), and
  a name is matched exactly, without its subdomains. A bad entry stops
  both at start-up with the reason.
- **Do not allow the stack's own network.** A listed range lets every
  caller of every network tool scan it. Keep the Docker networks of the
  stack (by default in `172.16.0.0/12`) out of the list. A service name
  stays refused even when its address is listed, unless the name is
  listed too.
- **Refusals answer 400** on `POST /api/v1/tools/{name}`, with a message
  that names the network target policy. An asynchronous task ends as
  `failed` with that message, and a workflow step of
  security_automation_orchestrator fails with it.
- **Other services are refused too.** The responder's `triage_ip` and
  `all_star_e2e` playbooks and the agents' port scans call the same
  endpoint: for a private address in an alert the scan step now fails
  (the playbooks continue without it) unless its range is listed.
- **One range holds at most 1024 addresses** (an IPv4 `/22`, an IPv6
  `/118`), allow-listed or not. network_scanner used to accept a larger
  range and sweep its first 1000 hosts, iot_security_scanner its first
  256: split a larger range into several requests.
- **Which inputs are checked**: `target` of ssl_analyzer, ca_analyzer,
  port_scanner, network_port_scanner and network_vulnerability_scanner;
  pki_certificate_manager's `domain`; iot_security_scanner's `target_ip`
  and `ip_range`; network_scanner's `network`; database_security_analyzer's
  `host`; dns_enumerator's `dns_servers` (which must be IP addresses) and
  the name servers it attempts a zone transfer from; the registry of
  container_security_scanner's `image_name` (`localhost:5000/app` is
  refused, `alpine:3.19` is not).
- **Host names must be ASCII.** Write an internationalized name in its
  `xn--` form. port_scanner also refuses a target with characters other
  than letters, digits, dots, hyphens and underscores instead of removing
  them, so it takes no IPv6 literal.
- dns_enumerator's zone transfers now connect to the name server's
  checked address. They passed the server's name, which dnspython does
  not accept, so every attempt failed; a zone that allows transfers is
  now reported as such.

### 30. guardian's own API keys no longer authenticate

guardian accepted rows of its own `APIKey` table from an `X-API-Key` (or
`Authorization: Bearer`) header on a direct request, as an administrator
and a Django superuser, beside the gateway (#629). It now accepts
gateway-authenticated requests only, as every other service does.

- **Use a personal API key from identity, through the gateway.** Create
  one in the dashboard (Settings > API keys) or with
  `POST /api/v1/identity/api-keys`, and send it as `X-API-Key` to
  `https://<host>/api/v1/guardian/...` (guardian's `/api/v1/...`). The
  key acts with its owner's team and role: a member's key reads, an
  owner's or admin's key also writes.
- **A direct request to guardian answers 403** `GATEWAY_AUTH_REQUIRED`
  (`"This service must be accessed through the API gateway"`), whatever
  key it carries. Before, a direct request without a key answered 401
  `NO_AUTH`.
- **The table is dropped.** guardian's migration
  `core.0002_remove_apikey`, applied at start, drops `core_apikey`, where
  the keys were stored in plain text, and the audit log's `api_key_id`
  column. The keys are not migrated to identity: create new ones. Back up
  first if you want a record of them; reversing the migration recreates
  an empty table.
- **`GUARDIAN_API_KEY` and `API_KEY_HEADER`** are gone from
  `open-security-guardian/.env.example`. Nothing read them; remove them
  from your `.env` if you copied them.

### 31. Responder playbooks call the services as the user who ran them

The responder's connectors now call the tools, data, guardian and agents
services at their real routes, with the identity of the user who started the
run and `GATEWAY_INTERNAL_SECRET` (#616). Before, every step that called one
of them failed.

- **New variables, optional.** `docker-compose.yml` sets the responder's
  `WILDBOX_API_URL`, `WILDBOX_DATA_URL`, `WILDBOX_GUARDIAN_URL` and
  `WILDBOX_AGENTS_URL` to the services' container addresses. Override them
  with `RESPONDER_WILDBOX_API_URL` and its siblings. A deployment that runs
  the responder elsewhere must set them, and `GATEWAY_INTERNAL_SECRET`, in
  the environment of the process that runs the playbook worker
  (`python -m dramatiq app.workflow_engine`); without the secret every
  connector step fails.
- **The URL defaults changed.** They named `localhost`, and Guardian's
  port 8003, where Guardian does not listen; they are now the container
  addresses of `docker-compose.yml`. A responder run outside the stack
  must set the URLs. Each must be an absolute `http(s)` URL, or the
  responder does not start.
- **A run acts for its caller, with their role.** The services authorize
  each call for that user and team: Guardian lets only owners and admins
  create a vulnerability, so `all_star_e2e`'s `create_finding` fails, and
  the run carries on, when a member runs it. A Guardian vulnerability needs
  an asset Guardian knows by the address.
- **Runs queued before the upgrade fail before their first step**: their
  message records no caller. Start them again.
- **Removed actions.** `data.add_to_blacklist`, `remove_from_blacklist`,
  `check_blacklist`, `query_iocs`, `add_ioc`, `get_threat_feed`,
  `update_reputation`, `get_asset_inventory`, `wildbox.add_to_blacklist`,
  `isolate_endpoint` and `create_ticket` called routes no service serves.
  A playbook of your own that uses one fails at that step as an unknown
  action; use `data.search_indicators` or `data.lookup_indicators` to read
  threat intelligence. `triage_url` no longer has a blacklist step.
- **Changed actions.** `wildbox.analyze_ioc` takes `ioc_type`,
  `ioc_value` and `priority` (no `context`) and returns the agents task.
  `wildbox.query_threat_intel` takes `query`, `indicator_type` and `limit`.
  `wildbox.create_vulnerability` requires `asset_name`, and
  `wildbox.get_asset_info` reads a Guardian asset by its UUID.
  `api.list_tools` returns `{"tools": [...]}`.
- With the production overlay, the responder reaches these services on
  `backend`, as before; `scripts/check_network_segmentation.py runtime`
  checks it.

### 32. Cancelling a responder run stops it

`DELETE /api/v1/responder/runs/{run_id}` now stops the run instead of only
relabelling it (#653).

- **New status `cancelling`.** A run cancelled while a step is running
  reads `cancelling` until the worker stops it, then `cancelled`. A client
  that waits for `completed`, `failed` or `cancelled` keeps working; one
  that lists the statuses it knows must add `cancelling`.
- **The answer says what happened.** `DELETE` answers 202 with
  `"status": "cancelling"` for a running run, 200 with `cancelled` for a
  queued one, and 200 with the run's status when it had already ended. It
  used to answer 200 `cancelled` in every case. The body carries `run_id`,
  `status` and `message`.
- **A cancelled run's steps.** The step in progress when the cancel
  arrives runs to its end and is kept in `step_results`; the steps after it
  do not run. A run whose last step had already started when the cancel
  arrived reads `cancelled` with every step in `step_results`.

### 33. The responder's notification action says it only logs

`system.notification` never delivered anything; it now says so (#639).

- **Its result changed.** The step output has `"status": "logged"` and
  `"delivered": false` instead of `"status": "sent"`. A playbook or client
  that tests for `sent` must test for `logged`; no notification is sent
  either way.
- **A step was renamed.** `triage_url`'s `notify_security_team` is now
  `log_security_alert`. A client that reads that step from a run's
  `step_results` or `context.steps` must use the new name.
- To have an alert reach people, read it from the run, or forward it from
  whatever polls the run.

## Upgrading to 0.10.0

From 0.9.x: five changes stop an existing deployment from starting, or change behavior in a
way that is invisible until it bites. Do them in this order.

### 1. Generate the new secrets (required — the stack will not start without them)

Several variables are newly required and are generated by nothing you already
have: `CSPM_CREDENTIAL_KEY`, `REDIS_PASSWORD`, `FLOWER_PASSWORD`,
`GUARDIAN_SECRET_KEY`, `CSPM_SECRET_KEY`, `SENSOR_API_KEY`,
`DATA_SECRET_KEY`. Without them
`docker compose config` fails, or the service starts and refuses every request
(guardian and cspm reject an empty SECRET_KEY; the sensor answers 503 on every
route but /health).

Cloud credentials used to be written to Redis in plaintext, so anyone with
Redis access held the customer's AWS, GCP and Azure keys. They are now
envelope-encrypted, and the CSPM service refuses to run a scan rather than fall
back to plaintext. `docker compose config` fails outright without the variable.

```bash
# FORCE=1 replaces .env from the template. The script backs the old one up to
# .env.env.backup first; copy across anything you had set by hand.
make generate-secrets FORCE=1
make validate-secrets           # CSPM_CREDENTIAL_KEY and the rest are required now
```

Credentials stored before the upgrade cannot be decrypted with the new key and
must be re-entered.

### 2. Rotate `API_KEY` (required — the old value is compromised)

The platform API key was rendered into dashboard HTML and is to be treated as
public. Regenerating is not enough on its own: rotate it, and prefer setting
`API_KEY_HASH_SECRET` once so that stored keys can be invalidated in future
without re-issuing every one of them.

```bash
./scripts/rotate_secrets.sh --secret API_KEY
./scripts/rotate_secrets.sh --secret API_KEY_HASH_SECRET --init   # once, ever
```

### 3. Migrate the databases (required — new constraints, and data may violate them)

The `identity` and `data` services now own alembic migration chains, and the
data API runs `alembic upgrade head` at startup instead of `create_all()`.
`create_all()` emits `CREATE TABLE` and never `ALTER TABLE`, so on a database
created before a column was added, that column stayed missing forever — which is
how the `team_id` tenancy columns went missing.

A database that predates the alembic scaffolding must be stamped first, or
alembic will try to create tables that already exist:

```bash
cd open-security-data
alembic stamp 0001_baseline      # ONLY for a database that predates alembic
alembic upgrade head
```

Two migrations add CHECK constraints, and **rows that already violate them stop
the migration**. This is deliberate: they are rows the application cannot
interpret. PostgreSQL's transactional DDL rolls the migration back cleanly, so
nothing is left half-applied, and the migration names the offending values and
the query that fixes them. To see the work in advance:

```sql
-- data service, revision 0003_vocab
SELECT indicator_type, count(*) FROM indicators
 WHERE indicator_type NOT IN ('ip_address','domain','url','file_hash',
                              'email','certificate','asn','vulnerability')
 GROUP BY indicator_type;

SELECT confidence, count(*) FROM indicators
 WHERE confidence NOT IN ('low','medium','high','verified')
 GROUP BY confidence;

-- identity service, revision f5a6b7c8d9e0
SELECT role, count(*) FROM team_memberships
 WHERE role NOT IN ('owner','admin','member')
 GROUP BY role;
```

Map each offending value to a valid one with `UPDATE`, then re-run the upgrade.

The identity migration also rewrites `api_keys.scopes`: rows where it was `NULL`
become an explicit `["*"]`. The permission is unchanged — "unrestricted" is now
a value that was written rather than an absence that was inferred, because the
old shape made the most privileged state the one an uninitialized column
produced.

Set `RUN_MIGRATIONS_ON_STARTUP=false` if migrations are a separate deploy step
in your environment; the data service then expects the schema to be at head
already.

### 4. Re-pull or rebuild images (recommended)

All six FastAPI services now resolve to the same Starlette (`1.6.0`) and FastAPI
(`0.141.1`). Before this change the deployment ran three different Starlette
majors, with different ASGI behavior and different security fixes in each.
Dependency locks are hash-pinned and resolved for Linux, so a rebuild installs
exactly the reviewed bytes.

```bash
docker compose build
docker compose up -d
```

### 5. Identity's JSON metrics moved (only if you consume them)

`GET /metrics` on the identity service now returns the Prometheus text
exposition, like every other service. The privileged JSON counts it used to
return -- `users_total`, `teams_total`, `api_keys_active`, still gated on
`X-Gateway-Secret` -- are at `GET /api/v1/admin/metrics`.

## Verifying the upgrade

```bash
make validate-secrets     # every required secret present, .env is 0600
make restore-drill        # backup -> restore -> row-by-row comparison
docker compose config -q  # compose file resolves
```
