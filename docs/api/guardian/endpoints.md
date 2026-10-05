# Guardian Service API

Guardian is the Django REST Framework service that stores assets, vulnerabilities,
scanner records, remediation work, compliance data, integrations and reports. This
page lists the routes defined in `open-security-guardian/guardian/urls.py` and in
each app's `urls.py`, and how to reach them through the gateway.

In the examples, `<host>` is the name you reach the gateway by, and IDs and
credentials are placeholders.

## Table of Contents

- [Base URL and routing](#base-url-and-routing)
- [Authentication and permissions](#authentication-and-permissions)
- [Conventions](#conventions)
- [Assets](#assets)
- [Vulnerabilities](#vulnerabilities)
- [Scanners, scans and schedules](#scanners-scans-and-schedules)
- [Remediation](#remediation)
- [Compliance](#compliance)
- [Integrations](#integrations)
- [Reports and alerts](#reports-and-alerts)
- [Task status](#task-status)
- [Health check](#health-check)
- [Rate limits](#rate-limits)
- [Errors](#errors)

---

## Base URL and routing

Every request goes through the gateway:

```text
https://<host>/api/v1/guardian/<path>  ->  guardian /api/v1/<path>
```

The gateway strips `/api/v1/guardian/` and forwards the rest to guardian under
`/api/v1/`. A few details of that route matter to clients:

- **Trailing slashes are required.** Every guardian route ends with `/`. Without it,
  Django's `APPEND_SLASH` answers `301 Moved Permanently` to the same path with the
  slash. The gateway rewrites that `Location` header back to `/api/v1/guardian/...`,
  so a `GET` that follows redirects still works, but most clients resend a
  redirected `POST` as a `GET`. Always write the slash.
- **Guardian sees its own host name.** The gateway sends `Host: open-security-guardian`
  (the caller's host travels as `X-Forwarded-Host`), because Django checks `Host`
  against `ALLOWED_HOSTS`. Guardian puts neither name in its answers: the `next` and
  `previous` links of a paginated response are relative references under
  `/api/v1/guardian/` (see [Pagination](#pagination)). The gateway tells guardian
  that path in `X-Forwarded-Prefix`, which it sets itself on every request, replacing
  any value a client sends.
- Paths in the tables below are relative to `https://<host>/api/v1/guardian/`.

Set up a shell for the examples:

```bash
CA=open-security-gateway/ssl/wildbox.crt
BASE="https://<host>/api/v1/guardian"
```

---

## Authentication and permissions

The gateway authenticates every request before it reaches guardian, then passes the
caller's user, team and role to guardian in trusted headers. Use either credential:

- **JWT bearer token.** Sign in with `POST https://<host>/auth/jwt/login`
  (form-encoded `username` and `password`) and send the `access_token` as
  `Authorization: Bearer <token>`.
- **API key.** Create one with the identity service:
  `POST /api/v1/identity/api-keys` (a user key) or
  `POST /api/v1/identity/teams/{team_id}/api-keys` (a team key). Send it as
  `X-API-Key: <key>`. See the [Identity Service API](../identity/endpoints.md).
  Guardian has no API keys of its own: the ones it had, and the model that stored
  them, were removed (#633).

```bash
TOKEN=$(curl -s --cacert "$CA" -X POST "https://<host>/auth/jwt/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=analyst@example.com" \
  --data-urlencode "password=<password>" | jq -r .access_token)

curl -s --cacert "$CA" "$BASE/assets/assets/" \
  -H "Authorization: Bearer $TOKEN"
```

### Gateway only

Guardian accepts a request under `/api/` only when it carries the gateway's
`X-Wildbox-User-ID` and `X-Wildbox-Team-ID` headers together with
`X-Gateway-Secret`, the `GATEWAY_INTERNAL_SECRET` proof of origin
(`apps/core/gateway_middleware.py`). A request sent to guardian's own port is
refused, whatever key it carries:

- without the identity headers: `403` with
  `"code": "GATEWAY_AUTH_REQUIRED"`;
- with the identity headers but without the matching secret: `403` with
  `"code": "GATEWAY_SECRET_REQUIRED"`;
- when guardian itself has no `GATEWAY_INTERNAL_SECRET`: `503` with
  `"code": "GATEWAY_SECRET_NOT_CONFIGURED"`.

Django REST Framework authenticates with the gateway headers only
(`GatewayHeaderAuthentication` in `guardian/settings.py`). Before #633 guardian
also accepted its own API keys in `X-API-Key` on its port, as an administrator,
beside the gateway.

### API key scopes

When an API key carries scopes, the gateway checks them on every guardian request
(`required_scope_for_request` in `open-security-gateway/nginx/lua/auth_handler.lua`).
A key created without scopes is unrestricted; a key with the `admin` scope passes
every check.

| Request | Required scope | Also accepted |
| --- | --- | --- |
| `GET`, `HEAD`, `OPTIONS` | `data:read` | `data:write`, `read`, `write` |
| `POST`, `PUT`, `PATCH` | `data:write` | `write` |
| `DELETE` | `data:delete` | none |

A key without the required scope gets `403` with `"error": "insufficient_scope"`.

### Roles

Guardian applies the team role it receives from the gateway
(`apps/core/permissions.py`):

- Any authenticated member can read (`GET`, `HEAD`, `OPTIONS`).
- Only `owner` and `admin` can create, change or delete. A `member` gets `403`.
- On the vulnerability list and detail routes, a `member` sees only vulnerabilities
  assigned to them or created by them; `owner` and `admin` see all of them.

### Teams

Every request acts on the caller's team's data only, the team the gateway
reports in `X-Wildbox-Team-ID` (`apps/core/tenancy.py`):

- Lists return the team's rows. Another team's id answers `404` on every
  detail route and action, as an id that does not exist would.
- A new row belongs to the caller's team; a `team_id` in the body is ignored.
  A reference to another team's row (an asset, a scanner, a user) is refused
  as one that does not exist.
- Rows that hang off another row take its team: a vulnerability its asset's,
  a scan its scanner's.
- Compliance frameworks, their controls and vulnerability templates without a
  team are shared reference data: every team reads them and none changes them.
- Names are unique within a team (environments, asset groups, discovery
  rules, frameworks, vulnerability templates, webhook endpoint paths): a
  name another team uses is free, and the answer to a duplicate never says
  what another team has.
- A user can be assigned or named (an assignee, an owner, an approver, the
  people a dashboard is shared with) only while they are a member of the
  team: they have made a request as a member of it within the last 30 days
  (`GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS`), and identity has not removed
  them from it. A user who left is refused as an id that does not exist
  is, and the roles they held in the team are cleared when they are
  removed: a vulnerability assigned to them becomes unassigned, with a
  line in its history. What they did (the rows they created, the notes
  they wrote) stays attributed to them.
- `/api/v1/guardian/tasks/<uuid>/` answers only for tasks the team
  dispatched; any other id answers `404`.

Rows created before 0.11.0 have no team and no team sees them until an
operator assigns them, for example with
`docker compose exec guardian python manage.py assign_guardian_team --team <team UUID>`
([UPGRADING.md, section 39](https://github.com/fabriziosalmi/wildbox/blob/main/UPGRADING.md#39-guardian-keeps-each-team-to-its-own-data-assign-the-existing-rows-required)).

---

## Conventions

### Pagination

List routes use page-number pagination with 50 items per page. Pass `?page=N`; the
page size cannot be changed per request.

```json
{
  "count": 120,
  "next": "/api/v1/guardian/assets/assets/?page=2",
  "previous": null,
  "results": []
}
```

`next` and `previous` are relative references: the path and query of the neighboring
page, without scheme or host, or `null` when there is none. They keep the other
query parameters of the request (`search`, `ordering`, filters); `previous` for page
2 is the list without `page`. Resolve a link against the URL you requested, as you
would a redirect:

```python
import requests
from urllib.parse import urljoin

url = "https://<host>/api/v1/guardian/assets/assets/?ordering=name"
while url:
    response = requests.get(url, headers={"X-API-Key": "<key>"}, timeout=30)
    response.raise_for_status()
    page = response.json()
    for asset in page["results"]:
        print(asset["name"])
    url = urljoin(response.url, page["next"]) if page["next"] else None
```

In JavaScript, `new URL(page.next, response.url)` does the same. Before #643 the
links were absolute URLs on `open-security-guardian`, the Host the gateway presents
guardian, and without the `/guardian` segment: no client could follow them. The
links contain no host on purpose: the only host guardian could write is the one the
client sent the gateway.

Custom actions that return a set of records (for example a vulnerability's
`history/`, or `compliance/exceptions/pending/`) answer a plain JSON array, not a
page. The one paginated custom action is `reports/alerts/{id}/notifications/`.

### Search, ordering and filters

Most list routes accept:

- `?search=<text>`: searches the fields the view declares (for example asset
  `name`, `hostname`, `fqdn`, `ip_address` and `description`).
- `?ordering=<field>` or `?ordering=-<field>`: sorts by one of the view's ordering
  fields.
- Field filters from the view's filter set, for example `?status=active` or
  `?criticality=high` on assets, and `?severity=critical` or `?status=open` on
  vulnerabilities.

### IDs and methods

`{id}` is the record's primary key; assets and vulnerabilities use UUIDs. Each
resource in the tables supports the standard routes unless the table says
otherwise:

| Method | Path | Action |
| --- | --- | --- |
| `GET` | `<resource>/` | List (paginated) |
| `POST` | `<resource>/` | Create |
| `GET` | `<resource>/{id}/` | Retrieve |
| `PUT`, `PATCH` | `<resource>/{id}/` | Update |
| `DELETE` | `<resource>/{id}/` | Delete |

Custom actions keep the Python method name in their path, underscores included
(for example `test_connection/`, `run_now/`).

### Placeholder actions

Several actions are not implemented yet: they validate the request, then return a
fixed success message without doing the work. The tables mark them as
**placeholder**. Do not rely on them for automation.

---

## Assets

Prefix: `assets/`. Defined in `apps/assets/urls.py`.

| Resource | Path | Notes |
| --- | --- | --- |
| Assets | `assets/assets/` | Standard routes |
| Environments | `assets/environments/` | Standard routes |
| Business functions | `assets/business-functions/` | Standard routes |
| Asset groups | `assets/groups/` | Standard routes |
| Discovery rules | `assets/discovery-rules/` | Standard routes |
| Installed software | `assets/software/` | Standard routes |
| Ports | `assets/ports/` | Standard routes |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `assets/assets/{id}/scan/` | Queues a port scan of the asset's `ip_address`. Returns `message` and `task_id`; `400` if the asset has no IP address |
| `POST` | `assets/assets/{id}/add_software/` | Adds a software record to the asset (`201`) |
| `POST` | `assets/assets/{id}/add_port/` | Adds a port record to the asset (`201`) |
| `POST` | `assets/assets/{id}/add_tag/` | Body `{"tag": "..."}` |
| `DELETE` | `assets/assets/{id}/remove_tag/` | Body `{"tag": "..."}` |
| `POST` | `assets/assets/discover/` | Body `{"network_range": "...", "scan_type": "basic"}`; queues a discovery task and returns `task_id` |
| `GET` | `assets/assets/statistics/` | Totals by type, criticality and status |
| `POST` | `assets/groups/{id}/apply_rules/` | Applies the group's assignment rules |
| `POST` | `assets/groups/{id}/add_assets/` | Adds assets to the group |
| `DELETE` | `assets/groups/{id}/remove_assets/` | Removes assets from the group |
| `POST` | `assets/discovery-rules/{id}/execute/` | Runs a discovery rule now |
| `POST` | `assets/discovery-rules/{id}/enable/` | Enables the rule |
| `POST` | `assets/discovery-rules/{id}/disable/` | Disables the rule |
| `GET` | `assets/software/inventory/` | Software inventory across assets |
| `GET` | `assets/ports/summary/` | Port summary across assets |

Asset fields accepted on create include `name` (required), `description`,
`asset_type` (`server`, `workstation`, `network_device`, `mobile_device`,
`iot_device`, `cloud_instance`, `container`, `application`, `database`, `other`),
`status` (`active`, `inactive`, `decommissioned`, `maintenance`, `unknown`),
`ip_address`, `hostname`, `fqdn`, `criticality` (`critical`, `high`, `medium`, `low`,
`unknown`), `tags` and `metadata`. Two assets cannot share an `ip_address`. Creating
an asset that has an `ip_address` and no ports also queues a port scan.

```bash
curl -s --cacert "$CA" -X POST "$BASE/assets/assets/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "web-01", "asset_type": "server", "criticality": "high", "hostname": "web-01.example.com"}'

curl -s --cacert "$CA" "$BASE/assets/assets/?criticality=high&ordering=name" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Vulnerabilities

Prefix: `vulnerabilities/`. The vulnerability resource is registered at the root of
the prefix, so the list is `vulnerabilities/` itself.

| Resource | Path | Notes |
| --- | --- | --- |
| Vulnerabilities | `vulnerabilities/` | Standard routes; `member` sees only assigned or self-created records |
| Templates | `vulnerabilities/templates/` | Standard routes |
| Risk assessments | `vulnerabilities/assessments/` | Standard routes |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `vulnerabilities/{id}/assign/` | Body `assigned_to` (user ID) and/or `assignee_group` |
| `POST` | `vulnerabilities/{id}/close/` | Sets status `resolved`. Body `reason`, `resolution_method` (default `fixed`) |
| `POST` | `vulnerabilities/{id}/reopen/` | Sets status `open`. Body `reason` |
| `POST` | `vulnerabilities/{id}/add_tag/` | Body `{"tag": "..."}` |
| `POST` | `vulnerabilities/{id}/remove_tag/` | Body `{"tag": "..."}` (a `POST` here, unlike assets) |
| `GET` | `vulnerabilities/{id}/history/` | Change history, as a plain array. The SLA check and the assignment notification record here what became of their e-mail: `SLA violation notification sent`, `sent to the team's owners and admins (no assignee to e-mail)` or `not sent (<reason>)` (`field_name` `sla_status`), and `Assignment notification sent` or `not sent (<reason>)` (`field_name` `assignment_notification`) |
| `GET` | `vulnerabilities/{id}/attachments/` | Attachments, as a plain array |
| `POST` | `vulnerabilities/bulk_action/` | See below |
| `GET` | `vulnerabilities/stats/` | Counts by severity and status |
| `GET` | `vulnerabilities/trends/` | Daily counts for the last `?days=N` days (default 30) |

A vulnerability needs `title`, `description` and `asset` (an asset ID). `severity`
is one of `critical`, `high`, `medium`, `low`, `info`; `status` is one of `open`,
`in_progress`, `resolved`, `accepted`, `false_positive`, `duplicate`; `priority` is
one of `p1` to `p4`. `cvss_v3_score` must be between 0.0 and 10.0.

`bulk_action/` takes `vulnerability_ids` (1 to 100 UUIDs) and `action`. The
serializer accepts `close`, `reopen`, `assign`, `tag`, `untag` and `priority`, but
the view only acts on `close`, `assign` (with `assigned_to` or `assignee_group`),
`tag` (with `tag`) and `priority` (with `priority`); `reopen` and `untag` change
nothing. The response reports `updated_count`.

```bash
curl -s --cacert "$CA" "$BASE/vulnerabilities/?severity=critical&status=open" \
  -H "Authorization: Bearer $TOKEN"

curl -s --cacert "$CA" -X POST "$BASE/vulnerabilities/<vulnerability-id>/close/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Patched in release 2.4", "resolution_method": "fixed"}'
```

---

## Scanners, scans and schedules

Prefix: `scanners/`. These routes record external scanners and their runs. Guardian
does not yet start, stop or import scans on an external scanner; the only scan it
performs itself is the asset port scan (`assets/assets/{id}/scan/`).

| Resource | Path | Notes |
| --- | --- | --- |
| Scanners | `scanners/scanners/` | Standard routes; filters `scanner_type`, `status` |
| Scan profiles | `scanners/scan-profiles/` | Standard routes; filter `scanner` |
| Scans | `scanners/scans/` | Standard routes; filters `scanner`, `profile`, `status` |
| Scan results | `scanners/scan-results/` | Standard routes; filters `scan`, `severity`, `processed`, `vulnerability_created` |
| Scan schedules | `scanners/scan-schedules/` | List, retrieve and delete only; see below |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `scanners/scanners/{id}/test_connection/` | **Placeholder.** Does not contact the scanner |
| `GET` | `scanners/scanners/stats/` | Scanner and scan counts |
| `POST` | `scanners/scans/{id}/start/` | **Placeholder.** Body `{"action": "start"}`; only sets the stored status to `running` |
| `POST` | `scanners/scans/{id}/stop/` | **Placeholder.** Only sets the stored status |
| `POST` | `scanners/scans/{id}/pause/` | **Placeholder.** Only sets the stored status |
| `POST` | `scanners/scans/{id}/resume/` | **Placeholder.** Only sets the stored status |
| `GET` | `scanners/scans/{id}/results/` | Results of one scan, as a plain array |
| `POST` | `scanners/scans/import_results/` | **Placeholder.** Validates the body and imports nothing |
| `POST` | `scanners/scan-schedules/{id}/disable/` | Disables a schedule |

### Scan schedules are not supported

Because guardian cannot start a scan on an external scanner, a scan schedule would
never run. Creating (`POST scanners/scan-schedules/`), updating (`PUT`/`PATCH`),
triggering (`POST .../{id}/trigger/`) and enabling (`POST .../{id}/enable/`) a
schedule all answer `400`:

```json
{
  "detail": "Scheduled scans are not supported: guardian cannot start a scan on an external scanner yet (starting, stopping and importing scans are not implemented), so a schedule would never run. Existing schedules can be listed, disabled and deleted."
}
```

Existing schedules can still be listed, retrieved, disabled and deleted. See
[issue #548](https://github.com/fabriziosalmi/wildbox/issues/548).

---

## Remediation

Prefix: `remediation/`.

| Resource | Path | Notes |
| --- | --- | --- |
| Tickets | `remediation/tickets/` | Standard routes |
| Workflows | `remediation/workflows/` | Standard routes |
| Steps | `remediation/steps/` | Standard routes |
| Comments | `remediation/comments/` | Standard routes |
| Templates | `remediation/templates/` | Standard routes |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `remediation/tickets/{id}/assign/` | **Placeholder.** Requires `assignee_id`; does not change the ticket |
| `POST` | `remediation/tickets/{id}/update_status/` | Body `{"status": "..."}`; sets the ticket status |
| `POST` | `remediation/tickets/{id}/sync_external/` | **Placeholder** |
| `POST` | `remediation/workflows/{id}/start/` | Sets the workflow status |
| `POST` | `remediation/workflows/{id}/pause/` | Sets the workflow status |
| `POST` | `remediation/workflows/{id}/complete/` | Sets the workflow status |
| `GET` | `remediation/workflows/{id}/progress/` | Progress of the workflow's steps |
| `POST` | `remediation/steps/{id}/execute/` | Marks the step started |
| `POST` | `remediation/steps/{id}/complete/` | Marks the step completed; optional `notes`, `validation_results` |
| `POST` | `remediation/steps/{id}/skip/` | Marks the step skipped |
| `POST` | `remediation/templates/{id}/clone/` | **Placeholder** |
| `POST` | `remediation/templates/{id}/apply/` | **Placeholder.** Requires `vulnerability_id` |
| `GET` | `remediation/templates/categories/` | Template categories in use |

---

## Compliance

Prefix: `compliance/`.

| Resource | Path | Notes |
| --- | --- | --- |
| Frameworks | `compliance/frameworks/` | Standard routes |
| Controls | `compliance/controls/` | Standard routes |
| Assessments | `compliance/assessments/` | Standard routes |
| Evidence | `compliance/evidence/` | Standard routes |
| Results | `compliance/results/` | Standard routes |
| Exceptions | `compliance/exceptions/` | Standard routes |
| Metrics | `compliance/metrics/` | Read-only (list and retrieve) |

Custom actions (all `GET`):

| Path | Description |
| --- | --- |
| `compliance/frameworks/{id}/controls/` | Controls of a framework |
| `compliance/frameworks/{id}/assessments/` | Assessments of a framework |
| `compliance/frameworks/{id}/metrics/` | Latest metrics of a framework |
| `compliance/controls/{id}/results/` | Assessment results for a control |
| `compliance/controls/{id}/evidence/` | Evidence for a control |
| `compliance/assessments/{id}/results/` | Results of an assessment |
| `compliance/assessments/{id}/evidence/` | Evidence of an assessment |
| `compliance/assessments/{id}/summary/` | Compliance summary of an assessment |
| `compliance/assessments/overdue/` | Overdue assessments |
| `compliance/results/non_compliant/` | Non-compliant results |
| `compliance/results/high_risk/` | High-risk results |
| `compliance/exceptions/pending/` | Pending exceptions |
| `compliance/exceptions/expiring_soon/` | Exceptions expiring in the next 30 days |
| `compliance/exceptions/needs_review/` | Exceptions due for review |
| `compliance/metrics/dashboard/` | Dashboard metrics |

---

## Integrations

Prefix: `integrations/`. The records can be created and managed, but none of the
actions below contacts the external system yet.

| Resource | Path | Notes |
| --- | --- | --- |
| External systems | `integrations/systems/` | Standard routes; filters `system_type`, `status`, `auth_type` |
| Field mappings | `integrations/mappings/` | Standard routes |
| Sync records | `integrations/sync-records/` | Standard routes |
| Webhook endpoints | `integrations/webhooks/` | Standard routes. `endpoint_url` is a record of the path the team chose, unique within the team (`400` on `endpoint_url` for a path one of the team's endpoints already uses); guardian does not receive webhooks on it |
| Integration logs | `integrations/logs/` | Read-only (list and retrieve) |
| Notification channels | `integrations/notifications/` | Standard routes |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `integrations/systems/{id}/test_connection/` | **Placeholder** |
| `POST` | `integrations/systems/{id}/health_check/` | **Placeholder.** Returns a fixed answer |
| `GET` | `integrations/systems/{id}/sync_status/` | **Placeholder.** Returns `last_sync` from the record |
| `POST` | `integrations/mappings/{id}/test_mapping/` | **Placeholder** |
| `POST` | `integrations/mappings/{id}/sync_now/` | **Placeholder** |
| `GET` | `integrations/sync-records/sync_statistics/` | **Placeholder** |
| `POST` | `integrations/sync-records/{id}/retry_sync/` | **Placeholder** |
| `POST` | `integrations/webhooks/{id}/test_webhook/` | **Placeholder** |
| `POST` | `integrations/webhooks/{id}/trigger_webhook/` | **Placeholder** |
| `GET` | `integrations/logs/error_summary/` | **Placeholder** |
| `DELETE` | `integrations/logs/cleanup_logs/` | **Placeholder.** Deletes nothing |
| `POST` | `integrations/notifications/{id}/test_notification/` | **Placeholder** |
| `POST` | `integrations/notifications/{id}/send_notification/` | **Placeholder** |

---

## Reports and alerts

Prefix: `reports/`.

| Resource | Path | Notes |
| --- | --- | --- |
| Report templates | `reports/templates/` | Standard routes |
| Report schedules | `reports/schedules/` | Standard routes |
| Reports | `reports/reports/` | Standard routes |
| Dashboards | `reports/dashboards/` | Standard routes |
| Widgets | `reports/widgets/` | Standard routes |
| Report metrics | `reports/metrics/` | Read-only (list and retrieve) |
| Alert rules | `reports/alerts/` | Standard routes |

Custom actions:

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `reports/templates/{id}/generate/` | Creates a report and queues its generation. Optional `parameters`, `filters`, `format`. Returns `202` with the report record |
| `GET` | `reports/templates/{id}/reports/` | Reports generated from the template |
| `GET` | `reports/templates/{id}/metrics/` | Metrics of the template |
| `POST` | `reports/schedules/{id}/run_now/` | Generates the scheduled report now. Returns `202` with the report record |
| `GET` | `reports/schedules/due/` | Active schedules whose next run is due |
| `GET` | `reports/reports/{id}/download/` | Downloads a completed report file; `400` while the report is not `completed` |
| `GET` | `reports/reports/recent/` | Recent reports |
| `GET` | `reports/reports/failed/` | Failed reports |
| `GET` | `reports/dashboards/{id}/data/` | Dashboard data |
| `POST` | `reports/dashboards/{id}/share/` | Shares the dashboard with users |
| `GET` | `reports/widgets/{id}/data/` | Widget data |
| `POST` | `reports/widgets/{id}/test/` | Tests the widget configuration |
| `GET` | `reports/metrics/summary/` | Reporting metrics summary |
| `POST` | `reports/alerts/{id}/test/` | Evaluates the rule now and returns `rule_triggered`, `current_value`, `threshold_value`, `test_time` |
| `GET` | `reports/alerts/{id}/notifications/` | Notifications of the rule, newest first (paginated). Each has `recipients` (who it was addressed to: the rule's own, or the team's owners and admins), `delivered` and, when it was not delivered, `failure_reason` |
| `POST` | `reports/alerts/check_all/` | Queues a check of all active rules; returns `task_id` |

Only some reports can be produced (`SUPPORTED_REPORT_TYPES` and
`SUPPORTED_REPORT_FORMATS` in `apps/reporting/models.py`):

- Report types: `vulnerability_summary`, `asset_inventory`, `compliance_status`,
  `executive_dashboard`.
- Formats: `json`, `html`.

Generating any other type or format creates a report that the worker marks as
failed, with the reason. A template's `default_format` is `pdf` unless set, so pass
`format` explicitly. Creating or updating a report schedule with an unsupported
template type or format answers `400` with the reason in `template` or `format`.

A generated report is processed by a worker. Poll `reports/reports/{id}/` until its
`status` is `completed`, then download it:

```bash
curl -s --cacert "$CA" -X POST "$BASE/reports/templates/<template-id>/generate/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format": "html"}'

curl -s --cacert "$CA" -OJ "$BASE/reports/reports/<report-id>/download/" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Task status

Actions that queue background work (`assets/assets/{id}/scan/`,
`assets/assets/discover/`, `reports/alerts/check_all/`) return a `task_id`. Read the
task's state with:

```bash
curl -s --cacert "$CA" "$BASE/tasks/<task-id>/" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "task_id": "3f2b8c1e-7d4a-4e09-9a51-0c6d2f8e4b17",
  "state": "SUCCESS",
  "ready": true,
  "successful": true,
  "queue": "scanning"
}
```

An ID that the caller's team did not dispatch, whether another team's or
unknown, answers `404`. Otherwise `state` is `PENDING`, `STARTED`, `SUCCESS`, `FAILURE` or
`RETRY`; `successful` is `null` until `ready` is `true`; `queue` is `null` until a
worker has taken the task. The task's result and traceback are never returned.

This is guardian's own task route, `/api/v1/guardian/tasks/<uuid>/`. The gateway path
`/api/v1/tasks/...` (without `guardian`) belongs to the tools service and does not
know guardian's tasks.

---

## Health check

Guardian's health check is `GET /health/`, with the trailing slash, on guardian's
own port (bound to `127.0.0.1:8013` in `docker-compose.yml`). It is not under
`/api/v1/`, so the gateway does not route it. It needs no authentication and
returns `200` with `"status": "healthy"`, or `503` with `"status": "unhealthy"`,
plus a `checks` object with the status of the database and Redis. It is not rate
limited.

---

## Rate limits

Two limits apply to guardian requests:

- **Gateway, per team.** The gateway allows `RATE_LIMIT_PER_HOUR` requests per
  hour per team, 10000 unless the deployment sets it, enforced in fixed 60-second
  windows of one sixtieth of that figure, rounded down and at least 1 (166 with
  the default).
  `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset` describe
  the current minute window, and `X-RateLimit-Policy` is the hourly figure, such
  as `10000;w=3600`. The gateway validates the variable at startup and does not
  start when it is not a whole number from 1 to 1,000,000,000.
- **Guardian, per user.** Guardian allows each user `GUARDIAN_RATE_LIMIT_USER`
  requests, 1000 per hour unless the deployment sets it, counted on the user the
  gateway authenticated (`X-Wildbox-User-ID`), not on an address
  (`apps/core/throttling.py`). The value is `<count>/<period>`
  with a period of `second`, `minute`, `hour` or `day`, for example `20/minute`, or
  `off` to leave only the gateway's limit. Guardian checks it at startup and does
  not start with any other value. One member cannot use up guardian for the rest
  of the team this way; the team as a whole is held by the gateway's limit.

Both answer `429 Too Many Requests` when exceeded. Guardian's throttle body is
`{"detail": "Request was throttled. Expected available in N seconds."}`, with the
same number of seconds in `Retry-After`.

Guardian has no limit for anonymous callers, because it has no anonymous callers:
a request under `/api/` that did not come through the gateway is refused (see
[Gateway only](#gateway-only)). Before #645 it carried one, 100 requests per hour
per address, whose only reachable route was the [health check](#health-check); and
the variable it read for both rates, `API_RATE_LIMIT`, was not passed to the
container by `docker-compose.yml`.

---

## Errors

Guardian answers errors in Django REST Framework's format:

| Status | Meaning | Body |
| --- | --- | --- |
| `400` | Validation failed, or an unsupported action | Field errors (`{"name": ["This field is required."]}`), `{"detail": "..."}` or `{"error": "..."}` |
| `401` | No valid credential (answered by the gateway) | Gateway JSON |
| `403` | Role or API key scope does not allow the request; or a request that did not come through the gateway | `{"detail": "..."}`, the gateway's `insufficient_scope` body, or `{"code": "GATEWAY_AUTH_REQUIRED", ...}` |
| `404` | Unknown ID or route | `{"detail": "..."}` |
| `429` | Rate limit exceeded | See [Rate limits](#rate-limits) |

---

## Related Documentation

- [Identity Service API](../identity/endpoints.md) - Sign-in and API keys
- [Authentication guide](../../guides/authentication.md) - Tokens and API keys through the gateway
- [Service ports](../../guides/ports.md) - Which ports each service binds
- [Security Policy](../../security/policy.md) - Authentication and authorization requirements
