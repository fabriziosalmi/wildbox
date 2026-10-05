# Guardian Django applications

Each directory is a Django application mounted under `/api/v1/` by
`guardian/urls.py` (`/api/v1/guardian/` through the gateway). Mutating
requests need the `owner` or `admin` gateway role; reads need any
authenticated caller.

| App | Route prefix | What it does |
| --- | --- | --- |
| `assets` | `assets/` | Asset inventory, environments, business functions, groups, discovery rules, software and ports. Runs its own TCP connect port scan and network discovery as Celery tasks. |
| `vulnerabilities` | `vulnerabilities/` | Vulnerabilities on assets, templates, assessments, history; close and reopen actions; SLA checks and risk-score recomputation as Celery tasks. |
| `remediation` | `remediation/` | Remediation tickets, workflows, steps, comments and templates. |
| `compliance` | `compliance/` | Frameworks, controls, assessments, evidence, results, exceptions and metrics; reminder and report tasks. |
| `reporting` | `reports/` | Report templates, schedules, generated reports, dashboards, widgets and alert rules; report generation and alert-rule tasks. |
| `scanners` | `scanners/` | Records of external scanners, scan profiles, scans, results and schedules. |
| `integrations` | `integrations/` | Records of external systems, mappings, sync records, webhooks, logs and notification channels. |
| `core` | none | Gateway authentication middleware, permissions, health and metrics views, the task-status view, the schedule dispatcher and management commands. |

## Records without behavior

`scanners` and `integrations` store configuration; they do not run scanners
or talk to external systems:

- `scanners`: no code contacts Nessus, Qualys, OpenVAS or any other scanner.
  A scan's `status` is a field of the record, set with `PATCH`. Creating,
  changing, triggering or enabling a scan schedule answers 400
  (`ScanScheduleViewSet`).
- `integrations`: no code contacts an external system, synchronizes
  anything, receives or sends a webhook, delivers through a notification
  channel, or writes an integration log. The one action is `cleanup_logs`,
  which deletes the team's logs older than a number of days.
- `remediation`: tickets mirror tickets of an external system that Guardian
  does not talk to; workflows and steps are worked by people
  (`automation_script` on a step is text, nothing runs it).

The only scanning Guardian performs is the asset port scan and discovery in
`apps/assets/tasks.py`. Of the discovery rule types, only `network_scan` is
implemented (`IMPLEMENTED_DISCOVERY_TYPES`).

### An action does what its answer says

These apps used to serve twenty actions that answered
`{"status": "success", ...}`, or fixed figures, without doing anything
(`test_connection`, `health_check`, `sync_now`, `send_notification`,
`import_results`, a scan's `start`, a ticket's `sync_external` and the rest).
They were removed in #644, and the ones that could be done in Guardian's own
database were implemented (a ticket's `assign`, a template's `clone` and
`apply`, `cleanup_logs`, the bulk `reopen` and `untag`).

`tests/unit/test_action_contracts.py` lists every custom action from the
URLconf and fails for one that is not classified there. To add an action, add
its contract:

- `Effect`: the request succeeds and changes something. The test compares
  every row Guardian stores, the Celery tasks dispatched and the e-mails
  sent, before and after; a `2xx` answer with nothing changed fails.
- `Evaluates`: a request other than a `GET` that computes an answer and
  stores nothing; the answer must change when the data does.
- `Refuses`: the action always answers an error and changes nothing. Use it
  for what Guardian cannot do, with a `detail` and a stable `code`; prefer
  not adding the route at all.
- `Reads`: a `GET`. It must store nothing, and its answer must change when
  the data does, so fixed figures fail.

An action that cannot do what it says is not given a route. One that cannot
run for a particular record answers an error with a `code` (for example `501
DISCOVERY_TYPE_NOT_IMPLEMENTED`), never `200` or `202`.

## Layout

Most apps follow the same layout: `models.py`, `serializers.py`, `views.py`
(DRF viewsets), `urls.py` (a DRF router), `migrations/`, and, where the app
has background work, `tasks.py` and `signals.py`. Every Celery task must be
listed in `TASK_QUEUES` in `guardian/celery.py`. Tests live in `../tests/unit/`.
