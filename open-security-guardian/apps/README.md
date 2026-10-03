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

- `scanners`: `test_connection` and `import_results` return a success message
  without doing anything, and `start`, `stop`, `pause` and `resume` only change
  the scan's `status` field. No code starts a scan on Nessus, Qualys, OpenVAS
  or any other scanner. Creating, changing, triggering or enabling a scan
  schedule answers 400 (`ScanScheduleViewSet`).
- `integrations`: the test, sync, retry, webhook trigger, notification and log
  cleanup actions return a success message without doing anything.
- `remediation`: `assign`, `sync_external`, and the template `clone` and
  `apply` actions are placeholders in the same way.

The only scanning Guardian performs is the asset port scan and discovery in
`apps/assets/tasks.py`.

## Layout

Most apps follow the same layout: `models.py`, `serializers.py`, `views.py`
(DRF viewsets), `urls.py` (a DRF router), `migrations/`, and, where the app
has background work, `tasks.py` and `signals.py`. Every Celery task must be
listed in `TASK_QUEUES` in `guardian/celery.py`. Tests live in `../tests/unit/`.
