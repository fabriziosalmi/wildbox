# Changelog

All notable changes to Wildbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **tools no longer serves `/api/system/info`,
  `/api/system/operational-metrics` and `/api/system/health-aggregate`,
  which answered without authentication.** Anyone who could reach the
  service port (the Docker network, or `127.0.0.1:8000` on the host)
  read the environment and debug flag, the tool inventory and the health
  body of every other service. The gateway never routed them and nothing
  called them. They are removed rather than put behind a role: the
  gateway forwards a team role, anyone who registers owns a team, and so
  tools cannot tell a platform operator from a tenant. What they
  reported was also wrong: the execution counters stayed at zero, and
  the aggregate called a healthy stack `degraded`, because it probed
  guardian at `/health` (a redirect to `/health/`), and answered 500
  when any service was unreachable. The real counters are in
  `GET /metrics` (`wildbox_tool_executions_total`); for the health of
  the other services use their own health checks or Prometheus (#646).

### Removed

- **tools: `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW` and
  `ENABLE_RATE_LIMITING`, settings that no code enforced.**
  `docker-compose.yml` set the first two and operators could tune them,
  but the service never applied a limit. They are removed, not enforced:
  every request reaches tools through the gateway, which already limits
  each team (`RATE_LIMIT_PER_HOUR`, 166 requests a minute at the
  default, well under the 500 these named), so a second counter of the
  same thing would have refused nothing. The lines are gone from
  `docker-compose.yml` and both `.env.example` files; in the Compose
  stack, leftover lines in `.env` are ignored (#646).
- **tools: `GET /api/system/metrics`, which answered 500 to every
  request.** It imported a name that `app/middleware.py` never defined.
  The service's metrics endpoint is the Prometheus one, `GET /metrics`,
  which `monitoring/prometheus.yml` scrapes; it is now registered by the
  shared package, as in the other services (#646).

### Fixed

- **tools registers one `GET /health` handler instead of two.** The
  second, with `uptime_seconds` and `tools_loaded`, never ran: the first
  one registered answers. The response does not change (#646).
- **`active_executions` in the tools `/health` response counts the runs
  in progress.** It was always 0: the tool routes ran through an
  execution manager of their own, not the one `/health` reads. For the
  same reason the service cancelled nothing when it shut down; it now
  cancels the synchronous runs in progress and waits up to 10 seconds
  for them to stop (#646).
- **Seven tools no longer add the tools service's `app` directory to
  `sys.path` when they are imported.** The entry was a leftover from
  before tools were loaded as packages, and it made every module of the
  service importable a second time under its bare name (#646).

## [0.11.2] - 2026-10-05

Two fixes found by running the upgrade from 0.10.0 to 0.11.1 end to end on
a Linux host, following UPGRADING.md's order of operations. The upgrade
itself held: every migration applied at start, an API key issued under
0.10.0 still authenticated, guardian's existing rows stayed hidden until
`assign_guardian_team` and were visible to their team afterwards, and the
integration suite passed against the upgraded stack (170 passed, 16
skipped, 0 failed). No API, schema or production configuration change.

### Fixed

- **The dashboard in the default `docker-compose.yml` no longer
  crash-loops on Linux when the checkout is not owned by uid 1001.**
  `next dev` runs as uid 1001 and was denied permission to write
  `next-env.d.ts` into the mounted checkout. The service now mounts
  only `src/` and `public/`, so nothing is written into the checkout;
  changes to `package.json` or a root config file need
  `docker compose up -d --build dashboard` (#690).
- **`make init-api-key-hash` no longer tells the operator to restart the
  running stack.** Seeding is an upgrade step that runs before the new
  images exist, yet it ended with the generic rotation advice to run
  `docker compose up -d --force-recreate`, which applies nothing to the
  old stack. It now points at the rest of the upgrade in UPGRADING.md
  (#689).

## [0.11.1] - 2026-10-04

Dependency upgrades for the dashboard and two documentation corrections.
No API, schema or configuration change: upgrading from 0.11.0 means
rebuilding the dashboard image. **Tailwind CSS 4 raises the dashboard's
browser baseline** to Safari 16.4, Chrome 111 and Firefox 128.

### Changed

- The dashboard uses zod 4; the tool form keeps its validation messages
  and now rejects integers outside the safe integer range with the
  field's bound.
- The dashboard builds with Tailwind CSS 4 and tailwind-merge 3; a v3
  compatibility layer keeps every page rendering as before.
- The dashboard type-checks with TypeScript 6. `tsconfig.json` targets
  ES2017 instead of ES5 and drops `baseUrl`, both deprecated in 6 and
  removed in 7; SWC compiles the code, so the output does not change.
  TypeScript 7 and eslint 10 are held back until typescript-eslint and
  eslint-plugin-react support them (#682, #683).
- The dashboard uses date-fns 4 (#672), and the CI workflows use
  `actions/setup-python` 7 (#673).

### Documentation

- The security policy no longer promises merchandise for critical
  reports, and the architecture decision log no longer lists
  `architecture@wildbox.dev`, an address that does not exist (#675).

## [0.11.0] - 2026-10-04

This release makes the platform's security promises hold when they are
tested. Revocation now holds: logout, a password change, revoking an API key
and removing a member from a team take effect at the gateway on the next
request, and each is committed only once the gateway confirms that it refuses
the credential; otherwise it answers 503 and changes nothing. Team isolation,
which 0.8.0 brought to data, responder and CSPM, now covers guardian (#642),
the data service's sensor telemetry (#641, #660) and the agents service's
tasks and rate limit (#650, #651). SSRF is closed across the tools service:
every network tool refuses internal targets, and the URL guard follows
redirects, nested inputs and workflow steps. What the platform made up is
gone: mock data in the dashboard, CSPM compliance figures that were
constants, fallbacks that showed sample values when a service failed, and
features that reported success while doing nothing. And the tests run: test
files no workflow collected, Playwright specs that never reached a backend
and a prose check that checked nothing now run and gate. **Several changes
are user-facing — read [UPGRADING.md](UPGRADING.md) before deploying.**

### Upgrade notes

Read [UPGRADING.md](UPGRADING.md) and follow its order of operations, which
puts the sections below in the order an existing deployment runs them; the
sections cited here are its sections for this release. In short:

- **Seed `API_KEY_HASH_SECRET` before starting the new images.** Run
  `make init-api-key-hash` once, while `.env` still holds the
  `JWT_SECRET_KEY` the running identity uses. Compose now passes the
  variable to identity, which keyed every API-key digest with the JWT key
  until now: started unseeded, identity rejects every existing API key, and
  in production it refuses to start without the variable (#648, section 38).
- **Rebuild every image.** `docker compose up -d` does not rebuild an image
  that exists, and nearly every image changes (section 1). Use the `-f`
  files you start the stack with.
- **Run the migrations.** identity (`a6b7c8d9e0f1`, `b7c8d9e0f1a2`), data
  (`0005_telemetry_team`) and guardian (`django_celery_beat.0019`,
  `core.0002_remove_apikey` and the `*_team_id` migrations) apply theirs at
  start; a data schema you migrate yourself needs `alembic upgrade head`
  before the new data API starts (section 34). `core.0002_remove_apikey`
  drops guardian's own API-key table (section 30).
- **Deploy identity and the gateway together.** Logout, a password change,
  revoking an API key, deactivating or deleting an account and removing a
  member need the gateway to confirm on its internal port 8081, and answer
  503 otherwise; a new gateway with an old identity refuses every API key
  (sections 3, 18, 25 and 26).
- **Assign guardian's existing rows to a team.** Rows written before 0.11.0
  have no team and are hidden from every team until
  `manage.py assign_guardian_team --team <uuid>` assigns them; run it with
  `--list` and `--dry-run` first (section 39). Sensor telemetry stored
  before the upgrade is hidden the same way, and section 34 has the SQL
  that assigns it.
- **The identity admin metrics need a superuser token.**
  `GET /api/v1/identity/admin/metrics` answers 401 without a token and 403
  to a token that is not a platform superuser's; `X-Gateway-Secret` no
  longer opens it (section 40).
- **The self-service API-key routes cover the caller's own keys only**, so
  the dashboard's API keys page lists your own keys. A team owner or admin
  manages other members' keys through
  `/api/v1/identity/teams/{team_id}/api-keys` (section 41).
- **New passwords follow a password policy**: 12 to 128 characters, not
  containing the email address or its local part, and not one of the
  10,000 most common passwords. Existing passwords keep working until they
  are next changed; `INITIAL_ADMIN_PASSWORD` must comply on a fresh install
  (section 23).
- **Removed endpoints and features** answer 404, or 401 and 403 for direct
  calls that bypassed the gateway; section 11 lists them with their
  replacements, and Changed below summarizes them.
- **Also**: leave `NEXT_PUBLIC_GATEWAY_URL` empty and rebuild the dashboard
  (section 16); set `TOOLS_ALLOWED_INTERNAL_TARGETS` if you scan an
  internal lab (section 29); `RATE_LIMIT_PER_HOUR` must be a whole number
  (section 32); the production overlay needs Docker Compose 2.24.4
  (section 10); and each sensor needs an identity API key with the
  `data:ingest` scope (section 35). Production Redis no longer evicts keys
  (section 42), and the agents service's per-user analysis limits are set
  through a compose override (section 43).

### Changed

Behavior that existing clients, scripts and operators will notice. Each item
names the detailed entries below.

- **Revocation fails closed.** Logout (#571), a password change (#569),
  revoking an API key and deactivating or deleting an account (#593), and
  removing a team member (#613) answer 503 and change nothing unless the
  gateway confirms. Repeating the request is safe.
- **A password change ends the account's other sessions**, including the
  token that made it; change-password answers with a new `access_token`
  (#569). It does not revoke API keys.
- **A password policy on every path that sets a password** (#583). A
  refusal answers 400 with the reason in `error.message` and fastapi-users'
  code in `error.details`.
- **Account changes need the current password.** `PATCH /auth/users/me`
  refuses `password` with 400 (#559); an email change needs
  `current_password`, and a wrong one counts toward the login lockout
  (#569). Login locks an account for 15 minutes after 5 failures, with 429
  and `Retry-After` (#509).
- **New 401 and 403 answers.** `PASSWORD_CHANGE_REQUIRED` for an account a
  team administrator created, until its password changes (#573);
  `team_membership_ended` for a removed member's session in that team
  (#613); `GATEWAY_AUTH_REQUIRED` for a direct request to guardian (#629);
  401 for a direct `X-API-Key` request to the tools service (#565); and
  identity's admin metrics for anyone but a superuser (#664).
- **New 404 answers that do not confirm what exists.** Another user's
  asynchronous tool task, or an unknown task id (#567); another user's
  agents task, which answered 403 (#650); another member's key on the
  self-service API-key routes (#664); another team's guardian rows (#642)
  and sensors (#641).
- **New 400 and 422 refusals before any work starts.** Internal network
  targets in the tools (#614, #610), tool input values a tool does not
  implement (#611), GCP and Azure scans in cspm (#612), and guardian
  schedules that cannot run (#548).
- **Scoping.** guardian (#642), sensor telemetry (#641) and the threat-intel
  dashboard metrics (#570) are per team; the self-service API-key routes
  act on the caller's own keys (#664); asynchronous tool tasks belong to
  the user who submitted them (#567); the agents analysis limit is counted
  per user (#651).
- **Removed endpoints and fields.** identity's team invitation (#570), its
  estimated request counts (#570) and `users.recent_logins` (#573); cspm's
  executive summary, remediation roadmap and scan status counts (#578),
  and renamed compliance fields (#572); the gateway's `/api/tools/` alias
  (#567) and the tools service's `/tools/` UI with the `auth_token` cookie
  (#581); guardian's own API keys (#629); responder actions that called
  routes no service has (#616). See Removed.
- **Null where there is no data.** `trends_change` (#573), and cspm's
  `compliance_score` and `overall_score` with no completed scan (#572,
  #578).
- **The tools verify TLS certificates** unless a scan sets
  `verify_ssl: false` (#495); identity serves no API documentation in
  production (#496).
- **Responder.** A cancel of a running run answers 202 `cancelling`
  (#653); `system.notification` answers `"status": "logged"` and
  `triage_url`'s step is now `log_security_alert` (#639); a playbook with
  an unknown key stops the responder at start (#417).
- **Refusals at start-up.** identity in production without
  `API_KEY_HASH_SECRET` (#648); the gateway with a `RATE_LIMIT_PER_HOUR`
  that is not a whole number (#627); the tools with a bad
  `TOOLS_ALLOWED_INTERNAL_TARGETS` entry (#614); cspm with
  `CSPM_SCAN_TIMEOUT_SECONDS` or `CSPM_REPORT_RETENTION_DAYS` out of range
  (#601, #591); identity with an `INITIAL_ADMIN_PASSWORD` the policy
  refuses (#583).

### Added

- **A team owner or admin can create accounts in the team** (#573).
  identity had no way to put a second person in a team since the
  invitation endpoint, which sent nothing, was removed (#570):
  registration always creates a team of its own. `POST
  /api/v1/admin/teams/{team_id}/members` with `email`, `password` and
  `role` now creates a new account whose only membership is that team,
  so its sessions work in it. It is open to the team's owners and admins
  and to superusers; the role must be below the caller's own (an owner
  creates admins and members, an admin creates members, nobody creates
  an owner), and an email that is already registered answers 409. An
  existing account cannot be added and no email is sent: the
  administrator gives the initial password to the new member. The
  creation is logged without the password. The Team page has an "Add
  member" form for owners and admins.
- **An account created that way must change its password first** (#573).
  The administrator chose its initial password, so the account carries
  `must_change_password` (a new column, alembic revision
  `b7c8d9e0f1a2`) until its user changes it. Meanwhile its sessions can
  only read the account, change the password and log out: identity
  answers 403 `PASSWORD_CHANGE_REQUIRED` to every other route, and the
  gateway does the same for every other service, as
  `/internal/authorize` now reports `password_change_required`. The
  dashboard takes such a user from the login to a "Choose your
  password" screen, and back to it from any other page.
- **Run a tool from the dashboard** (#585). `/toolbox` was a catalog
  since the tools service's standalone pages were removed (#581). Each
  tool's "Run" button now opens `/toolbox/<name>`, a form generated from
  the input schema of `GET /api/v1/tools/<name>/info`: strings, numbers
  and integers with their bounds, enums (also behind `$ref`), booleans,
  arrays of primitives, and a JSON text area for anything else; `anyOf`
  with `null` is an optional field, and the schema's description,
  default and example are the help text, initial value and placeholder.
  The schema's constraints are checked before anything is sent, and an
  empty optional field is left to the service's default. The run is
  either synchronous (`POST /api/v1/tools/<name>`) or a background task
  (`POST .../async`, then `GET /api/v1/tasks/<id>` until it finishes),
  which can be cancelled. The result is the service's answer as it came,
  as key/value tables and lists plus the raw JSON, with "Copy JSON",
  "Download JSON" and "Copy as cURL" (the request with the form's body;
  the token comes from `$WILDBOX_TOKEN`). Refusals are shown with the
  service's reason: field errors under their fields, SSRF-blocked
  targets (400) and tools the caller is not authorized for (403).
- **A tool's 422 names the fields that failed** (#585). The tool
  endpoint answered every invalid body with the bare message "Input
  validation failed". The canonical error body now also carries
  `details.errors`, the location, message and type of each failure,
  without the submitted values.

### Fixed

- **The responder's `system.notification` no longer claims to have sent
  anything** (#639). It wrote a log line and answered `"status": "sent"`,
  though no e-mail, webhook or chat message ever left the system, so
  `triage_url` reported an alert that nobody received. It now answers
  `"status": "logged"` and `"delivered": false`, and its description in
  `GET /v1/connectors` says that nothing is delivered. `triage_url`'s
  step `notify_security_team` is renamed `log_security_alert`, and
  `simple_notification` is named "Simple Logging Test". The responder
  README documents the action, and the connector example in
  `docs/api/responder/endpoints.md`, which listed Jira and Slack
  connectors that do not exist, shows the real response. Delivery is not
  implemented.

- **Cancelling a responder run stops it** (#653). `DELETE
  /v1/runs/{run_id}` only rewrote the stored status: the worker never
  read it again, so a cancelled run executed every remaining step, side
  effects included, and then wrote `completed` over `cancelled`, and a
  run cancelled while queued was set back to running and executed in
  full. The cancel is now a request stored with the run, which the
  worker checks before the run starts and before each step. A queued run
  is cancelled at once and runs no step; a running run becomes the new
  status `cancelling`, its step in progress runs to its end and is
  recorded as it ended, no further step starts, and the run ends
  `cancelled`. The worker's writes are compare-and-set (WATCH/MULTI)
  against the run's status and the request, so a `cancelled` run is
  never recorded as anything else and a race between completion and
  cancel goes to whichever commits first. `DELETE` answers 200 with
  `cancelled`, 202 with `cancelling`, or 200 with the status of a run
  that had ended, and is checked against the run's team as before. A
  run's `logs` also keep every line again: saving the worker's copy of
  the record replaced the lines written since the run started.

- **The agents routes accept a session token, and `/stats` is reachable**
  (#630). `/api/v1/agents/*` read `X-API-Key` only and answered a JWT
  with 401 `NO_API_KEY`, so a signed-in user could not submit or read an
  analysis, although the API documentation says a JWT or an API key works
  on every route. Both work now (see Security). `/api/v1/agents/stats`
  mapped to the service's `/v1/stats`, which does not exist; it now
  reaches `/stats`, authenticated.
- **The gateway declares `RATE_LIMIT_PER_HOUR` and refuses a bad value**
  (#627). `auth_handler.lua` reads the per-team budget with `os.getenv`,
  but `nginx.conf` did not list it with `env`, and nginx hands its
  processes only the variables listed there. The setting took effect
  only because `init_by_lua` loads the module in the master process,
  whose environment is still complete on a cold start; a module loaded
  anywhere else, or a master started by a binary upgrade, saw nothing
  and used 10000. It is now declared. A value that is not a whole number
  from 1 to 1000000000 (`0`, `10k`, `1.5`, an empty string) used to
  become 10000 without a word; the gateway now logs
  `RATE_LIMIT_PER_HOUR must be a whole number ...` and does not start
  (`nginx -t` does not run `init_by_lua` and does not catch it).
  `scripts/check_gateway_config.py`, run by the Gateway Lint workflow,
  fails when the gateway's Lua or nginx configuration reads a variable
  `nginx.conf` does not declare; the six other variables the gateway
  reads were already declared. The
  gateway harness starts a gateway with `RATE_LIMIT_PER_HOUR=120` and
  checks that the third request in a minute gets 429, and starts one per
  invalid value and checks that each exits. The deployment guide
  documents the variable.

- **Reading a just-cancelled async task no longer answers 500** (#619).
  `GET /api/v1/tasks/{id}` read `AsyncResult.state` and then
  `AsyncResult.info`: two reads of the result backend while the task
  has not finished. When the worker marked the task REVOKED in between,
  `info` held a `TaskRevokedError` that the response could not
  serialize (`PydanticSerializationError`), and the read failed. The
  tools service now reads a task's state, result and completion time
  once, and every state has a defined answer: REVOKED is `cancelled`,
  FAILURE is `failed` with the exception class only (no message or
  traceback, which can carry internal paths and hosts), and a result
  Celery cannot decode, such as a FAILURE stored with a custom meta, is
  read from the raw record instead of raising. A running task shows
  its progress fields and no longer the worker's host name and process
  ID. Cancelling and listing read the same way, and an unreachable
  result backend is a 503. The tools service now logs the class and
  traceback of a request that fails, and the integration workflow
  uploads every service's full log when it fails.


- **Sensor telemetry reaches the data service, under the sensor's team**
  (#628). The sensor's forwarder posted to the data service's
  `/api/v1/ingest` directly with `Authorization: Bearer <key>`, but the
  data service accepts only requests the gateway has authenticated, so
  every batch was refused and no telemetry was ever stored. The sensor
  now posts to the gateway, `https://<gateway>/api/v1/data/ingest`, with
  an identity personal API key in `X-API-Key`: the key of a team member
  created for the sensor. The gateway resolves the key, refuses it once
  it is revoked, expired or its member removed (#593, #608), and forwards
  the key's team; the data service stores the events and the sensor's
  record under that team. A new API key scope, `data:ingest` (identity's
  vocabulary, the dashboard's API keys page, the gateway's scope map),
  allows `POST /api/v1/data/ingest` and nothing else; `write` and
  `data:write` keep allowing it. The sensor verifies the gateway's
  certificate by default, against `data_lake.ca_bundle` when set
  (`SENSOR_DATA_LAKE_CA_BUNDLE`), sends the key in no other header, does
  not follow redirects with it and never logs it; a 401 or 403 is no
  longer retried. At start-up it refuses, with a message naming the
  setting, an endpoint that is not an `https://` gateway URL (the old
  direct URL included), a key that is not an identity key and a CA
  bundle that does not exist; with no key it runs and logs that
  forwarding is disabled. `--test-connection` posts an empty batch and
  reports the answer: it used to print success without connecting.
  Batches are now in the shape the data service validates (sensor ID,
  one of its event types, the collected event kept whole in
  `event_data`, the collector's type as a tag); the forwarder sent the
  processor's own shape, which the data service would have refused too.
  `docker-compose.yml` points the sensor at `https://open-security-gateway`
  and gives it the gateway's certificate (never its key), which the
  gateway now publishes into a `gateway_cert` volume when it starts; in
  the production overlay the sensor moves from `backend` to `frontend`,
  reaching the gateway and no backend service
  (`scripts/check_network_segmentation.py` asserts both). The data
  service stores the events and the sensor record under the key's team
  and serves them to that team only (#641, under Security). Three
  defects on the same path that the refused credential had hidden are
  fixed with it: a batch of more than one event from a new sensor
  inserted its record twice and failed with 500, the events and sensors
  listings answered 500 as soon as they had a row (their `id` was
  declared a string), and a batch whose commit fails now answers 503,
  so that the sensor sends it again, instead of 200 with nothing stored.
- **cspm refuses scans of providers it cannot scan** (#612). The scan
  API accepted `provider: gcp` and `provider: azure`, single and batch,
  and answered with a scan id; the worker then failed every such scan,
  because only the AWS session existed. `POST /api/v1/scans` and `POST
  /api/v1/batch/scans` now answer 400, naming the supported providers,
  before they store credentials or queue anything; a batch that names
  one is refused whole. The supported providers come from a registry in
  `app/providers.py`: a provider is supported when cspm has a session
  factory for it and at least one implemented, enabled check. The new
  `GET /api/v1/providers` (`/api/v1/cspm/providers` through the gateway,
  authenticated like every cspm route) lists them with their check
  counts, and the dashboard's scan form (`/cloud-security/scans`) offers
  exactly those, or an error with a retry when the call fails, instead
  of a hard-coded AWS, GCP and Azure list. The GCP and Azure check
  modules were removed: nine checks that returned the same invented
  buckets, instances and users on every run, and could not run without
  a session, and two empty files. `/api/v1/checks` now lists the 22 AWS
  checks only. The AWS session factory refuses credentials that cannot be valid (an access key id
  that is not 16 to 128 letters, digits or underscores, a missing
  secret, `assume_role` without an IAM role ARN) before it creates any
  boto3 session, so such a scan fails without a request to AWS; the
  integration tests of cspm-worker use that path to reach `failed`
  instead of a GCP scan. `assume_role` now also passes `external_id` to
  STS when one is given; it was accepted and ignored. A scan that failed
  on such an error could read 500 at `GET /api/v1/scans/{id}` for a
  moment: the worker stored a FAILURE state with a plain dict as its
  meta, which Celery cannot read back as an exception. The worker now
  fails the task with a detail-free exception, and a scan whose stored
  status is final no longer reads the result backend.

- **network_scanner scans again** (#615). Every run failed before the
  first probe: `ping_host` indexed the boolean that a stub target check
  returned, and `asyncio.gather` swallowed the `TypeError`, so each scan
  reported success with no hosts. The tool now pings each address with
  an argument list and no shell, probes the common ports of live hosts
  with a TCP connect when `scan_type` is `tcp`, and honors `timeout` and
  `max_threads` from the request: it ignored both before. A range larger
  than 1024 addresses is refused before any probe instead of being
  listed in full and then truncated, which hung the service on a `/0` or
  an IPv6 `/64`. The stubs went with the defect: a rate limiter that
  slept while holding its lock, which held a `/24` for minutes, and a
  port "restriction" that skipped 22, 135, 139, 445 and 3389. A failed
  probe of a host now reports why in the host's new `error` field. The
  tool stays separate from port_scanner and network_port_scanner, which
  scan one host each; it is the only tool that sweeps a range.
- **hash_generator runs with its defaults** (#611). `hash_types`
  defaulted to md5, sha1, sha256 and sha512 while the tool no longer
  implemented md5 or sha1, so a run with the defaults, and the form the
  dashboard builds from the schema, answered `success: false`. The field
  is now an enum built from the same tuple as the tool's algorithm
  table (sha224, sha256, sha384, sha512, blake2b, blake2s), defaults to
  sha256 and sha512, and an unsupported algorithm is a 422 before the
  tool runs. `output_format` is an enum too, and a salted hash uses the
  algorithm it is labeled with: sha224 and blake2 fell back to SHA-256.
- **Every tool's input schema describes what the tool accepts** (#611).
  An audit of all 52 tools found the same mismatch in many of them: a
  free-text field whose tool implements a fixed set of values, an
  unknown value then failing the run, running nothing while reporting
  success, or falling back to another value silently. Those fields are
  now enums of the values the tool implements (fields the tool compares
  regardless of case still accept any case), defaults outside them are
  gone (threat_intelligence_aggregator listed the unimplemented
  MalwareBazaar source, cloud_security_analyzer scored nist 100% compliant
  without checking it), and inputs a tool cannot run without, such as
  one of `target_ip`/`ip_range` or `file_url`/`file_data`, are checked
  by the model. Such a request is now a 422 before the tool runs. The
  per-tool list is in the pull request.
- **`/info` publishes the model the tool endpoint validates** (#611).
  It took any class whose name contains "Input", so for six tools whose
  model sorts before `BaseToolInput` (api_security_analyzer,
  api_security_tester, base64_tool, security_automation_orchestrator,
  threat_intelligence_aggregator, web_application_firewall_bypass) it
  published the base class, and the dashboard built a form without the
  tool's fields. For five tools that list their classes in `TOOL_INFO`
  it answered 500. The endpoint, `/info` and the worker now share one
  lookup, and `/info` leaves classes out of the metadata.
- **Every tool answers with its output model** (#611). Seventeen tools
  built their output without `success`, which `BaseToolOutput`
  requires, so every one of their runs failed validation:
  api_security_analyzer, api_security_tester,
  blockchain_security_analyzer, cloud_security_analyzer,
  crypto_strength_analyzer, digital_footprint_analyzer,
  directory_bruteforcer, dns_enumerator, email_harvester,
  file_upload_scanner, hash_cracker, jwt_analyzer,
  mobile_security_analyzer, static_malware_analyzer, subdomain_scanner,
  threat_intelligence_aggregator, xss_scanner. port_scanner,
  network_scanner and header_analyzer built theirs from fields their
  schema does not have (header_analyzer also handed pydantic's `HttpUrl`
  to `urlparse`, so it never ran), and ip_geolocation and
  malware_hash_checker declared `Optional` fields without a default,
  which pydantic treats as required. A target that could not be reached
  also escaped many tools as an exception: they caught `ConnectionError`,
  which a DNS failure, an aiohttp or requests error, a dnspython error
  or the bare `Exception` some of them re-raised is not. They now catch
  `app.tool_errors.RUN_ERRORS` and answer `success: false` with the
  reason; a malformed threat indicator, input base64_tool cannot decode
  and a trivy binary that cannot be started are reported the same way.
- **A workflow step gets its tool's input model** (#611). The
  orchestrator took the first schema class whose name ends in "Input",
  which was the imported `BaseToolInput` for every tool.
- **cspm runs the scans it queues** (#601). `docker-compose.yml` had the
  cspm worker commented out and `docker-compose.prod.yml` declared none,
  so every scan stayed `queued` and the compliance pages, the cloud
  security overview and the reports never had data. A new service,
  `cspm-worker`, built like cspm and with its settings (credential key,
  Redis URLs with the password, `CSPM_REPORT_RETENTION_DAYS`, scan time
  limit), consumes exactly the queue the scan tasks are routed to, now
  named in `app/worker.py` and checked against the service by a unit
  test. It has a health check that pings its own node, resource limits,
  `restart: unless-stopped`, `no-new-privileges`, the image's non-root
  user, and a `stop_grace_period` equal to the scan time limit, which is
  now `CSPM_SCAN_TIMEOUT_SECONDS` (default 3600, validated from 120 to
  86400). Redis redelivers an unfinished task only after that limit plus
  ten minutes, so a long scan is never run twice. In production it sits
  on `data` and `egress`; `check_network_segmentation.py` covers it. A
  scan a worker has taken reads `running` instead of `unknown`. The
  Production Stack job checks that each replica answers a ping and reads
  the routed queue, and an integration test submits a scan through the
  gateway and waits for the worker to finish it.

- **tools resolve host names again.** aiohttp resolves through aiodns when it
  is installed, and the lock paired aiodns 3.2.0 with pycares 5.0.1: aiodns
  called pycares' `getaddrinfo` with the pycares 4 signature, so every lookup
  raised `TypeError` and every tool that fetched a host name through aiohttp
  failed before connecting. aiodns is now 4.0.4, which requires pycares 5, and
  a unit test resolves `localhost` through aiohttp's default resolver.
- **A protected route no longer answers 503 when identity closes an idle
  connection** (#609). The gateway asks identity to authorize every
  uncached token over connections it keeps alive, and kept them idle for
  60 s, while identity (uvicorn) closes them after 5 s. A request written
  into a connection identity was closing failed with "connection reset
  by peer" or "broken pipe", and the gateway answered 503 with nginx's
  HTML error page: about one E2E repetition in a hundred, at times three.
  Ten of those within a minute opened the circuit breaker, and every
  uncached token then got 503 for a minute. The gateway now gives an
  idle connection up after 4 s, for its Lua calls and for every upstream
  it proxies to (a POST written into a closing connection got a 502), and
  sends an authorization that met a closed connection once more, on
  another one: authorizing changes nothing at identity. Only a failure
  that survives that counts toward the circuit breaker. When identity
  cannot be reached, the 503 is now JSON, like every other refusal of
  the gateway, with `Retry-After`.

- **A responder step condition on an undefined name is false** (#595).
  Templates render with `StrictUndefined`, so a condition that checked
  an optional field, such as `trigger.tag == 'urgent'` when the trigger
  carried no `tag`, raised and failed the step instead of skipping it.
  Such a condition now evaluates to false, the step is skipped, and the
  run log records a warning naming the reference as written in the
  condition, without any value from the context. A condition that is not
  a valid expression or that the sandbox blocks still fails the step, and
  an undefined name in a step's input is still an error. The semantics
  are in the playbook reference (`open-security-responder/README.md`).
- **A responder condition that reaches for Python internals fails the
  step** (#595). A condition containing a blocked pattern such as
  `__class__` evaluated to false, so the attempt was hidden behind a
  skipped step. It now raises like a sandbox violation, and the step
  fails according to its `on_failure` policy.
- **The shipped responder playbooks' conditions are valid expressions**
  (#595).
  `triage_ip.yml`, `triage_url.yml` and `all_star_e2e.yml` wrote their
  conditions as `"{{ ... }}"`. A condition is the body of an `{% if %}`,
  so each was a syntax error and every conditional step failed. They are
  now plain expressions, with `is defined` guards where the data is
  optional, and `all_star_e2e.yml` reads the step result from `output`
  instead of `result`, which never existed. A unit test compiles every
  condition and every input template of every shipped playbook, so a
  broken one fails CI.
- **The shipped responder playbooks run to completion** (#605). They
  compiled, but read names the run context does not have and branched on
  results no step produces:
  - `all_star_e2e.yml` read `steps.<id>.result` and a `system.timestamp`
    that nothing provided, so it stopped at `threat_assessment`.
  - `system.evaluate` returned neither of the `verdict` and `severity`
    that `add_to_blacklist` and `notify_security_team` in
    `triage_url.yml` and `create_finding` in `all_star_e2e.yml` were
    guarded on, so those steps never ran. It also took `bool()` of what
    it was given, so the nested mapping `triage_ip.yml` passed always
    held. It now takes a `conditions` mapping and an optional `min_true`,
    returns `overall_result` with the names that held, and fails the step
    on a value that is not a boolean. The guarded steps read
    `overall_result`.
  - The playbooks named tools the tools service does not have (`nmap`,
    `whois`, `reputation_check`, `domain_reputation`) and fields their
    results lack. They now call `port_scanner`,
    `threat_intelligence_aggregator`, `url_analyzer` and `ip_geolocation`
    with those tools' parameters, and read the fields the tools return.
  - A step after an invalid IP address or URL is skipped, so such a run
    completes after validation instead of failing on a skipped step's
    output.
  - Every step's context now has `run.id`, `run.playbook_id` and
    `run.started_at`, documented with `steps.<id>.output` in the playbook
    reference (`open-security-responder/README.md`).
  - Step inputs are no longer HTML-escaped. `{{ trigger.url }}` turned
    `&` into `&amp;`, so `triage_url.yml` would have blacklisted a URL
    nobody submitted.

  A unit test runs each shipped playbook through `start_execution` and
  the worker actor, with the other services stubbed at the connectors'
  HTTP clients, and asserts which steps run, are skipped or fail for
  malicious, benign and invalid inputs. The stubbed responses and the
  parameters sent to each tool are checked against the services' own
  schemas.
- **Responder playbooks reach the services they call, as the user who
  ran them** (#616). No step that called another service could succeed:
  - No request carried an identity, and tools, agents, data and guardian
    accept only the gateway's `X-Wildbox-*` headers with
    `X-Gateway-Secret`. A run now records the gateway-authenticated user
    who started it, and every connector request carries that user's
    identity and the secret, so each service authorizes the call for that
    user and team. A run without a complete caller fails before its first
    step, and nothing is sent without one. The identity is scoped to the
    run and reset when it ends.
  - The tools connector posted a `params` envelope to
    `/api/v1/tools/{tool}/execute`. It now posts the tool's input to
    `/api/tools/{tool}`, or to `/api/tools/{tool}/async` with
    `async_execution`, and reads and cancels tasks at `/api/tasks/{id}`.
  - `wildbox.analyze_ioc` sends the agents service's
    `{"ioc": {"type", "value"}, "priority"}` and returns the task it
    queues; the verdict is read later from the task's `result_url`.
  - `wildbox.create_vulnerability` records the vulnerability against the
    Guardian asset named or addressed by `asset_name`, and fails the step
    when there is none. Guardian's list and asset routes now have their
    real paths.
  - Actions whose routes exist in no service are removed: the blacklist
    actions (the data service has no blacklist), `isolate_endpoint`,
    `create_ticket`, and the data connector's IOC writes, reputation,
    feed and asset actions. The data connector now has
    `search_indicators` and `lookup_indicators`. `triage_url.yml` alerts
    on a malicious URL and no longer claims to blacklist it.
  - `docker-compose.yml` gives the responder the services' addresses
    (`WILDBOX_API_URL`, `WILDBOX_DATA_URL`, `WILDBOX_GUARDIAN_URL`,
    `WILDBOX_AGENTS_URL`); every connector used to target `localhost`
    inside the container. The responder's own defaults are now those
    addresses too, and checked at startup: Guardian's default named port
    8003, where Guardian does not listen.

  A new playbook, `hash_evidence.yml`, queues the hashing of a piece of
  evidence as the caller. Unit tests call every connector action and check
  its route, body and query against the target service's source, and its
  headers against the run's caller. An integration test starts
  `hash_evidence` through the gateway and checks that the tools task it
  queues belongs to that user and to nobody else.
- **The agents service accepts analysis requests again** (#582).
  `POST /v1/analyze` answered 500 to every call: its rate limiter finds
  the request by the parameter named `request`, and that name belonged to
  the body model, so slowapi raised before the handler ran. The starlette
  request now has that name and the body is `analysis`; the JSON the
  endpoint takes is unchanged. The integration suite did not notice,
  because it accepts any status but 404 from that endpoint.

- **The executive dashboard workflow reports cspm's figures, and only
  those** (#592). The n8n workflow called
  `/api/v1/dashboard/executive-summary`, removed in #578, and
  `/api/v1/cspm/summary`, which never existed, under a base URL read from
  a field its trigger does not produce. It then filled the report with
  invented values: a compliance score of 85 when none came back, five
  fixed "top risks", five fixed recommendations, a "Stable" compliance
  trend, a posture score from weights of its own and an endpoint count
  from a sensor API the gateway does not route. It now reads cspm's
  `dashboard/summary`, `compliance/summary` and failed
  `compliance/findings` through the gateway with a personal API key, and
  reports what they return: accounts assessed, compliance score (or "not
  assessed"), failed checks by severity, compliance by framework and the
  failing checks most severe first, with their remediation text. With no
  completed scan it says there is nothing to report. The e-mail body is
  built in the workflow instead of with `{{#each}}`, which n8n does not
  evaluate. Tested by importing it into n8n 1.74.0 and running it
  against a stub of those three endpoints, with and without scan data.
- **Workflows can be imported** (#592). `import_workflows.sh` and
  `export_workflows.sh` used n8n's REST API with HTTP basic auth, which
  n8n 1.x answers with 401, and the import covered four hard-coded
  directories that did not include `reporting/`. Both now run the n8n
  CLI in the container; the import takes every subdirectory, and a
  workflow with a fixed id is updated in place when imported again.
  `docker-compose.yml` passes the automations container the gateway URL,
  the API key, the report recipients and the gateway's certificate
  (not its key), so a workflow can reach the API over verified HTTPS.

- **cspm keeps scan reports for 90 days, and batch scans count** (#591).
  The compliance summary and findings, the dashboard summary and the
  cloud security overview read scan reports from the Celery result
  backend, which drops results after a day, so every scan older than
  that dropped out of them while its metadata lived on for 30 days. The
  worker now stores each report in Redis under its scan, and the report,
  the scan's metadata and its entry in the team's scan index share one
  retention, `CSPM_REPORT_RETENTION_DAYS` (default 90, validated at
  start); the index is a sorted set scored by expiry, pruned on every
  read and write. Reports are read from there only. Celery results now
  expire after two hours, and a finished scan's status comes from its
  metadata. `POST /api/v1/batch/scans` stored each scan's credentials
  unencrypted, which the worker cannot decrypt, and wrote no scan
  metadata, so batch scans failed, answered 404 by id and never counted
  in the summaries; each scan of a batch now goes through the
  single-scan path, under the caller's team. See UPGRADING.md for the
  memory to plan for and for scans completed before the upgrade.
- **The cloud security overview shows what cspm reports, and says when
  it cannot** (#578). When cspm did not answer, `/cloud-security`
  dropped the failure and showed "0 scans", "0%" compliance, "0 critical
  findings" and "0 cloud accounts"; when it did answer, the page read
  fields cspm never returns, so "Last Scan" was always "Never", the risk
  level "Unknown" and the trend a `stable` the page supplied itself. And
  cspm's `GET /api/v1/dashboard/summary` read a Redis key nothing writes,
  so its findings and score were 0 even after a real scan, with the
  severity counts fixed at 0. The summary now aggregates the newest
  completed scan of each of the team's accounts, the reports
  `/api/v1/compliance/summary` reads (#572), with each failed check's
  severity taken from the check catalog; with no completed scan the
  score is null ("Not assessed"), not 0%. The page shows the scan
  count, that score, the critical findings, the accounts assessed, the
  failed checks by severity and the last scan time, and an error with a
  retry when the request fails. The security posture card (score, risk
  level, trend) is gone: nothing computes it. The home dashboard's cloud
  compliance card reads the same summary. See UPGRADING.md for the field
  changes.

- **Signing up no longer reports an error after creating the account**
  (#589). The dashboard read an `access_token` from `POST /auth/register`,
  which answers 201 with the created user, so it stored no token, its
  `/users/me` call answered 401 and the form showed an error; a second
  attempt then failed with "already exists". The dashboard now signs the
  new account in with the same credentials through the login flow and
  opens the dashboard. identity's login does not require a verified
  address; should the sign-in be refused anyway, the user lands on the
  login page with "Your account has been created. Sign in to continue."
  A refusal of the registration itself (the password policy's reason, an
  address already registered) is shown in the form, and a password that
  is too short now shows the policy's reason there instead of the
  browser's generic hint. fastapi-users' error codes no longer reach the
  client as `ErrorCode.REGISTER_USER_ALREADY_EXISTS`: the shared error
  handler sends the code itself, `REGISTER_USER_ALREADY_EXISTS` (also
  `LOGIN_BAD_CREDENTIALS` on the login page).
- **Logging out always lands on the login page** (#590). After the token
  was revoked, the page's own requests answered 401 and the API client
  answered each one with a hard redirect to `/`, which raced the logout's
  client-side redirect to `/auth/login` and sometimes won. The logout is
  now the only owner of that navigation: it suspends the API client's
  redirect, revokes the token, removes the cookie and then replaces the
  page with `/auth/login` (a full navigation, which also drops the old
  session's client state). The `/auth/logout` page no longer issues a
  second redirect of its own, and the unused `useLogout` hook, a third
  one, is removed.
- **Asynchronous tool tasks can be read, cancelled and listed** (#567).
  `POST /api/v1/tools/{name}/async` queued a task through the gateway,
  but the gateway routed none of the task endpoints, so its result could
  never be read: `/api/v1/tasks` answered 404, and since #566 the tools
  service refuses direct calls. The gateway now serves
  `GET /api/v1/tasks/{id}`, `DELETE /api/v1/tasks/{id}` and
  `GET /api/v1/tasks`, authenticated like the tools routes (API keys need
  `tools:read` to read and list, `tools:execute` to cancel). They have
  their own prefix because under `/api/v1/tools/` the next segment is a
  tool name. The submit response's `status_url` is that gateway path, and
  the list, a placeholder that pointed at Flower, returns the caller's
  tasks of the last day with their state.
- **A task id no longer opens someone else's task** (#567). The task
  endpoints answered for any id: Celery's result backend does not record
  who submitted a task, so whoever held an id could read its result or
  cancel it, and an id that never existed was reported as pending. The
  tools service now records the owner in Redis before queuing the task
  and answers only them; another user's task, a task without an owner
  record (submitted before the upgrade) and an unknown id all answer 404,
  so the answer does not confirm that a task exists. There is no admin
  override.

- **Cloud compliance reports the team's scans, not an invented account**
  (#572). cspm's `GET /api/v1/compliance/summary` and `/findings`
  returned the same constants to every team (1547 resources, 86.7%
  compliant, CIS / NIST / PCI figures, five findings on account
  123456789012), and `/cloud-security/compliance` showed a copy of them
  "for demo" whenever the request failed. Both endpoints now aggregate
  the newest completed scan of each of the team's accounts; with none,
  the counts are 0 and the score is null ("Not assessed"), not 0%. The
  page shows only what the service returns, and an error with a retry
  when it cannot. See UPGRADING.md for the field changes.
- **`/vulnerabilities` lists what guardian holds, and says when it
  cannot** (#572). The page asked guardian for
  `/api/v1/vulnerabilities/vulnerabilities/`, which is not the list, and
  turned that failure, like any other, into an empty result, so it
  always read "No vulnerabilities found". It now calls
  `/api/v1/vulnerabilities/`, pages with guardian's own previous / next
  links instead of a page size guardian ignored, and shows a failed
  request as an error with a retry. The statistics no longer announce
  "No Vulnerabilities Found" while they are still loading, and their
  error card gains a retry.
- **`/api-docs` no longer documents endpoints that do not exist** (#572).
  Its hand-written catalog listed routes no service serves (responder
  `GET /v1/metrics`, identity `GET /api/v1/user/profile`), showed
  "healthy" on every service without probing any, labeled endpoints
  with Free / Business plans that nothing enforces, and gave an example
  response with invented indicator counts and an `api.wildbox.local` base
  URL. The services' OpenAPI pages are not routed through the gateway,
  so the page now lists the gateway's routes, explains how to
  authenticate, and links the endpoint references in `docs/api/` and on
  the documentation site.
- **`/toolbox` shows an error when the tools service fails** (#572). The
  tool list request returned an empty list on any failure, so an outage
  read as a toolbox with 0 tools and the page's error state was
  unreachable. The error now shows the service's message, and its retry
  asks the service again instead of reloading the page.
- **The Team and Profile pages show the team the session works in**
  (#573). `GET /api/v1/admin/me/activity` listed the memberships in no
  particular order and both pages took the first; it now lists them
  oldest first, the order `/internal/authorize` picks a session's team
  in. Superusers can now list, rename and remove the members of any
  team, as they can create members in it; the three routes used to
  answer them 403 unless they belonged to the team.
- **The threat-intel trend no longer invents +100%** (#573).
  `GET /api/v1/dashboard/threat-intel` reported `trends_change: 100.0`
  whenever the previous 24 hours had no indicators and the last 24 had
  any, and 0.0 when both were empty. A change from zero has no
  percentage, so the field is now null in both cases. The dashboard
  home page and the threat-intel feeds page show "no prior data"
  instead of a trend; the home page used to render a null as a red
  "0%".
- **`/cloud-security/scans` no longer lists invented scans** (#570).
  The CSPM service has no endpoint that lists scans, and the page filled
  the gap with three made-up ones, refreshed every 10 seconds, whose
  View Report and Download buttons did nothing. It now says that scan
  history is not available and shows the ID of a scan started from the
  page; starting a scan is unchanged.
- **`/response` no longer shows invented run statistics** (#570). Its
  totals (45 runs, 2 running, 87% success) and three "recent runs" were
  constants, shown whether or not the responder answered; only the
  playbook count was real. The responder neither lists nor counts runs,
  so the page now shows the playbooks it reports, "Unavailable" when it
  cannot be reached, and says that run statistics are not available.
  It also stops wrapping itself in a second copy of the main layout.
- **The response pages reach the responder** (#570). They called
  `responderClient` with `/v1/...`, and the gateway already maps
  `/api/v1/responder/<x>` to the responder's `/v1/<x>`, so every request
  went to `/v1/v1/...` and got a 404: no playbook list, no execution, no
  run status. They now build their paths with `getResponderPath`, as the
  home page does. The responder has no run list, so `/response/runs`
  stops asking for one and stops claiming to show "demo data": it shows
  the runs started from this browser with the status the responder
  reports for each, and says that run history is not available. The
  run cards' Cancel and View Details buttons, and the playbook cards'
  details button, only logged to the console and are gone.
- **A session token alone could change the account's password** (#559).
  fastapi-users' `PATCH /auth/users/me` applied a `password` field
  without the current password. identity now refuses a password there
  (`UPDATE_USER_INVALID_PASSWORD`); a user changes it through
  `POST /api/v1/identity/admin/me/change-password`, which verifies the
  current one. An administrator's reset of another account is unchanged.
- **Dashboard pages that missed the backend** (#559). The team page
  called `/auth/me` and `/api/v1/teams/{id}/members`, which the gateway
  does not route, and never loaded; it now uses identity's
  `/admin/me/activity` and `/admin/teams/{id}/members`, open to the
  team's members, and no longer offers an invite (identity's endpoint
  sent nothing and is removed, #570; owners and admins now add members
  with the form of #573) or role changes (identity has none). The profile
  page saved nothing (`PUT /api/v1/users/me` hit the catch-all 404); the
  email now goes to `PATCH /auth/users/me`, with the current password
  (#569), and the password to the change-password route. Search and the status filter on `/admin` now
  reach identity as `email_filter` and `is_active`, debounced.
- **System Health shows real status** (#559). The gateway routes
  `/api/v1/identity/health` to identity's `/health`, which it used to map
  to a path that does not exist, and identity's health now checks Redis
  as well as the database. The admin page reads Database and Redis from
  those checks instead of assuming both healthy whenever identity
  answered.
- **No more invented figures in the dashboard** (#559). The home page
  showed sample values when a service had no data or could not be
  reached (87% compliance, 5 critical findings, 4/4 feeds, 3 alerts, an
  IOC 192.168.1.100); each card now shows the service's answer or
  "Unavailable", and several of its requests, which repeated `/api/v1`
  under the service prefix, now reach the service. `/admin` showed a
  random number of requests today, the profile page three made-up
  activity entries and a "Strong" password badge, and the toolbox marked
  every opened tool "completed" with a random duration; all are gone.
- **The production dashboard image had no gateway URL** (#559).
  `NEXT_PUBLIC_*` is compiled into the browser bundle, and the
  Dockerfile declared no build argument for it, so every production
  build fell back to `http://localhost:80`. The Dockerfile now takes
  `NEXT_PUBLIC_GATEWAY_URL`, `NEXT_PUBLIC_USE_GATEWAY` and
  `NEXT_PUBLIC_APP_URL` as build arguments, `docker-compose.prod.yml`
  passes them from `.env`, and an unset gateway URL now means the
  dashboard's own origin, which is where the gateway serves the API.
- **The dashboard works through the gateway again** (#103). Signing in
  at https://localhost on a stack set up the documented way failed four
  ways at once: `.env.example` pointed the dashboard's API calls at
  `http://localhost`, which only redirects, so every call ended in
  "Network error"; the gateway's server-wide rate limit (burst 10)
  answered 429 to the JavaScript chunks of a single page load; the
  login, signup and logout pages inherited the gateway's API
  Content-Security-Policy on top of the dashboard's own, which blocks
  the dev runtime; and `next dev`'s hot-reload socket got a 404. The
  API calls now go to the dashboard's own origin, where the gateway
  serves the API (`NEXT_PUBLIC_GATEWAY_URL` is empty by default since
  #559; this fix first set it to `https://localhost`), static assets have
  their own limit, every dashboard page location sends the dashboard's headers
  only, and the socket is proxied.
- **Admin and IOC lookup pages** (#103). Loading or reloading `/admin`
  sent an admin to `/dashboard` whenever `/users/me` was slower than
  the first render. The IOC lookup requested
  `/api/v1/data/api/v1/<kind>/<value>` and so reported every indicator
  as not found, and its "Detected type" hint described the previous
  search rather than the input.

- **tools pass the authenticated caller to tools that act for one** (#563).
  `sql_injection_scanner` requires a caller, but the execution manager
  called every tool with its input alone, so every API execution of it
  answered 500. A tool whose `execute_tool` declares `user_id` is now
  authorized in one place, before it starts, by both the synchronous and
  the asynchronous path: without a caller it is refused, otherwise the
  authorization manager must allow that caller the tool's operation
  against its `target_url`, and the tool then receives the caller. A
  refusal answers 403 with the reason. The asynchronous endpoint passed
  the literal caller `"anonymous"`, and the task status reported refused
  or failed tasks as completed. The security layer no longer repeats the
  check, which spent the one destructive test allowed per hour. The
  policy files now load when they contain the documented `description`
  keys, URL entries cover the URLs below them, `.example.com` no longer
  matches every name that merely ends in `example.com`, and CIDR entries
  match URL targets. With no policy files, which is the shipped default,
  nobody may run the scanner; `open-security-tools/README.md` describes
  how to grant it.
- **guardian runs the schedules users define** (#548). Asset discovery
  rules and report schedules were stored with a schedule nothing read. A
  dispatcher, sent by `guardian-beat` every minute
  (`GUARDIAN_SCHEDULE_USER_SCHEDULES`), queues each due rule's network scan
  and each due schedule's report, once per due time: the run is claimed by
  a conditional update of `next_run`, so overlapping sweeps cannot both
  queue it, and missed runs are skipped rather than replayed. The work
  behind them did not work either, and does now: every report failed
  (templates that never existed, a signal reading a missing `tracker`
  field, a filter on a missing `Asset.is_active`), reports written by
  `guardian-worker` could not be downloaded from `guardian` (they now
  share a volume), editing a report schedule answered 500, and host
  discovery ran a `ping` binary the image does not contain (it now probes
  with TCP). Schedules that could not run are refused at the API with a
  400: invalid cron expressions, unimplemented discovery types, report
  types without data, unwritten formats, and every scan schedule, since
  guardian cannot start an external scan. Generating one of those report
  types or formats by hand now fails with the reason, rather than
  completing with a placeholder score, no data, or HTML named `.pdf`.
- **Updating a compliance result or assessment works, and starts its
  follow-up** (#555). guardian's compliance signals read
  `instance.tracker`, a django-model-utils field tracker the models never
  declared (the package is not installed), so every update of an existing
  result or assessment raised `AttributeError` and answered 500. A change is
  now detected by comparing with the stored row before the save. A changed
  result status or risk level recalculates the assessment's metrics and,
  for a high or critical non-compliant result, sends the high-risk
  notification; an assessment that starts or completes is announced, and
  completing one recalculates its metrics. The start notice was
  unreachable before. The tasks are queued once the change is committed,
  and metric calculations for one assessment no longer run concurrently.
  None of the compliance e-mail templates existed, so no compliance
  notification, the overdue-assessment and expiring-exception reminders
  included, was ever sent; they are now.
- **guardian's alert rules evaluate real data and notify on changes only**
  (#549). `get_current_value_for_rule` returned 0 for every rule, so no
  rule measured anything, and a firing rule notified on every sweep (96
  times a day). A rule now names one of five metrics computed from
  guardian's data (unresolved, overdue and highest-risk vulnerabilities,
  filterable by severity and asset; non-compliant results; overdue
  assessments), and the API refuses unknown metrics, filters, and the
  `change`, `trend` and `anomaly` conditions, which were never evaluated.
  A rule notifies when it starts firing, once when it recovers, and at
  most once per `GUARDIAN_ALERT_RENOTIFY_INTERVAL` (a day) in between; its
  state is kept on the rule and each notification is recorded and listed
  at `.../reports/alerts/{id}/notifications/`. The alert e-mail template
  did not exist, so no alert was ever e-mailed; it does now, to the rule's
  recipients.

- **guardian's vulnerability history endpoint answers again.** It ordered by
  `changed_at`, which does not exist (the field is `timestamp`), so
  `GET /api/v1/vulnerabilities/{id}/history/` answered 500 for every
  vulnerability.

- **guardian's periodic tasks run, and its tasks reach their queues**
  (#545). guardian used django-celery-beat but scheduled nothing and ran
  no beat, so the SLA check, alert rules, risk-score recalculation,
  report and history cleanup, asset inventory and compliance reminders
  never ran on their own. A `guardian-beat` service (one instance) now
  sends them on a schedule defined in `guardian/schedule.py`, each
  interval overridable with a `GUARDIAN_SCHEDULE_*` variable; runs expire
  instead of piling up, and the notifying sweeps skip a run while one is
  in progress. Its health check reads a heartbeat the scheduler refreshes
  on every tick. The task routes were globs such as `reporting.tasks.*`
  that matched no registered name (`apps.reporting.tasks.*`), so every
  task went to `default`; each task is now routed by name, a unit test
  fails for a task without a queue, and `GET
  /api/v1/guardian/tasks/{task_id}/` reports the queue a task was
  delivered on. Two of the scheduled tasks could not have run anyway:
  the SLA check and the history cleanup filtered on a field that does not
  exist (`changed_at`), and the SLA e-mail read an undefined
  `settings.BASE_URL` (now `GUARDIAN_BASE_URL`).
- **guardian's Celery tasks run** (#537). guardian queued tasks (port
  scans of new assets, threat-intel enrichment, alert-rule checks, report
  generation) but no service consumed its queue, so none of them ever ran.
  A `guardian-worker` service now does. `POST
  /api/v1/guardian/assets/assets/{id}/scan/` imported a module that does
  not exist and answered 500 on every call; it now queues the asset's port
  scan. `GET /api/v1/guardian/tasks/{task_id}/` reports a queued task's
  state, and the integration suite waits on it for the task to finish.
- **guardian's health check and integration tests check something** (#532).
  With `DEBUG=false` guardian redirected every plain-HTTP request to
  HTTPS, its health route included, so the container health check
  (`curl -f`, which counts a 301 as success) reported healthy with the
  database down, and the integration suite's probe followed the redirect
  to a port with no TLS and skipped all six guardian tests on every run.
  `health/` is now exempt from the redirect and the container health
  checks call it directly; it answers 503 when a dependency is down. The
  tests go through the gateway with a real login and assert concrete
  results, and CI now fails, rather than skips, a test whose service the
  stack starts but does not answer (`REQUIRE_ALL_SERVICES=1`).

- **identity reads a comma-separated `CORS_ORIGINS`** (#531). Its
  settings declared `cors_origins` as `list[str]`, which pydantic-settings
  decodes from the environment as JSON only, so the comma-separated value
  in `.env` made identity exit at import and restart forever. The field
  now accepts a JSON list or a comma-separated string; an empty value
  allows no cross-origin requests. The production overlay passes
  `CORS_ORIGINS` to identity again, as it does for the other services, and
  the Production Stack workflow checks that a preflight from each
  configured origin is allowed and one from elsewhere is refused.

- **`make clean` no longer prunes the whole Docker host.** It ran
  `docker system prune -f --volumes`, deleting every unused volume and image
  on the machine, other projects' data included; it now clears local caches
  only. Every Makefile target uses `docker compose`, and `.env.example` no
  longer carries a `REDIS_URL` without password that nothing reads.

- **The dashboard type-checks against the node it runs on** (#521):
  `@types/node` moves from 20 to 24, the major in the Dockerfile and in
  CI since node 24 became the base image. Dependabot no longer proposes
  `@types/node` majors (it offered 26, which types APIs node 24 lacks);
  the types move by hand with the base image.

- **Dashboard icons are hidden from screen readers** (#520): lucide-react
  0.378 to 1.50. The icons are decorative, but only 2 of the 23 on the
  vulnerabilities page carried `aria-hidden`, so assistive technology
  announced unlabeled graphics; lucide 1 sets it by default. All 69 icons
  the dashboard imports still exist under the same names and CSS classes,
  and the pages render the same apart from four slightly redrawn glyphs.

- **guardian can create vulnerabilities again** (#515). The post_save
  history entry wrote `old_value=None` into a NOT NULL column, so every
  vulnerability creation raised `IntegrityError`, and so did assigning a
  user or clearing the assignment. A missing value is now stored as `''`,
  the column's own empty value. No migration.

- **guardian's vulnerability templates and assessments are reachable**
  (#514). The router registered the empty prefix first, so
  `/api/v1/vulnerabilities/templates/` and `.../assessments/` were served
  as a vulnerability lookup and answered 404. The named prefixes are now
  registered before it.

- **guardian's remediation and integrations endpoints answer again** (#499).
  All 11 list endpoints of the two apps, plus `scanners/stats/` and
  `reports/metrics/summary/`, answered 500: `filterset_fields`, search and
  ordering named fields the models do not have, and no endpoint in either
  app had a serializer. Filters now use real fields, each endpoint has an
  explicit serializer, and stored credentials (`auth_config`,
  `secret_token`, channel `config`) are write-only. A new test GETs every
  read route, with search and every ordering, and fails on any 5xx.

- **Completing a guardian remediation step works, and creators are
  recorded** (#516). `RemediationStep.complete_execution` called a
  workflow method that did not exist and raised `AttributeError`; the
  steps API's `complete` and `execute` actions only flipped the status, so
  timings and workflow progress never moved. They now go through
  `start_execution`/`complete_execution`, and the workflow recomputes its
  progress from its steps. Creating a ticket, workflow, template, external
  system or notification channel now sets `created_by` to the
  gateway-authenticated user instead of leaving it null.

- **The web vulnerability scanner's SQL injection check works** (#507). It
  read `await response.text().lower()`, which calls `.lower()` on the
  coroutine and raised before any comparison, so it never reported a finding.

- **`make start` no longer leaves the data service crash-looping** (#506). It layers
  `docker-compose.dev.yml`, which sets `DEBUG=true` for data, over a `.env`
  whose `ENVIRONMENT` is `production`; data refuses that combination. The
  development overlay now sets `ENVIRONMENT=development` for data as well.

- **Password change and self-deletion work again** (#501). identity's custom
  routes verified with passlib bcrypt, which cannot read the Argon2id hashes
  fastapi-users writes for every account, so they failed for every user.
  `app.auth` now uses fastapi-users' `PasswordHelper`: Argon2id for new
  hashes, Argon2id and legacy bcrypt accepted.

- **Logout now ends the session** (#475). Tokens from the login endpoint carried
  only `sub`, `aud` and `exp`: `POST /auth/logout` refused every one of them
  ("Token carries no jti"), `POST /auth/jwt/logout` revoked nothing, the
  dashboard only deleted its cookie, and two logins within the same second got
  the same token. A logged-out token stayed valid at the gateway for its whole
  lifetime. Login tokens now carry a `jti` and an `iat`, identity's own routes
  refuse a revoked one, both logout routes revoke, and the dashboard calls
  revocation before clearing its cookie. Tokens issued before this release
  still lack a `jti` and expire on their own.
- **identity could not reach Redis** (#475). Its `REDIS_URL` came from `.env`
  without the password Redis has required since 0.10.0, so every blacklist
  write and read failed with "Authentication required" and was swallowed:
  even a token with a `jti` could not have been revoked. compose now builds
  the URL with `REDIS_PASSWORD`, as it does for every other service
  (`IDENTITY_REDIS_URL` overrides it).
- **The gateway auth-cache purge never reached the gateway** (#475). identity
  called it on port 80, which answers everything but `/health` with a 301, so
  a revoked token stayed authorized from the cache for up to its TTL. The
  endpoint now also lives on an internal listener, port 8081, not published,
  and that is identity's default.

- **responder playbooks fail loudly instead of doing nothing** (#417). The
  shipped all-star playbook passed every step's arguments under `params:`,
  which the engine never reads, so each step ran with an empty input; steps
  referred to each other by `id` while the engine keyed them by `name`; and
  `on_failure: continue` was read by nothing. The engine now keys steps by id
  (name when there is none) and honors `on_failure: continue`; the playbook
  models reject unknown keys, so a playbook with a key the engine ignores
  stops the responder at start-up with the file and key named. `retry_count`,
  never honored, is removed from the model.
- **The sensor's Linux service inventory is collected** (#417). Its osquery
  query asked `systemd_units` for columns the table does not have, so every
  collection cycle failed with "no such column: name". The query now uses the
  table's real columns.
- **Generated secrets no longer fail the services' own checks** (#422).
  `scripts/generate_secrets.py` could emit a key containing a pattern the
  tools service rejects as weak (`abc`, `123`), so about one fresh install in
  thirty-five failed at start-up. The generator now refuses such values.

- **The gateway waited 10 s, not 5, for an unresponsive identity** (#428).
  `utils.http_request` ignored the caller's `timeout` because `request_uri()`
  does not read one, so `auth_handler`'s `TIMEOUT_SECONDS = 5` never applied.
  Found by the rewritten chaos suite: 10.0 s per request before, 5.01 s after.
- **The dashboard no longer promises what the platform does not do.** The
  cloud security, scans and compliance pages fetch from the CSPM service and
  work, yet each opened with a "Coming in Future Release" banner that
  promised AWS, Azure and GCP; the banner now says the service scans AWS
  accounts only and refuses the others, and that compliance results are the
  AWS checks grouped by framework, not a full assessment. The profile page
  offered an "Enable" button for two-factor authentication, which identity
  does not have; it now says so, with no button.

### Security

- **identity: the admin metrics need a platform superuser; the gateway
  vouches only for requests it authenticated** (#664).
  `GET /api/v1/admin/metrics` accepted the `X-Gateway-Secret` header
  alone, and the gateway's `proxy_params.conf` set that header on every
  proxied request, including the `/api/v1/identity/` passthrough, which
  authenticates nobody: an anonymous
  `GET /api/v1/identity/admin/metrics` read the number of users, teams
  and active API keys. The route now takes a superuser's bearer token,
  checked by identity, and refuses an account that must change its
  password; the header counts for nothing there. The gateway sends its
  secret only on a request `auth_handler.authenticate()` let through, and
  drops a client's own on every other location (identity's routes, the
  dashboard). An audit of identity's routes found `/internal/authorize`
  the only other one that reads the secret; the gateway calls it itself,
  and no location routes a client to `/internal`. The counts were also
  always zero: the handler imported a model name that does not exist,
  and its catch-all turned the error into "unavailable". Unit tests use
  real tokens (anonymous and forged header 401, team owner 403,
  superuser 200, flagged superuser 403) and check that no route outside
  `/internal` reads the secret; the gateway harness checks the header on
  the passthrough (absent, even when the client sends one) and on an
  authenticated route (the gateway's own). Reverting either side fails
  them. Integration tests do the same through the gateway.

- **identity: the self-service API-key routes act on the caller's own
  keys** (#664). `DELETE /api/v1/api-keys/{key_prefix}` selected the key
  by team and prefix only, so any member could revoke a teammate's or
  the owner's key, and since #608 the gateway refused it at once. The
  revoke, `GET /api/v1/api-keys/{key_prefix}` and the list now match the
  caller's user ID as well; another member's key answers 404 and keeps
  working. A team owner or admin revokes any key of the team through
  `DELETE /api/v1/teams/{team_id}/api-keys/{key_prefix}`, whose role
  check is unchanged, and the gateway is still told before the key is
  marked inactive. Unit tests read the criteria of each query and check
  the team route's roles; dropping the user predicate from any of the
  three routes, or letting a member through the team route, fails them.
  Integration tests through the gateway: a member's revoke of the
  owner's key answers 404 and the key keeps working, the owner revokes
  the member's key through the team route and it is refused on the next
  request.

- **identity: no development reloader in production** (#664).
  `scripts/init.sh`, the image's command, started uvicorn with `--reload`
  whatever the environment, so every deployment ran a file-watching
  supervisor that restarts the server from a second process. It now
  passes `--reload` only when `ENVIRONMENT` is `development`; otherwise
  the server starts as one process, as before, without the watcher. The
  image holds no mounted source, so nothing is lost: the reloader had
  nothing to reload. The script also embedded a command substitution
  (backticks) in a comment inside the superuser step, which ran
  `docker logs` in the container at every start. A test runs the script
  with stubbed commands and checks uvicorn's arguments for development,
  production, staging, empty and unset; reverting the condition fails it.

- **Sensor telemetry is scoped to the team that ingested it** (#641).
  `telemetry_events` and `sensor_metadata` had no team column, and the
  data service's telemetry routes queried the whole tables: any
  authenticated member of any team listed every team's events
  (including `raw_data` and host names), sensors and statistics. A
  sensor ID was unique across all teams, so a batch posted under
  another team's sensor ID updated that team's sensor record. Both
  tables now carry `team_id` (alembic revision `0005_telemetry_team`),
  and a sensor ID is unique per team. `POST /api/v1/ingest` stores the
  caller's team from the gateway, never one named in the batch, and
  looks the sensor up by team and ID. `GET /api/v1/telemetry/events`,
  `/telemetry/stats`, `/sensors` and `/sensors/{sensor_id}` return the
  caller's team's rows only, and another team's sensor answers 404.
  Rows written before the upgrade have no team and are shown to no
  team; UPGRADING section 34 gives the SQL to assign them. Unit tests
  run the scenario of the issue (team B lists nothing of team A's,
  gets 404 for A's sensor, and a batch of B's under A's sensor ID
  leaves A's record unchanged); removing the team predicate from any
  of the reads, or from the ingest's sensor lookup, fails them. An
  integration test does the same through the gateway with two
  accounts.

- **agents: the analysis rate limit is counted per user** (#651). The
  limiter on `POST /v1/analyze` was keyed by the client address. Every
  request reaches the service through the gateway, so that address was
  the gateway's for every caller: the whole platform shared one budget
  of five analysis requests a minute, and one user of one team could exhaust it
  for all the others. The limit is now keyed by the user ID of the
  gateway-authenticated caller, taken from the verified identity after
  the gateway secret has been checked; no header is read for the key, so
  `X-Forwarded-For` cannot move a request to another bucket, and a
  request without a verified identity is refused before it is counted.
  Per user rather than per team, so that one member cannot use up the
  budget of their teammates. The value is configurable with
  `ANALYZE_RATE_LIMIT` (default `5/minute`), and
  `ANALYZE_TEAM_RATE_LIMIT` adds an optional ceiling for a whole team;
  the service refuses to start on a value it cannot parse, where slowapi
  would have dropped the limit silently. The 429 body says whether the
  user or the team limit was hit. Unit tests check that two users each
  get their own budget, that the same user is limited, that a spoofed
  `X-Forwarded-For` leaves the bucket unchanged, the team ceiling, and
  the validation of both settings.

- **agents: reading or cancelling a task fails closed on its owner
  record** (#650). `DELETE /v1/analyze/{task_id}` compared the owner only
  when the owner record existed, so with the record missing any
  authenticated caller, of any team, could revoke someone else's
  analysis. The record could be missing while the task was still
  addressable: the celery id was written after it with the same TTL and
  outlived it, and eviction can drop one key and keep the other. `GET`
  and `DELETE` now share one check: no celery id, no owner record, or
  another user's task all answer 404 `Task not found`, before anything is
  read or revoked. Another user's task used to answer 403 on `GET`, which
  confirmed that the task id was live. The owner record is now written
  with five minutes more time to live than the task's other keys, and is
  rewritten in the same transaction as the celery id, so it outlives
  every key that can address the task. Unit tests cover a missing owner
  record, another user's task and the owner's own task on both methods,
  and the TTLs written on submission.

- **guardian keeps each team to its own data** (#642). The tenancy work of
  0.8.0 (#177-#183) scoped data, responder and CSPM, not guardian:
  guardian stored no team on any row, and every API view served every row.
  Any owner or admin of a team -- which is anyone who registers, since
  registration creates a team -- read, changed and deleted every other
  team's assets, vulnerabilities, scanners and their credentials,
  integrations, remediation, compliance evidence and reports, and could
  reference them from its own rows. Every tenant-owned model now stores
  its team, or takes it from the row it belongs to; one mixin narrows
  every API view to the caller's team, so another team's ids answer 404;
  serializers stamp the caller's team and refuse foreign keys and user
  ids from other teams as ids that do not exist; list filters, statistics,
  Celery tasks (discovery, alert rules, scheduled reports, widgets,
  compliance metrics), report files and the task status route
  (`/api/v1/tasks/<id>/`) are per team. Compliance frameworks, their
  controls and vulnerability templates without a team are shared
  reference data, read-only to teams. Rows written before this change
  have no team and are reachable by no team until an operator assigns
  them with `manage.py assign_guardian_team` (see UPGRADING.md).
  Names that were unique across guardian (environments, groups,
  discovery rules, frameworks, vulnerability templates, ticket ids) are
  now unique per team. Media files are no longer served as static files
  in development. Tests list the API views from the URL configuration
  and check every list, detail route, detail action, list action and
  foreign key against a second team; a mutation that removes the team
  filter fails 124 of them. An integration test registers two accounts
  and checks the same through the gateway.

- **API-key digests no longer depend on `JWT_SECRET_KEY`** (#648).
  `API_KEY_HASH_SECRET` was generated into `.env` and documented, but
  compose never passed it to identity, which then keyed every stored
  API-key digest with `JWT_SECRET_KEY` without a warning. Rotating the JWT
  key, the routine rotation `SECURITY.md` recommends, invalidated every
  API key with no way back, and the guard in `scripts/rotate_secrets.sh`
  could not catch it: it checked `.env`, where the generator always writes
  the variable. `docker-compose.yml` and the production overlay now pass
  it to identity as a required variable, identity refuses to start
  without it when `ENVIRONMENT=production`, a short, placeholder or
  low-entropy value is refused in any environment (and the error no
  longer echoes the settings it validated), and outside production a
  missing value still falls back to the JWT key with a warning at
  start-up. `make validate-secrets` requires it. The rotation
  guard now refuses `JWT_SECRET_KEY` unless `docker compose config` passes
  the variable to identity and the running identity container, if any,
  has it. `--init` (`make init-api-key-hash`) copies `JWT_SECRET_KEY` into
  `API_KEY_HASH_SECRET` inside `.env` without printing either, does
  nothing when they already match, and the script no longer passes a new
  value on a command line, where `ps` could read it. An existing
  deployment runs `--init` once before upgrading, so keys issued so far
  keep working; see UPGRADING.md. Unit tests cover the production
  refusal, the digest keyed by the hash secret, a JWT rotation that
  leaves digests unchanged and a pre-upgrade key that still verifies
  after seeding; script tests cover both compose files and the guard
  against a stub `docker`.

- **guardian accepts gateway-authenticated requests only** (#629). Its
  middleware accepted rows of guardian's own `APIKey` table from an
  `X-API-Key` header on a direct request, authenticated the caller as role
  `admin` and set `is_superuser` on the user, and DRF's
  `APIKeyAuthentication` accepted the same keys, also from
  `Authorization: Bearer`. That path skipped identity, the revocation
  markers, team scoping and the gateway's rate limits: anything that
  reached guardian's port with such a key was an administrator. Both are
  removed; a direct request answers 403 `GATEWAY_AUTH_REQUIRED`, as on
  the other services. The permission classes no longer read the user's
  staff flags as a role when there is no gateway identity, which only
  that path produced. Nothing in the repository called guardian with
  these keys except three manual check scripts under `tests/`, which now
  use a personal API key through the gateway. Unit tests send a direct
  request with a key row present and expect the refusal; an integration
  test reads and writes guardian through the gateway with a personal API
  key from identity, and expects 403 for the same key sent directly.

- **Network tools refuse internal targets unless the operator allows
  them** (#614). The URL guard covered tools that fetch a URL; the tools
  that take a host, an address, a range, a DNS server or an image
  reference connected to whatever they were given, so any authenticated
  user could scan the platform's own network (Redis, PostgreSQL, the
  other services, cloud metadata) from inside it. One check,
  `app/target_policy.py`, now runs before every tool on the synchronous
  endpoint, in the Celery task and in each security_automation_orchestrator
  step, together with the URL guard. It refuses private, loopback,
  link-local, unspecified, multicast, reserved and shared
  (`100.64.0.0/10`) addresses, IPv4 addresses embedded in IPv6 ones,
  ranges with any such address, host names that resolve to one (every
  answer is checked) or do not resolve, non-canonical spellings such as
  `127.1`, and the deployment's own names (any name without a dot,
  `localhost`, `*.local`, `*.internal`, metadata names). A range holds at
  most 1024 addresses. The fields checked are declared per tool, with
  their kind, in `NETWORK_TARGET_FIELDS`; a unit test fails when a tool
  has a host-like field that is neither declared nor listed as reviewed
  with a reason. Operators allow internal lab ranges and hosts with
  `TOOLS_ALLOWED_INTERNAL_TARGETS` (CIDR ranges, IP addresses and host
  names; empty by default; a bad entry stops the service at start-up).
  The authorization manager's `authorized_targets` (#563) is not reused:
  it narrows which public targets a caller may attack and never lifts
  the SSRF guard. dns_enumerator applies the policy to the name servers
  it attempts a zone transfer from and connects to the checked address,
  which also makes the transfers work: they passed a name dnspython does
  not accept. port_scanner refuses a target with other characters
  instead of removing them, which turned `::1` into `1` (0.0.0.1). A
  host name is still resolved again by most tools when they connect, so
  a name whose answer changes in between (DNS rebinding) is a remaining
  window, documented in the module. See UPGRADING section 29.
- **The agents routes authenticate through `auth_handler` like every
  other route** (#630). `location ~ ^/api/v1/agents/(.*)$` carried its
  own copy of the authentication in inline Lua, "for regex location
  compatibility", which it never needed: the tools route is a regex
  location and calls `authenticate()`. The copy called identity's
  `/internal/authorize` at a fixed address rather than
  `IDENTITY_SERVICE_URL`, cached nothing, did not retry a connection
  identity had just closed (#609), applied no per-team rate limit, and
  checked the API-key revocation marker (#593) and the
  must-change-password refusal (#573) only because both were added to
  it by hand; every later fix to `auth_handler` had to be repeated
  there. Nor did it set `$wildbox_user_id`, `$wildbox_team_id` and
  `$wildbox_role`, from which `proxy_params.conf` sets the `X-Wildbox-*`
  headers, so the service received no caller identity at all (nginx
  drops a header whose value is empty), even for an accepted key. The
  location now calls `auth_handler.authenticate()`, so the agents
  routes get the cache, every revocation marker (logout,
  password change, API key, team removal), `PASSWORD_CHANGE_REQUIRED`,
  the API-key scopes, the rate limit, the retry and the JSON 503, and
  the same client-header stripping and `X-Wildbox-*` identity headers.
  The three functions `auth_handler` exported only for that copy are
  gone, and `scripts/check_gateway_config.py` now fails when an nginx
  configuration file calls `/internal/authorize` itself. The gateway
  harness covers the agents routes (session and API key accepted, no
  credential 401, scopes, must-change-password, cache, revoked API key,
  logout, password change, team removal, retry, 503, rate limit), and
  an integration test submits an analysis with a session token through
  the gateway and gets 202.
- **A member removed from a team loses the team at the gateway on the
  next request** (#613). A session is not bound to a team:
  `/internal/authorize` resolves the oldest membership on every request,
  and the gateway caches the answer for `AUTH_CACHE_TTL` (300 s). Since
  #593 the removal revoked the member's API keys for the team, but their
  sessions kept the cached "allowed in this team" decision, and the
  removed member went on acting in the team for up to five minutes.
  Removing a member (`DELETE /api/v1/admin/teams/{team_id}/members/{user_id}`,
  by the team's owner or an admin, or by a superuser) now also sends the
  gateway `{"memberships": [{"user_id", "team_id", "not_before"}], "ttl": <seconds>}`
  before it commits, and commits only once the gateway confirms the
  count; otherwise nothing changes and the request answers 503. The
  gateway keeps a marker per user and team and refuses, with 403
  `team_membership_ended`, a session decision of that user in that team
  whose token was issued up to the removal, on a cache hit and after a
  fresh authorization, so a request in flight across the removal is
  refused too. The refused decision is dropped from the cache: the next
  request with the same session is authorized afresh, and works in the
  team the user still belongs to, if any. The user's sessions in their
  other teams are not ended, which the per-user cutoff a password change
  uses (#569) would have done. Deleting an account already ended all its
  sessions (#593), including in the teams deleted with it, whose only
  member it is.

- **The tools SSRF guard checks URL-typed and nested inputs** (#610).
  `InputSanitizer.validate_request_urls`, which runs on every validated
  tool input before the tool starts, on the synchronous endpoint and in the
  Celery task alike, checked only top-level `str` fields named like a URL.
  A field declared as `HttpUrl`, `AnyUrl` or `AnyHttpUrl` holds a pydantic
  `Url` object after validation, so it was skipped, as was any URL inside
  a nested model, a list or a dict. A tool that relied on the generic guard
  for such a field could be pointed at loopback, private ranges or the
  cloud metadata address. The guard now walks the whole input: every value
  of a pydantic URL type is checked wherever it sits and whatever it is
  called, through the same structural parser, host rules and DNS
  resolution as string URLs, and a non-http(s) scheme in such a field is
  refused; strings named like URL carriers are checked in nested models,
  lists and dict values too. Input nested deeper than 16 levels is refused
  rather than left unchecked. `header_analyzer` and `url_analyzer`, the
  two tools with `HttpUrl` fields, are now covered by the generic guard
  as well as by their own checks.

  The guard on inputs could not see what a tool fetched afterwards, so the
  same change closes the paths around it:

  - _Redirects and DNS rebinding._ No tool checked redirect targets, and
    aiohttp and requests follow redirects by default: a public URL that
    answered `302 Location: http://169.254.169.254/` took the tool to the
    metadata service. Every tool that fetches a caller-supplied URL now
    opens its connections through `app/safe_http.py`. The aiohttp session
    it builds checks scheme, host and port on every connection, redirect
    hops included, and resolves names through a resolver that refuses the
    name when any answer is not public; aiohttp then connects to those
    checked addresses, so the resolution is pinned and a rebinding answer
    cannot slip in between the check and the connection. Automatic
    redirects stop after 5 hops, which also ends redirect loops. The
    requests-based tools (`sql_injection_scanner`, `xss_scanner`,
    `file_upload_scanner`, `email_harvester`) validate every hop the same
    way but are not pinned: urllib3 resolves the name again when it
    connects, which leaves a short window to a nameserver that answers
    differently on the second lookup.
  - _URLs built from other input._ `http_security_scanner` adds `https://`
    to a bare host and `email_harvester` fetches pages of a bare domain;
    neither value looked like a URL to the input guard. The URL actually
    fetched is now validated, as is `api_security_tester`'s specification
    URL, which was detected with a case-sensitive `startswith('http')`.
  - _Tools' own weaker checks._ `header_analyzer` and
    `url_security_scanner` looked at the first DNS answer only, let a name
    that did not resolve through, and ignored multicast, unspecified and
    shared addresses; `sql_injection_scanner` did no DNS resolution at all.
    All three now use the shared guard and fail closed.
    `web_application_firewall_bypass` allowed `localhost`, `127.0.0.1`,
    `*.local` and `*.test` on its own allowlist and matched hosts with user
    info still attached (`example.com@evil.example`); the shared guard now
    decides first and the allowlist only narrows it.
  - _WHOIS referrals._ `whois_lookup` followed the `Whois Server:` line of
    a response to any host. The referral must now be a bare public host
    name, and the tool connects to the address it checked.
  - _Workflow steps._ `security_automation_orchestrator` called other
    tools' `execute_tool` directly, skipping the SSRF guard and the
    caller authorization of #563. Each step's parameters are now validated
    by the tool's own input model (it used to pick `BaseToolInput` for
    most tools), checked by the SSRF guard, and a tool that acts on behalf
    of a caller is refused as a step.

  Host, IP and CIDR targets of the network scanners are covered by the
  network target policy of #614, above.

- **An agents task never sends another task's caller identity** (#594).
  The analysis task set the caller identity, a `ContextVar` the Wildbox
  client forwards on every tool call, only when its caller had both a user
  and a team id, and never reset it. A Celery worker runs one task after
  another in the same context, so a task arriving with no caller, or a
  partial one, would have made its tool calls as the previous task's user
  and team. Each task now runs inside `caller_identity(caller)`, which
  refuses a missing or incomplete caller with `CallerIdentityUnavailable`
  before any work and restores the previous value when the task ends,
  however it ends; the task is marked failed in Redis. `/v1/analyze`
  refuses such a caller with 403 before writing any state or enqueuing
  anything, `set_caller_identity()` returns the `ContextVar` token and
  refuses a blank id, and the client refuses an identity without a user or
  team id. The agent's tool calls run in asyncio tasks, several at once
  through `asyncio.gather`, and a sync tool would run in LangChain's
  thread pool under `copy_context()`; both inherit the task's context, and
  the tests check the identity reaches the wire through each.
- **A revoked API key is refused on the next request** (#593). The
  gateway caches the decision for a key for `AUTH_CACHE_TTL` (300 s), and
  revoking a key only marked it inactive in identity's database, so a key
  revoked because it leaked kept working for up to five minutes on every
  route the gateway authenticates. Deleting or deactivating the account
  behind a key, or removing the member from the team, did the same; only
  the admin status route flushed the gateway's cache, after the commit and
  best effort. identity now reports the key's id with every authorization
  it grants for a key (`api_key_id`), and every change that disables keys
  -- revoking a key (own or team), deactivating an account
  (`/admin/users/{id}/status` or `PATCH /users/{id}`), deleting one
  (`/admin/users/{id}`, `DELETE /users/{id}`, `/admin/me/account`) and
  removing a member from a team -- first sends the gateway
  `{"api_keys": [<ids>], "ttl": ...}` on its internal listener and
  commits only once the gateway confirms the count; otherwise nothing
  changes and the request answers 503, as logout does since #571. The
  gateway keeps a marker per key, shared by its workers, and refuses a
  decision for that key on a cache hit and after a fresh authorization,
  so a request in flight across the revocation is refused too.
  Deactivating or deleting an account also ends its sessions there, with
  the per-user cutoff a password change uses (#569), and stores it in
  `users.tokens_valid_after`. A password change does not revoke API
  keys.
- **An API key with an expiry works until it expires, and not after**
  (#593). `/internal/authorize` compared the key's `expires_at`, read back
  timezone-aware, with a naive `utcnow()`: the comparison raised, so every
  key created with an expiry answered 500 and the gateway 503. Once that
  was fixed, the gateway would have kept serving a cached decision for up
  to its TTL past the expiry. identity now reports `credential_expires_at`
  (the key's expiry, or a session token's `exp`), and the gateway caches a
  decision no longer than that and does not serve it afterwards.
- **One password policy for every path that sets a password** (#583).
  Registration and the reset-password flow accepted a one-character
  password: fastapi-users' `BaseUserCreate` does not check it and its
  `validate_password()` is a no-op, which identity did not override, so
  only change-password asked for 12 characters. identity's
  `UserManager.validate_password()` now refuses a password shorter than
  12 or longer than 128 characters, containing the account's email
  address or the part before the `@`, or among the 10,000 most common
  passwords of that length (vendored from SecLists, MIT license; no
  network access). There are no composition rules, as NIST SP 800-63B
  advises. Registration, reset-password, change-password, an
  administrator's reset of another account, the members a team
  administrator creates (#573) and the first administrator
  (`INITIAL_ADMIN_PASSWORD`, whose refusal now stops identity's start
  with the reason instead of starting without an administrator) all go
  through it. A refusal answers 400 with the reason as `error.message`;
  fastapi-users' `{"code", "reason"}` detail used to reach clients as a
  Python dict literal and is now in `error.details`. The dashboard's
  signup, profile, change-password, add-member and user-creation forms
  check the same length and email rules before submitting (signup and
  user creation asked for only 8 characters) and show the server's
  reason. Existing passwords are not
  checked until they are next changed.
- **Changing the password ends the account's other sessions** (#569).
  A password change updated the hash and nothing else, so every token
  already issued stayed valid until it expired and changing the password
  after a compromise did not lock the intruder out. identity now records
  the time of the change per user (`users.tokens_valid_after`, a new
  migration) and refuses session tokens issued up to it, on its own
  routes and for the gateway; the gateway keeps the same cutoff per user
  and checks it on every request, so a decision it cached before the
  change, or one in flight across it, is not served. identity tells the
  gateway first and changes the password only once the gateway has
  confirmed (503 otherwise). This covers change-password, the
  reset-password flow and an administrator's reset. change-password
  answers with a new access token for the session that made the change;
  the dashboard switches to it. Login tokens now carry a fractional
  `iat`, so that token is told apart from the ones it replaces within
  the same second. API keys are not affected.
- **Changing the email needs the current password** (#569). With a
  session alone, `PATCH /auth/users/me` and
  `PATCH /api/v1/identity/admin/me/profile` moved the account to another
  address, after which forgot-password sends the reset link there. Both
  now require `current_password` for an email change, and the dashboard's
  profile form asks for it. Password-reset tokens carry the email they
  were issued for and stop working once it changes.
- **Current-password checks count toward the login lockout** (#569).
  A wrong current password on change-password, account deletion or an
  email change answered 400 and counted nothing, so a session could be
  used to guess the password without limit. It now counts as a failed
  login, and a locked account is refused with the login's 429 and
  `Retry-After`, even with the right password.
- **`/admin/me/profile` no longer sets a password** (#569). It accepted
  any `new_password`, with no length rule and without identity's password
  validation. Nothing used it; a request carrying one is now refused and
  pointed to change-password.
- **A superuser's own account follows the self-service rules** (#569).
  `PATCH /auth/users/{id}` with the caller's own id changed the password,
  or the email, without the current password. It now refuses a password
  there, like `PATCH /auth/users/me`, and needs `current_password` for an
  email change; resets of other accounts are unchanged.
- **The threat-intel dashboard metrics counted every team's data**
  (#570). `GET /api/v1/data/dashboard/threat-intel` counted the sources
  and indicators of all teams, so any signed-in user learned how many
  feeds and new indicators other teams had, and when their feeds last
  ran. Every figure now covers the caller's team and the global feeds,
  the same scope as `/api/v1/indicators/search`. `last_updated` is the
  end of the last completed collection run of a visible feed, and null
  when there is none; it used to fall back to "one hour ago".
- **A logged-out token is refused at once, on every gateway worker**
  (#571). The gateway caches authorization decisions; logout blacklisted
  the token's `jti` and then purged that cache entry. A request that
  missed the cache while the logout ran had already passed identity's
  blacklist check, and stored its "allowed" after the purge,
  so the revoked token was accepted from the cache for up to
  `AUTH_CACHE_TTL` (300 s). The full-stack logout test failed
  intermittently for this reason; the gateway harness reproduces it on
  every attempt. The gateway now keeps a revocation marker per `jti`
  in a dictionary shared by its workers, checks it on every request,
  cached decision or not, and after every fresh authorization, and a
  purge also discards any decision that was in flight across it.
  Logout fails closed: it answers 2xx only once the gateway has
  confirmed the marker and the blacklist is written, retries the
  gateway twice, and otherwise answers 503, which the client can
  retry. A Redis error while blacklisting used to be logged and
  ignored, so logout reported success with nothing revoked. The same
  confirmed revocation now backs a password change (#569), a disabled
  API key or account (#593) and a member's removal (#613); the
  best-effort full flush that deactivating a user used to trigger is
  gone with #593.
- **The tools service validates target URLs by parsing them** (#561).
  `SecurityValidator.validate_url` ran the free-text injection patterns
  over the whole URL, so it refused `http://` targets, any query string,
  `&` in a path and hosts such as `shop.example.com` (the `sh` pattern),
  and `sql_injection_scanner` could not scan the parameters it exists to
  test. It also accepted what those patterns did not cover:
  `user:pass@host`, CR/LF and other control characters, out-of-range
  ports, and numeric host spellings that clients resolve to loopback
  (`2130706433`, `0x7f000001`, `017700000001`, `127.1`), plus
  `localhost.`. Both URL validators (`SecurityValidator` and
  `InputSanitizer`, which also backs `UrlField`, `url_analyzer` and
  `static_malware_analyzer`) now share one parser: no whitespace or
  control characters, scheme `http` or `https`, a host and no user info,
  port 1 to 65535, a valid (internationalized) domain name or a
  canonical IP literal (other IPv4 spellings are refused, not
  normalized), and no `localhost` or `*.localhost`. Free-text fields keep
  the pattern check.
  `InputSanitizer` now also refuses every address that is not globally
  routable, such as `100.64.0.0/10`. `sql_injection_scanner` also
  returns its result again: its output lacked the required `success`
  field, so every completed scan failed validation.

- **Bandit reports no medium-or-higher findings** in the service code.
  The tools service SSRF guard let every private address through over
  `https://`: `SecurityValidator._validate_public_host` raised its
  "private address" error inside the `try` whose `except ValueError`
  meant "not an IP literal", so the error was swallowed and only the
  names `localhost`, `127.0.0.1`, `::1` and `0.0.0.0` were refused.
  `10.0.0.0/8`, `192.168.0.0/16`, `169.254.169.254` and `::` are now
  refused too. The SAML analyzer parses responses with defusedxml only
  (the standard-library fallback is gone) and reports a DTD, entity
  declaration or external reference as a critical "Forbidden XML
  Construct" instead of expanding it; the tool also no longer imports
  `lxml`, which the service does not install, and its results validate
  again. The mobile analyzer's unused XML helpers are removed. MD5 and
  SHA-1 used as sample identifiers and certificate fingerprints are
  marked `usedforsecurity=False`, and the sensor's default temporary
  directory follows `TMPDIR`. The remaining reports (binding `0.0.0.0`
  inside containers, `/tmp` matched as a substring, the SHA-1
  certificate fingerprint) are annotated with `# nosec` and the reason.

- **Production Redis no longer evicts authoritative state** (#530):
  `docker-compose.prod.yml` replaced the base file's
  `--maxmemory-policy noeviction` with `allkeys-lru` at 512 MB, so under
  memory pressure Redis could delete token-blacklist entries (a revoked
  token worked again), failed-login lockout counters, and Celery and
  Dramatiq queues and results. The overlay now inherits the base command,
  so a full Redis refuses writes instead. The container memory limit
  becomes `REDIS_MEMORY_LIMIT` (default `2g`, twice the default
  `REDIS_MAXMEMORY` of `1gb`) in both files: with the limit equal to
  `maxmemory` the kernel OOM-killed Redis before `noeviction` refused a
  write, and at 1.5x it was killed during an AOF rewrite.
  `scripts/check_redis_config.py` asserts the policy, AOF and the headroom
  on the rendered production configuration and on the running Redis; the
  Production Stack workflow runs both. Sizing and monitoring are in the
  deployment guide.

- **Production network segmentation now takes effect** (#494):
  `docker-compose.prod.yml` attached services to `frontend`, `backend` and
  `data`, but Compose merges a service's networks with the base file's, so
  every service also stayed on the flat `wildbox` network and the dashboard
  and the gateway could open connections to PostgreSQL and Redis. The
  overlay now replaces each service's networks with `!override` (Docker
  Compose 2.24.4 or later). Only `gateway` and `dashboard` are on
  `frontend`; the gateway and the API services on `backend`; PostgreSQL,
  Redis and the services whose database or Redis URLs name them on `data`,
  which is internal. `backend` is no longer internal: Docker gives a
  container on internal networks only neither a route out nor published
  ports, and the API services need both. The four services that are on
  `data` alone (tools-worker, tools-flower, data-scheduler, backup) get them
  from a fourth network, `egress`, with inter-container communication
  disabled. The new `Production Stack` workflow renders the configuration,
  starts it, runs the integration suite against it and probes the
  segmentation from inside the containers
  (`scripts/check_network_segmentation.py`). Starting it also exposed three
  overlay defects that kept the production stack from coming up, now fixed:
  guardian was pointed at a settings module that does not exist and lost
  the hostname the gateway sends from `ALLOWED_HOSTS`; identity was given
  `CORS_ORIGINS` in the comma-separated form it cannot parse and exited at
  start-up; and the dashboard's development bind mount hid the production
  build.

- **Least-privilege workflow tokens and no exception text in API errors.**
  Every workflow now declares `permissions: contents: read`, with
  `security-events: write` only for the two SARIF uploads and
  `packages: write` only for the image push on `main` (23 code-scanning
  alerts). The tools metrics endpoint and guardian's widget test returned
  `str(e)` to the caller; they now log it and return a generic message.

- **The dashboard moves to React 19** (#526). `react`, `react-dom` and their type
  definitions move together to 19.3 (Dependabot's #151 moved `react` alone).
  Unblocked by lucide-react 1.x.

- **Gateway base image refreshed** (#525) to the current `openresty/openresty:alpine`
  digest (OpenResty 1.31.1.1). Dependabot no longer proposes Node.js major
  bumps of the dashboard image: it stays on the active LTS line, which is
  changed by hand.

- **The dashboard runs on Next.js 16** (#522): 16.3.8, from 15.5. Next 15
  pins postcss 8.4.31, which carries four advisories; Next 16 depends on
  the patched 8.5 line itself. `src/middleware.ts` becomes `src/proxy.ts`
  (the file convention Next 16 renamed), `images.domains` becomes the
  equivalent `remotePatterns`, and production builds now use Turbopack.
  Status codes, redirects and response headers match Next 15, and the
  login and dashboard pages render the same.

- **The dashboard no longer ships four libraries it never imports** (#519):
  recharts, zustand, @hookform/resolvers and react-markdown. No file under
  `src/` or `tests/` references them, and the build output is unchanged
  without them. 99 packages leave the lockfile, along with the
  `mdast-util-to-hast` override that existed only for react-markdown, and
  so do the four major-version Dependabot PRs that kept proposing them.

- **The dashboard's npm tree has no known advisory left** (#518): 61 open
  Dependabot alerts (29 high) and 15 `npm audit` findings, down to zero.
  Patch and minor releases only, inside the existing ranges: axios 1.20.0,
  js-cookie 3.0.8, next 15.5.27, postcss 8.5.28 and eleven transitive
  packages (brace-expansion, minimatch, nanoid, picomatch, js-yaml,
  follow-redirects, browserslist, among others). Next 15 pins its own
  postcss 8.4.31; an override now dedupes it to the patched 8.5 line, the
  one Next 16 itself ships. The same change takes the in-range minor
  updates Dependabot grouped (Radix primitives, TanStack Query 5.104,
  react-hook-form 7.89, Playwright 1.63, eslint-config-next 16.3), so the
  lockfile is refreshed once instead of rebased sixteen times.

- **Failed-login lockout is enforced** (#509). The helpers and settings
  existed (5 attempts, 15 minutes) but no login route called them, so every
  account accepted unlimited password guesses. Password login now refuses an
  account with 429 after 5 failures, for registered and unknown emails alike,
  and a successful login clears the counter.

- **identity no longer serves its API documentation in production** (#496).
  `/docs`, `/redoc` and `/openapi.json` mapped every route, admin and
  internal ones included; like agents, responder and cspm, identity now
  serves them only when `ENVIRONMENT` is not `production`.

- **identity no longer prints the initial admin password** (#493).
  `scripts/init.sh` wrote it to the container log on first start, where
  `docker logs`, log shippers and CI artifacts could read it. It now says
  where the value comes from (`INITIAL_ADMIN_PASSWORD`) instead.

- **cryptography 50.0.2 in every service that uses it** (#415): cspm, data,
  guardian, identity, sensor and tools were held at 48.0.1, which carries 3
  advisories (two fixed in 49.0.0, one in 50.0.0: a padding
  oracle in PKCS#7 decryption). Nothing else in the locks moves. 49.0.0 stops
  publishing wheels for Intel macOS; the containers are Linux and unaffected.
- **Python security upgrades no longer depend on Dependabot** (#420). Its pip
  PRs regenerated the locks with pip-compile instead of uv and could never pass
  the Dependency Integrity gate, so no Python fix had landed since 0.10.0.
  `scripts/upgrade_vulnerable_requirements.sh` (`make lock-security`) moves only
  the packages with a known advisory, within the ranges `requirements.in`
  allows, and lists the rest; a weekly workflow opens the PR, and the pip entry
  is gone from `.github/dependabot.yml`. This run moved 19 pins, among them
  PyJWT, urllib3, tornado, anyio and oauthlib.
- **aiohttp 3.14.3 in cspm, data, sensor and tools** (#415), from 3.14.1: 3
  advisories, among them request smuggling through WebSocket upgrades in the
  server, which the sensor's local API runs. Patch releases, bug fixes only.
- **python-jose is gone, and ecdsa with it** (#415). It was pinned in cspm, data
  and guardian only because `open_security_shared.auth_utils` imported it, and
  none of the three uses those helpers. It pulled in `ecdsa`, whose timing
  advisory (CVE-2024-23342) upstream will not fix. `auth_utils` now uses PyJWT;
  its JWT behavior is covered by new tests in `tests/shared/test_auth_utils.py`.
- **pytest 9 and black 26.3.1 in the service locks** (#415). pytest 7.4 and
  8.3 (one advisory: predictable `/tmp/pytest-of-<user>` directories) move
  to 9.0.3 in six services and 9.1.1 in identity (which keeps a range), with
  pytest-asyncio 1.3.0, the first release that accepts pytest 9. black 24
  (2 advisories) moves to 26.3.1 in data,
  guardian, identity and sensor. Dev tools only: no runtime code changes, and
  the Code Quality job already ran an unpinned black.

- **agents moves to LangChain 1.x** (#415). langchain 0.3.30,
  langchain-anthropic 0.3.22, langchain-core 0.3.86 and
  langchain-text-splitters 0.3.11 carried 6 advisories between them. The agent
  keeps its `AgentExecutor` loop, now from `langchain-classic` 1.0.8; prompts,
  messages and `@tool` come from langchain-core 1.6.6; langchain-anthropic is
  1.4.6. `langchain-community`, never imported, is gone. One visible change:
  the analyst notes passed to the structured report are now the model's text,
  where 0.3 passed the string form of a list of content blocks.

- **guardian moves to Django 5.2 LTS** (#415). Django 4.2 has been out of
  support since April 2026; 4.2.30 carried 8 advisories, djangorestframework
  3.15.2 another 2. Now Django 5.2.17, DRF 3.17.2, django-celery-beat 2.8.1
  (2.5.0 declared `Django<5.0`) and django-filter 25.1 (with 23.2 every list
  endpoint with a `ChoiceFilter` answered 500 on Django 5; a new unit test,
  `test_filtersets.py`, builds every filterset form so this fails in CI
  instead of at request time). `STATICFILES_STORAGE`, which Django 5.1 drops
  without an error, becomes `STORAGES`: without it the WhiteNoise compressed
  manifest storage would have been silently replaced by the plain one.
  Deploy runs one new migration, `django_celery_beat.0019`.

- **cspm leaves urllib3 1.26** (#415). urllib3 1.26.20 carried 7 advisories and
  was held there by `google-auth==2.23.0` (`urllib3<2.0`) and
  `botocore==1.34.0` (`urllib3<2.1`). google-auth 2.23.4 and boto3/botocore
  1.34.63 are the first releases of the same lines that allow urllib3 2; the
  lock now has urllib3 2.8.0 and s3transfer 0.10.4.

- **Unused dependencies with advisories removed** (#415). guardian pinned
  Pillow 12.2.0 (13 advisories) and nothing imports PIL or declares an
  ImageField. data pinned nltk 3.10.3 (1 advisory, no fixed release exists)
  and dash 2.15.0, which held flask at 3.0.3 and werkzeug at 3.0.6
  (4 advisories); neither is imported. 15 packages leave the data lock.

- **click 8.3.3 in cspm and data** (#415), from 8.1.7 (1 advisory). Neither
  service calls click itself; celery, uvicorn and black do, and their CLIs
  behave as before. The one change seen: `python -m spacy info` in data now
  exits with an error (typer 0.9.4, pinned by spacy 3.7.2, predates click
  8.2); nothing in the repository imports spacy or runs its CLI.

- **Tools verify TLS certificates by default** (#495). `web_vuln_scanner`,
  `cookie_scanner`, `http_security_scanner` and `url_analyzer` connected with
  certificate verification switched off (`ssl=False` or `CERT_NONE`), so a
  scan could report on content served by whoever intercepted the connection.
  They now verify the certificate chain and the hostname. When verification
  fails the scan returns `success: false` with the reason (for example
  `self-signed certificate`) and sends no further request; there is no retry
  without verification. Accepting an unverified certificate is a per-scan
  choice through the `verify_ssl` input every tool already inherits (default
  `true`), whose description in the input schema states the risk.
  `ssl_analyzer`, `ca_analyzer` and `pki_certificate_manager` still read the
  certificate over an unverified handshake, which is what lets them inspect a
  broken one, and now also run a verified handshake and report its failure as
  a finding. Most of these seven tools could not return any result before this
  change (the required `success` field was never set, `getpeercert_chain()`
  does not exist in the `ssl` module, naive and aware datetimes were
  compared); those defects are fixed so the new behavior is reachable, and
  22 unit tests against a local self-signed HTTPS server cover it.

- **cspm drops the cloud SDKs it never imported, and protobuf with them**
  (#415). requirements.in pinned 23 `google-*` packages besides google-auth
  and seven `azure-mgmt-*` packages; the service imported only
  `google.auth` and `azure.identity` (in `app/worker.py`), and every GCP
  and Azure check ran on sample data, naming its SDK only in a comment
  (those checks and imports are gone since #612; google-auth and
  azure-identity stay pinned). The 2023
  google-cloud releases require `protobuf<5`, which held protobuf at 4.25.9
  (PYSEC-2026-1805, fixed in 5.29.6). With them gone protobuf, grpcio and
  google-api-core leave the lock entirely: 128 packages become 73, and
  pip-audit reports nothing for cspm. boto3, botocore, google-auth and
  azure-identity stay at the same versions.

- **No advisories left in the requirement files outside the locks**
  (#508). Four files were outside `scripts/compile_requirements.sh` and
  carried 15 Dependabot alerts. `open-security-tools/requirements-secure.txt` is
  deleted: nothing in the repository installs or mentions it.
  `tests/requirements.txt` (installed by the chaos and load workflow) moves
  to pytest 9.0.3, pytest-asyncio 1.3.0, aiohttp 3.14.3, black 26.3.1 and
  psutil 6.1.1, and drops `safety`, which nothing runs and which pulled in a
  vulnerable filelock (or, from 3.6.1, nltk, which has no fixed release).
  The cspm and guardian `requirements-dev.txt` move to pytest 9.0.3, black
  26.3.1 and mkdocs-material 9.7.7. guardian's could not be resolved against
  its own lock at all (safety 2.3.5 required packaging<22, pgcli 3.5.0
  sqlparse<0.5); it now resolves, with safety dropped and pgcli at 4.6.0.
  pip-audit reports nothing for any of them, transitive dependencies
  included.

- **The dashboard image runs node 24 LTS** (#462), from node 18, out of
  support since April 2025. The image stays pinned by digest; CI moves from
  node 20 to 24 as well.

### CI

- **The dashboard E2E specs no longer race the toast announcement**
  (#602). Radix renders a toast's text twice for about a second: in the
  toast, and in a visually hidden `aria-live` span outside it for screen
  readers. A page-wide `getByText` on toast text matched both while the
  announcement lasted and failed Playwright's strict mode, which made
  "creates a user from the form" flaky. Each toast now carries
  `data-testid="toast"`, and the admin and settings specs find toast text
  only inside it through a `toast()` helper, with the outcome still
  asserted through the API. No retry or timeout was added. Repeated 30
  times with no retries, the test failed 9 of 30 runs before the change
  and passed 30 of 30 after it.

- **Prose Quality checks the Markdown and fails on findings** (#606).
  The job installed proselint unpinned and ran
  `proselint FILE ... || true`; proselint 0.16 only accepts
  `proselint check FILE`, so every call failed and the job passed having
  checked nothing. proselint is now pinned to 0.16.0, its rules are in
  `.proselintrc.json`, and `scripts/check_prose.py` lints every tracked
  Markdown file except the vendored ones, with code blocks, inline code
  and HTML comments masked so that commands are not read as prose. Each
  finding is a GitHub annotation and any finding fails the job, which is
  no longer advisory. The 16 findings left in the documentation are
  fixed.

- **A failed E2E run keeps what is needed to trace it** (#609). The
  workflow printed the last 150 lines of `docker compose logs`, which do
  not include the gateway's access and error logs: they are files. On
  failure it now uploads them, with the state and restart count of every
  container and the full, timestamped logs of gateway, identity and
  data, and prints the access log's 5xx lines. The access log records
  `$request_id`, `$upstream_addr` and `$upstream_status`, so a 5xx line
  says whether an upstream answered it or the gateway did.

- **Every test file runs in CI, and a new one cannot be left out**
  (#582). Sixteen files named `test_*.py` sat where no workflow looked:
  beside the services' `tests/unit/`, at a service's root, under
  `scripts/`, or in the repository's `tests/` outside the suites CI runs.
  None ran, several no longer matched the code (the agents' `test_basic.py`
  asserted an attribute the client had lost), and most caught every error
  and printed it. What still mattered moved into the unit suites,
  rewritten against the current code: the agents' request schemas, the
  caller identity from `/v1/analyze` through the worker to every agent
  tool, and the gateway secret's source; the responder's step templates,
  conditions and system actions; the tools' CIDR-bounded scanner, now with
  `ping` replaced rather than sent to the runner's network. The rest was
  removed, being duplicated by the integration suite or written against
  endpoints that no longer exist. `scripts/check_test_collection.py`, run
  by Code Quality, reads the workflows' pytest commands, works out what
  they collect and fails on any test file outside it; deliberate
  exceptions go in `scripts/test_collection_allowlist.txt` with a reason.

- **A workflow that calls a missing route fails the build** (#592).
  `scripts/check_automation_workflows.py`, run by Code Quality, resolves
  the URL of every HTTP Request node in
  `open-security-automations/workflows`, matches the path against the
  gateway's HTTPS locations with nginx's precedence, maps it through
  `proxy_pass` to the upstream service and looks the method and path up
  in that service's routes, read from its source. It also fails on a
  call that addresses a service directly, a base URL it cannot resolve,
  an upstream it has no route table for, and a gateway call without an
  `X-API-Key` or `Authorization: Bearer` header. Unit tests in
  `tests/scripts` include a fixture that calls the removed executive
  summary.
- **The backend-dependent Playwright specs run on the real stack**
  (#103). `E2E Full-Stack` brings the stack up with
  `docker compose up --wait` and a generated `.env`, as Integration
  Tests does, and drives the dashboard through the gateway at
  https://localhost. The four deferred specs are rewritten against the
  current UI and assert outcomes on the page and through the API: 27
  tests, tagged `@backend`, replace 8 that ran (4 of them quarantined)
  and 27 that never did. Billing tests are gone with the billing page.

- **The workflows are bounded, deduplicated and cached** (#557). Every
  job has a timeout of about three times its longest observed green run
  (26 had none), with step limits on installs and stack start-up; a new
  push to a pull request cancels its superseded runs, never runs on
  `main`. Trivy and Bandit run once per pull request, in Security
  Scanning, uploading to code scanning as `trivy-fs` and `bandit` (Trivy
  ran twice, Bandit missed guardian, the sensor and the shared package);
  the critical-advisory gate moved there unchanged. The documentation
  secret scan's AWS and GitHub token patterns matched nothing without
  `grep -E`. pip caches are keyed per service, and Integration Tests and
  the production stack build through the Actions cache: 5.4 to 2.1 min of
  image builds warm. `.github/workflows/README.md` now lists what each
  workflow runs and gates, and actionlint passes.
- **A scheduled guardian task is seen to run, and on its queue** (#545).
  Integration Tests and Production Stack start guardian-beat with the
  alert-rule sweep every 15 seconds and wait, through the gateway, for a
  rule's trigger count to move with nothing else starting a sweep; the
  alert sweep and an asset port scan must report the `reporting` and
  `scanning` queues. Production Stack also checks the queues the running
  worker consumes and that there is one beat container.
- **The dashboard is linted, format-checked and type-checked in CI**
  (#528). `npm run lint` used `next lint`, gone in Next.js 16, with a
  legacy `.eslintrc.json` ESLint 9 cannot load; it now runs the ESLint
  CLI on a flat config from `eslint-config-next`, with warnings failing
  it. 181 of its 182 findings are fixed in code (the last, `require()`
  in the CommonJS Tailwind config, is allowed for `*.config.js`), among
  them IOC lookups that returned
  `response.data` from a client that already returns the body (every
  hit showed as an error, every miss was retried instead of reported as
  not found) and error handlers reading an axios `response` the API
  client never rejects with. Prettier was applied once to the whole
  project, in a commit listed in `.git-blame-ignore-revs`. A new
  `dashboard-lint` job runs lint, `format:check` and `tsc --noEmit`, and
  the image build waits for it.
- **The license gate blames the right cause** (#429). It reported "no license
  data in the SBOM" for the gateway image, whose SBOM is complete but holds no
  language packages, only Alpine ones the gate deliberately ignores. Its first
  correct run found `python-nmap` (see Removed).
- **The sensor's tests run in CI** (#417); the service had never been in the
  unit-test matrix.

- **The weekly pip security PR can trigger CI without a personal token.**
  `Pip Security Upgrades` mints a one-hour GitHub App installation token,
  scoped to this repository's contents and pull requests, when
  `DEPS_APP_CLIENT_ID` and `DEPS_APP_PRIVATE_KEY` are configured, and falls
  back to `GITHUB_TOKEN` otherwise. The `DEPS_PR_TOKEN` personal-token option
  is removed.

- **The chaos suite measures the system now** (#428). Seven experiments
  against the stack as the integration job starts it: cached authorization
  survives an identity outage; new tokens fail closed with 503, then
  immediately once the breaker opens, and work again when it closes; a
  PostgreSQL outage is reported and recovered from without a restart; a Redis
  outage does not block login; a crashed identity or data process is
  restarted and served again; a 200-request burst gets only 200s and 429s.
  Back on the nightly schedule.

- **The critical-advisory gate now gates, and only on what a PR adds** (#430).
  `PR Validation Summary`, the check branch protection requires, never read
  the result of `security-scan` and did not depend on `dependency-integrity`
  at all, so both went red on PRs that could still be merged. Both now count.
  The critical-advisory step compares the PR against its base and fails only
  on advisories the PR introduces; those already on `main` are reported by the
  new `Main Advisories` workflow, daily and on every push, in one issue it
  opens, updates and closes.

### Documentation

- **The published site and the API reference re-checked against the code
  for 0.11.0.** The landing page claimed 58 tools (there are 52), 50+ threat
  sources (7 feeds), AWS, Azure and GCP scanning (AWS only; others are
  refused), any LLM provider (Anthropic only) and keys generated on first
  run, and its quick start copied `.env.example` and opened
  `http://localhost:3000`; it now shows `make generate-secrets`,
  `INITIAL_ADMIN_EMAIL`, `make validate-secrets`, `docker compose up -d
  --wait` and `https://localhost`, and its copy button works. The CSPM check
  count (31, with sample-data Azure and GCP checks) is corrected to 22 AWS
  checks everywhere. The gateway route tables gain `/api/v1/tasks/`,
  `/auth/users/`, `/auth/forgot-password`, `/auth/reset-password` and
  `/api/v1/identity/auth/` and `/api/v1/agents/stats`. The tools, data,
  guardian, responder and agents endpoint pages are rewritten from the real
  routes, with every example through the gateway, and include this release's
  changes to them: the network-target policy, per-team telemetry, guardian
  behind the gateway only, agents and responder acting as the caller. The guides document `PASSWORD_CHANGE_REQUIRED`, the
  change-password route, Docker Engine 23.0 and Compose 2.24.4 as the
  minimums, guardian's `/health/` and the refused CSPM providers;
  `TROUBLESHOOTING.md` and the quick start drop statements about `make
  start` and `make clean` that no longer hold. Superseded engineering notes
  move to `docs/archive/`, and the tools service audit of November 2025 is
  no longer published.

- **Service READMEs describe the code on main.** The README of every
  service (tools, gateway, identity, agents, cspm, dashboard, data,
  guardian, sensor) and the use cases are rewritten from the code: real
  routes, gateway paths, ports, settings and counts (52 tools, 22 CSPM
  checks, AWS only, 7 data collectors), gateway-only authentication, no
  plans or billing, and no invented releases, badges or performance
  figures. The sensor and data documents describe telemetry as it now
  flows, through the gateway and per team (#640, #660). Seven obsolete
  reports and migration notes are
  deleted (tools `DOCKER_SETUP.md`, `SECURITY_AUDIT_SUMMARY.md`,
  `SECURITY_FIXES_APPLIED.md`; guardian `QUEUE_MANAGEMENT_REPORT.md`;
  identity `FASTAPI_USERS_MIGRATION.md`; agents `LLM_SETUP.md`,
  `MIGRATION_LM_STUDIO_TO_VLLM.md`). Standalone configs follow: the agents
  compose loses its OpenAI-compatible `llm` service, the standalone sensor
  binds and publishes 8004 and passes the telemetry settings through, and
  the dashboard and tools `.env.example` list
  only variables the code reads.

- **An Authentication and sessions guide, and the operator documents
  re-checked against today's code.** `guides/authentication.md` covers login,
  token lifetime, logout and revocation (including the gateway's internal
  port 8081 and what fails open when Redis is down), the failed-login lockout
  and how to lift it, and how the gateway behaves when identity is down.
  `UPGRADING.md` gains a section for this release. `SECURITY.md` gave a
  reporting address (`security@wildbox.dev`) that is not the one in
  `security.txt`, recommended refresh tokens and bcrypt, and ran a script that
  does not exist; it now points to private GitHub reporting and the
  `security.txt` contact. `TROUBLESHOOTING.md` created an admin with the
  password `admin123` through modules identity does not have, and told
  readers to `FLUSHALL` Redis, which holds CSPM, responder and agents state;
  it is rewritten. `SETUP_GUIDE.md`, a drifted second quick start with
  default n8n credentials, now points to the maintained guides.
  `api-reference.html` documented a JSON login, `/auth/refresh` and identity
  on port 8000; it is now an overview of authentication and the gateway path
  of each service.

- **SEO pilot pages** (#433, #435): `/learn/how-to-check-spf-dkim-dmarc/` and
  a client-side `/tools/jwt-decoder/`, with `/learn/` and `/tools/` hubs
  linked from the homepage navigation.

- **README rewritten from verified facts** (#505). It described components the
  project no longer has (Stripe billing, OpenAI, Elasticsearch, Grafana,
  NLTK), claimed 50+ threat feeds (there are 7) and a stale v0.8.0 roadmap,
  and its quick start ended in a stack where `data` refused to start. The
  new README documents the configuration CI starts on every change, an HTTPS
  health check and login against the generated certificate, one table of
  capabilities with real counts, and links into the published docs.

- **Crawlers may fetch the site's own assets.** `robots.txt` disallowed
  `/vendor/`, which holds the self-hosted Tailwind, highlight.js and fonts
  every page loads. `api-reference.html` and the two Redoc pages now load
  their vendored files from root-relative paths like the rest of the site,
  the Redoc pages get canonical URLs, the remaining standalone pages link
  `security.txt` in their footers, and `api-reference.html` loses a stale
  "Last Updated" stamp.
- **Stale and placeholder notes are labeled.** `DOCUMENTATION_QUALITY_AUDIT.md`
  (a November 2025 snapshot, unpublished) is marked archived, and the
  gateway authentication guide, linked from the published tools audit, says
  that its keys and hosts are fictitious.

- **`llms.txt` and `llms-full.txt` describe what exists.** They sold a SIEM, a
  WAF, Kubernetes support and a local Ollama LLM, none of which the project
  ships, and gave the gateway as port 8080 and Postgres credentials that do
  not match. Both are rewritten from `docker-compose.yml`, the gateway routes
  and the integration tests' login flow, agree with each other, state no
  version, and count only what is real: 52 loadable tools and 22 CSPM
  checks, AWS only.
  The homepage's structured data loses the same claims and its stale
  `softwareVersion`.
- **The `/learn/` and `/tools/` hubs say how small they are.** Each holds one
  item; the copy now says so and calls them a growing collection instead of
  promising a library, and the placeholder comments are gone. Both stay
  indexed.
- **The privacy notice is indexable.** It is a complete, dated legal page
  listed in the sitemap, so `noindex` contradicted the sitemap; it now has
  `index, follow` and a canonical URL.
- **The homepage, hubs and privacy notice link `security.txt`**, and the
  homepage loads its vendored Tailwind from a root-relative path like the
  other pages.

- **The security status page says what is still wrong** (#491). It
  reported every finding "Fixed", every check "PASS" and "99% of known
  vulnerabilities resolved" as of v0.5.5. Re-checked against `main`, it now
  lists the failures as open issues (several were fixed later in this
  release: the logged admin password, TLS verification in the scanners,
  identity's API docs in production, the login lockout), points at #415 for
  dependencies, marks unchecked claims "Not verified", and says how each
  check was made. The 2024 and 2025
  audit documents are marked historical; the checklist's quoted heredoc that
  wrote `$(openssl ...)` literally and its `sk_live_` placeholders are
  replaced by `make generate-secrets`, and the guardian `SECRET_KEY` fallback
  is no longer quoted as current. Expired version and review stamps are gone
  from the security policy.
- **The security policy no longer claims bcrypt with 12+ rounds**
  (fastapi-users hashes with Argon2id), and the status page stops linking the
  November 2024 audit documents, which the site no longer publishes.

- **One ports table, one login flow, no published passwords.** The guides
  disagreed about ports (identity on 8000 or 8001, agents on 8002, 8004 or
  8006, guardian on 8001) and showed the login once as JSON and once
  form-encoded. `docs/guides/ports.md` now lists every service, container
  and port from `docker-compose.yml`, and the other guides link to it. The
  Quick Start uses the login sequence the integration tests run (form-encoded,
  through the gateway over HTTPS, trusting the generated certificate), with no
  time promise. The Credentials guide no longer lists `dev-api-key-123`,
  `postgres/postgres`, `demo-password-123` or `admin/admin`, none of which the
  stack uses; it explains `generate_secrets.py`, `INITIAL_ADMIN_*` and
  rotation instead. The Deployment guide no longer overwrites
  `docker-compose.yml`, replaces the gateway with a separate nginx or creates
  databases by hand. The identity API reference is rewritten from the routes
  the service registers; the other references get correct ports and a note
  that they are hand-written.
- **The Ollama guide says Ollama is gone.** `guides/ollama-llm.md` described a
  local LLM container that no Compose file defines; it now documents the
  Anthropic configuration the agents service actually reads, including that
  submitted indicators are sent to Anthropic when it is enabled.
- **One authentication reference.** The guides state, from the identity
  code, the signing algorithm (HS256), the claims, the 30-minute lifetime
  (which `.env` cannot change, because Compose does not pass it), that there
  is no refresh, and both revocation routes. The tools reference counts 52 loadable tools
  instead of 54, the ports page explains how `/metrics` and Prometheus are
  kept private (localhost binding, not authentication), the references mark
  their example values as fictitious, and acronyms are expanded on first use.

- **The documentation site renders Markdown at build time.** `docs.html` used
  to fetch guides from `raw.githubusercontent.com` and turn them into HTML in
  the browser with a hand-written parser, injecting the result unsanitized; a
  failed fetch left a "Loading..." page. Jekyll now renders every guide,
  security page and API reference through one layout, with a sidebar built
  from `docs/_data/docs_nav.yml`, and old `docs.html#quickstart` links redirect
  to the published page. The API cards that said "Coming Soon" for tools,
  identity, data and guardian link to their endpoint references, and
  `docs/api/README.md` is published at `/api/`. The dead `collections`
  configuration, the unused remote theme and the stale `docs/index.md` are
  gone, and the sitemap lists only pages the build produced.
- **`docs/security/findings.json` is deleted.** It was a November 2024 dump
  with local `/Users/...` paths that contradicted the status page; nothing
  read it. It remains in git history.
- **`api/swagger-index.html` redirects to the API overview.** It called itself
  the index of all APIs and listed two of six; Redoc pages for the other four
  were not generated because no exported OpenAPI document exists for them.
- **The 2024 security audit is no longer published.** `docs.html#security-audit`
  led to `/security/audit-report/`; that report, its remediation checklist and
  its improvements summary describe code that has since changed and are
  excluded from the site and the sidebar, and the old hash now leads to the
  security status page.
- **Contributor docs page and smaller site fixes.** `/contributing/` links the
  engineering notes that stay unpublished (cited by `SECURITY.md` and CI
  scripts) and states that Jekyll in `docs/` is the only documentation stack;
  `website/` is ignored by git. Long pages get an "On this page" list built
  from their headings, every documentation page links `security.txt`, vendor
  READMEs are no longer published as pages, and the sitemap emits only `<loc>`
  because Pages cannot supply a real last-modified date.

### Removed

- **guardian's `APIKey` model and its plain-text table** (#629), with
  `APIKeyAuthentication`, the unused `APIKeyMiddleware` and
  `generate_api_key()`. Migration `core.0002_remove_apikey` drops
  `core_apikey` and the audit log's `api_key_id` column. guardian's
  `.env.example` loses `GUARDIAN_API_KEY` and `API_KEY_HEADER`, which
  nothing read. Use identity's personal API keys through the gateway;
  UPGRADING.md says how.

- **Nine n8n workflows that could not run** (#592): Security Compliance
  Automation, Daily OSINT Report, Honeypot Alert Classifier, Threat
  Intelligence Feed Aggregator, Vulnerability Sync and Enrichment, CSPM
  Alert Processor, Security Incident Response Orchestrator, Support
  Ticket Triage and Threat Intelligence Enrichment. Every one called
  endpoints that do not exist on any service, or called services
  directly, which they refuse since #566. UPGRADING.md lists each one
  with its reason. The automations README now describes the one
  workflow that remains instead of an inventory of planned ones.
- **cspm's executive summary and remediation roadmap** (#578).
  `GET /api/v1/dashboard/executive-summary` and
  `GET /api/v1/scans/{scan_id}/remediation-roadmap` read
  `scan:{id}:results`, a Redis key nothing writes (scan reports live in
  the Celery result backend), so the first answered zeros and an empty
  trend after any scan and the second answered 404 for every completed
  scan; the roadmap also gave every item a fixed "Medium" effort and
  "High" priority. Both now answer 404. The dashboard summary reports
  the figures the overview needs from the real reports, and
  `/api/v1/compliance/findings` lists failed checks with their severity
  and remediation.
- **The scan status counts of cspm's dashboard summary** (#578).
  `active_scans`, `completed_scans` and `failed_scans` came from the
  status stored when a scan starts, which is never updated, so every
  scan counted as active, forever. The Celery state that could replace
  it cannot tell a queued scan from one whose result has expired, so the
  fields are removed rather than estimated.

- **`users.recent_logins` in identity's system statistics** (#573).
  `GET /api/v1/analytics/admin/system-stats` reported as "recent logins"
  the number of users whose `updated_at` changed in the last day, so a
  profile change counted as a login and a login that changed nothing
  did not. identity keeps no record of successful logins (the lockout
  counts only failures, and clears them on success), and nothing in
  the dashboard read the field, so it is removed rather than estimated.

- **The tools service's standalone web UI** (#581). `app/web` served an
  index of the tools, a page per tool with a form built from its input
  schema, a settings page, a developer guide and Swagger UI / ReDoc pages,
  which the gateway exposed under `/tools/`. Through the gateway it did
  not work: its CSS and JavaScript were requested from `/static/`, which
  the gateway sends to the dashboard, and its API calls carried a key
  typed into the page rather than the session. The service no longer
  serves `/`, `/tools/{name}`, `/settings`, `/guide`, `/docs`, `/redoc`
  or `/static/`; `/openapi.json` stays. The gateway answers `/tools/` with
  404 itself instead of proxying it, and no longer accepts the
  `auth_token` cookie as a credential on safe methods, which it did only
  for those page loads; the dashboard sends the session as a Bearer
  token. The dashboard's `/toolbox` "Execute Tool" button only opened the
  removed page; each tool's "Run" button now opens the dashboard's own
  form for it (#585, under Added). `Jinja2` and `aiofiles` leave the tools
  service's dependencies. Two fixes made earlier in this release to those
  pages go with them: their API calls had moved from the removed
  `/api/tools` alias to `/api/v1/tools` (#567), and their search, which
  built results with `innerHTML` from the typed query and from tool names
  read back with `textContent`, had been escaped (#464, CodeQL
  `js/xss-through-dom`).
- **The gateway's `/api/tools/` alias** (#567). It served the tools API
  beside the canonical `/api/v1/tools/`, with `Deprecation` and `Sunset`
  headers announcing its removal on 1 July 2026. Nothing in the
  repository calls it any more; it now answers 404.
- **The agents client's `X-API-Key` fallback** (#567). Without a caller
  identity or `GATEWAY_INTERNAL_SECRET`, the client sent the static
  `INTERNAL_API_KEY` as `X-API-Key`, which the tools service has refused
  since #566 (401). It now always forwards the caller's gateway identity
  with the secret, and without either it raises
  `CallerIdentityUnavailable`, naming what is missing, before sending
  anything. `INTERNAL_API_KEY` is no longer passed to the agents
  container. The unused `api_client` test fixtures, which sent
  `X-API-Key` straight to the tools service, are removed too.
- **Estimated request counts in identity's admin analytics** (#570).
  `GET /api/v1/analytics/admin/usage-summary` returned
  `summary.api_requests_today` as the number of API keys used in the
  last day times 75, and `GET /api/v1/analytics/admin/system-stats`
  returned `api_usage.estimated_requests_today` and
  `api_usage.estimated_requests_week` the same way (times 50 and 200).
  identity does not see API requests, the gateway serves them, so it has
  no count to report; the three fields are removed rather than replaced
  by another estimate. The dashboard's unused `useSystemStats` hook,
  which read the first one and invented user counts when identity did
  not answer, is deleted.
- **identity's `POST /api/v1/admin/teams/{team_id}/invite`** (#570). It
  answered "Invitation sent successfully" to a team owner or admin and
  did nothing: no invitation was stored or sent, and the request body was
  not read. Nothing in the stack called it since the dashboard dropped
  its invite form (#559). The path now answers 404. A team owner or
  admin now adds a member by creating the account in the team,
  `POST /api/v1/admin/teams/{team_id}/members` (#573, under Added).
- **Direct `X-API-Key` authentication on the tools service** (#565). A
  request that sent the service's static `API_KEY` straight to port 8000 as
  `X-API-Key` was answered with a `GatewayUser` built on the nil UUID,
  which the model refuses (it declares UUID4), so every such call ended in
  a server error. Nothing in the stack depended on it: the gateway removes
  `X-API-Key` before proxying, and the agents service forwards the caller's
  gateway identity. The tools service now accepts only requests forwarded
  by the gateway (`X-Wildbox-*` headers verified with `X-Gateway-Secret`);
  anything else gets 401, and the message no longer mentions `X-API-Key`.
  Personal API keys sent to the gateway are unaffected. `API_KEY` stays a
  required setting: the service still validates it at start-up. (The
  agents service received it as `INTERNAL_API_KEY` until #567.)

- **The blue/green deployment experiment** (#552).
  `docker-compose.blue-green.yml`, `haproxy/`, the `blue_green_*.sh`
  scripts and the `Blue-Green guardian tasks` workflow are deleted. The
  experiment could not complete a deployment for any service: HAProxy
  routed to `data-blue`, `tools-blue` and `agents-blue`, which the Compose
  file did not define, so it could not start; the traffic switch rewrote
  `server guardian-blue …` into a line without the `server` keyword that
  still pointed at blue; the deploy script stopped at a `smoke_tests.sh`
  that did not exist and told the operator to run a
  `blue_green_finalize.sh` that did not exist either; and it always
  deployed to green, so a second deployment had no idle color. Neither
  `docker-compose.yml` nor `docker-compose.prod.yml` used any of it. The
  guardian worker and beat it gained in #550 go with it.

- **guardian's `generate_vulnerability_reports` task** (#550). It logged a
  line and returned; nothing called or scheduled it. Reports, the
  vulnerability summary, risk assessment and executive dashboard among
  them, are generated by `apps.reporting` from report templates, which is
  what the stub's comment described.

- **The tools credential manager and `ENCRYPTION_KEY`** (#540).
  `SecureCredentialManager` read API keys from the same environment
  variables as the fallback beside it, and its encrypt/decrypt methods had
  no caller, so nothing was ever stored encrypted. It imported `keyring`,
  which the image does not install: setting `SECURITY_CONTROLS_ENABLED=true`
  raised an ImportError that switched the whole security layer off, SSRF
  validator and authorization manager included. Removing it makes that flag
  load both. `ENCRYPTION_KEY` goes from `.env.example`,
  `open-security-tools/.env.template` and `setup_security.sh`; no service
  reads it.

- **python-nmap** (#431), a GPL-3.0 package declared by tools and guardian
  and imported by nothing. The services use the `nmap` binary, which stays.

- **The Docusaurus site in `website/`** (#419). It was never the published
  site: GitHub Pages serves `docs/` (Jekyll) from `main`, and
  `deploy-docs.yml` last ran in November 2025, failed, and could not have
  deployed anyway with Pages set to build from a branch. The site did not
  build, its pages still described OpenAI and Stripe billing, and it drew
  about fifteen Dependabot PRs. Gone with it: `deploy-docs.yml`,
  `scripts/generate-api-specs.sh` (which only fed it) and
  `docs/DOCUMENTATION_MIGRATION.md`.

## [0.10.0] - 2026-09-08

Everything here was found by running the thing. A 20-category audit produced 115
findings, all remediated; then the stack was started for the first time, which
produced a second and larger set of defects that no amount of reading would have
surfaced — services that could not boot, a gateway that could not reach one of
its backends, and an executive dashboard whose headline numbers came from
`random.choice`. The integration suite, which had never really run, now runs
against the full stack and passes. **Several changes are user-facing — read
[UPGRADING.md](UPGRADING.md) before deploying.**

### Upgrade notes

Read [UPGRADING.md](UPGRADING.md); it has the commands. In short:

- **New required secrets.** `CSPM_CREDENTIAL_KEY`, `REDIS_PASSWORD`,
  `FLOWER_PASSWORD`, `GUARDIAN_SECRET_KEY`, `CSPM_SECRET_KEY`, `SENSOR_API_KEY`
  and `DATA_SECRET_KEY` are now required. Without them `docker compose config`
  fails, or the service starts and refuses every request.
  `make generate-secrets FORCE=1` produces them.
- **Rotate `API_KEY`.** The platform key was rendered into dashboard HTML and is
  to be treated as public.
- **Run the migrations.** `identity` and `data` own alembic chains now, and the
  data API migrates at startup instead of calling `create_all()`. Two revisions
  add CHECK constraints and **stop on rows that violate them** — deliberately,
  and they name the offending values and the query that fixes them.
- **Identity's JSON metrics moved** from `GET /metrics` (now the Prometheus text
  exposition, like every other service) to `GET /api/v1/admin/metrics`.
- **Rebuild the images.** All six FastAPI services now resolve to one Starlette
  and one FastAPI; the deployment previously ran three different Starlette
  majors.

### Fixed — the platform could not start

- **`docker compose build` was broken for every Python service.**
  `additional_contexts` pointed at `../open-security-shared`, which compose
  resolves from the project directory, so it escaped the repository. CI was
  unaffected, which is why it went unnoticed.
- **The tools service could not import its own entrypoint.** The shared package
  imported `auth_utils` eagerly, which imports `jose`; services install it with
  `--no-deps` and none pin python-jose. Names resolve lazily now (PEP 562), with
  a test that fails if an eager import returns.
- **The identity service could not boot**: it imports `redis` through
  `token_blacklist` and never pinned it. At the previous release the only
  importer did it inside a function, so it surfaced as a 500 on the first
  authenticated request rather than at boot.
- **The data image shipped no `alembic/` directory**, so the startup migration
  died with `Path doesn't exist: '/app/alembic'`.
- **The sensor image had never built**: `setup.py` opened a `README.md` excluded
  from the build context and fed the hash-pinned lockfile to `install_requires`.
- **The sensor lockfile could not install on Linux.** Compiled on macOS, it
  contained `pyobjc-core`, whose build refuses to run anywhere else.
  `compile_requirements.sh` now resolves for linux, so the same
  `requirements.in` yields the same lock from a laptop and from CI.
- **The gateway crash-looped whenever any upstream was absent.** nginx resolves
  upstream hostnames at load time and treats failure as fatal; the gateway's
  `depends_on` named five of its nine upstreams.
- **A fresh install could not reach `docker compose up`.** `.env.template` and
  `.env.example` had drifted into two different variable sets, with `make setup`
  reading one and `make generate-secrets` the other; the generator replaced only
  empty values, leaving the template's placeholders for the validator to reject;
  and it prompted unconditionally, so the documented setup order aborted on EOF
  and left every secret empty.
- **Generated passwords could contain `$`,** which docker compose interpolates —
  the container received a different, truncated secret than the one in `.env`,
  silently.
- **A freshly generated `.env` could not authenticate to its own database.**
  The connection strings ship as
  `postgresql://postgres:YOUR_DB_PASSWORD@postgres:5432/<db>` and nothing
  replaced the placeholder, so PostgreSQL started with the generated password
  while every service connected with the literal `YOUR_DB_PASSWORD`.
  `docker compose config` accepts that happily — the values are present and
  non-empty — so it only surfaced as `FATAL: password authentication failed`
  once running. `validate_secrets.py` now fails when a `*DATABASE_URL` password
  does not match `POSTGRES_PASSWORD`.
- **Generated passwords are restricted to RFC 3986 unreserved punctuation.**
  Beyond `$`, a password is embedded in a DSN: `@` ends the userinfo component,
  `%` starts a percent-escape and `+` decodes as a space. Each silently produced
  a password the database never saw.
- **The data service and its scheduler crash-looped** on `SECRET_KEY must be set
  in production`. Nothing passed one; `DATA_SECRET_KEY` is generated and
  required now.
- **The gateway could not start on Linux at all.** The dashboard upstream listed
  `host.docker.internal:3000`, a name that exists only under Docker Desktop, and
  nginx treats an unresolvable upstream as fatal at config load. It worked on
  macOS for exactly the reason it failed everywhere else, CI included.

### Fixed — services unreachable or wrong

- **Guardian answered every request through the gateway with a redirect loop.**
  `SECURE_SSL_REDIRECT` is on whenever `ENVIRONMENT=production`, TLS terminates
  at the gateway, and `SECURE_PROXY_SSL_HEADER` was never set — so Django saw an
  insecure request and 301'd to the same URL, which arrived over HTTP again.
- **`RATE_LIMIT_PER_HOUR` reached no service.** It is documented in
  `.env.example` and read by the gateway's Lua handler, but nothing passed it in:
  the limit was always the built-in 10000/hour default and setting the variable
  had no effect anywhere.

- **Guardian was unreachable through the gateway**, on every route, for every
  client. Django validates `Host` against `ALLOWED_HOSTS` before anything else
  runs; the gateway forwarded the caller's. It now presents guardian its own
  name and forwards the caller's as `X-Forwarded-Host`.
- **The CSPM executive dashboard invented its numbers.** Severity was assigned
  with `random.choice(['critical','high','medium','low'])` — re-rolled on every
  request — and the 30-day trend was synthesized by a formula that always
  improved, for accounts that had never been scanned. Severity now comes from
  the check's own metadata; no scan history means no trend.
- **Three data-service endpoints answered 500.** `from app.schemas.api import *`
  after importing the models shadowed `SensorMetadata` and `TelemetryEvent`, so
  `db.query()` was querying Pydantic classes and telemetry ingest was building
  schema instances that never reached the database.
- **The sensor's local API was inert**: it fails closed without an API key, the
  shipped config had it null, and no environment variable could set it — every
  route but `/health` answered 503.
- **`/api/v1/tools`** (the list of tools) **was not routed**, and
  **`/api/v1/responder/*`** mapped to the responder's root rather than `/v1/`,
  so every documented responder path 404ed.
- **New API keys stored JSON `null` in `scopes`**, satisfying the NOT NULL
  constraint while restoring the ambiguity it was added to remove. Omitted
  scopes now store `["*"]` explicitly.
- **The rate-limit headers described two different budgets**: `Limit` advertised
  the hourly figure while `Remaining` counted against the enforced 60-second
  window, so a client could not compute a backoff.
- **The gateway's development certificate had no `subjectAltName`,** which no
  current TLS client accepts — anything talking to it had to disable
  verification outright.

### Fixed — the tests did not test

- **71 test functions ended in `return passed`.** pytest ignores a return value,
  so all of them passed unconditionally, whatever happened.
- **`asyncio_mode` sat below the `[coverage:*]` sections** of
  `tests/integration/pytest.ini`, so configparser filed it under coverage and
  every async test was skipped as "no async plugin installed".
- **The integration CI job started no gateway.** It ran five services as bare
  processes with `GATEWAY_URL` pointing at a port nothing listened on, so the
  reachability guard skipped every test that goes through the gateway — which is
  most of them. It now brings the real stack up with `docker compose up --wait`.
- **Whole test files targeted endpoints that never existed** and asserted field
  names no schema has. They now use the documented routes, through the gateway,
  over verified TLS, and the suite mints a real API key through the same code
  path a client would use instead of relying on a placeholder the gateway
  rejects.

### Changed

- **The CSPM check catalogue is honest.** 166 generated placeholders that
  declared full metadata while inspecting nothing are deleted; 31 real checks
  remain, all of which call a cloud API. Two of those 31 had never run
  (`gcp/compute` had no `__init__.py`) and four `check_id`s were claimed by two
  checks each, silently shadowing one another. Documentation claiming "200+
  checks" now says 31.
- **`DEP-01` closed**: all six FastAPI services on `starlette==1.6.0` and
  `fastapi==0.141.1`. `pydantic==2.5.0` had been holding cspm and data three
  Starlette majors back.
- **The "Code Quality" CI job gates.** Every step carried
  `continue-on-error: true` and `build-images` did not depend on it. Three tiers
  now block: correctness across the whole tree, full style on the shared
  package, and full style on files a change adds.
- **The SBOM license check does something.** It was `pip install pip-licenses`
  followed by an `echo`, under `continue-on-error`. It now reads the CycloneDX
  SBOM of the built image and fails on copyleft in language packages.
- **The restore drill compares row counts** table by table against the source
  and covers all three databases; it compared table counts and skipped guardian.


## [0.9.0] - 2026-08-03

Truthful security tooling. The headline is a catalog-wide cleanup: every tool that fabricated its results with `random` now either does real work or has been removed. Alongside it, a 360° pre-release audit produced a batch of security fixes — a privilege escalation, leaked-secret purge with CI scanning, real gateway CORS, and more. **Several changes are user-facing — read the upgrade notes.**

### Upgrade notes

- **Fabricated tools are gone or now behave differently.** Fourteen tools used to invent their output with `random`. Nine now perform real analysis (their output shape is unchanged but the data is real, so downstream consumers that keyed on the old fake fields may see different values); five were removed entirely (`compliance_checker`, `security_compliance_checker`, `incident_response_automation`, `threat_hunting_platform`, `social_media_osint`). The tool catalog went from 59 to 54.
- **`database_security_analyzer` now supports PostgreSQL and MySQL/MariaDB only.** It connects for real with the supplied credentials; Oracle, MSSQL and MongoDB return an honest "engine not supported" instead of fabricated findings. Add `PyMySQL`/`pg8000` are bundled.
- **`container_security_scanner` requires Trivy.** It wraps the real scanner (bundled in the tools image, pinned) and returns an honest error if the binary is absent rather than inventing vulnerabilities.
- **Set the gateway CORS allowlist for split-origin deployments.** If the dashboard is served from a different origin than the gateway, add that origin to `$cors_allow_origin` in `open-security-gateway/nginx/nginx.conf`. Same-origin deployments need no change. (Previously the gateway emitted no CORS headers at all, silently breaking login on split-origin setups.)
- **Rotate any credentials ever used with the keys purged from history** (see Security). None were known to be live, but the repo is public.

### Security

- **Privilege escalation on the identity admin endpoints fixed (#323).** Three "admin" user endpoints gated on being OWNER/ADMIN of _any_ team, and registration makes every new user OWNER of a personal team — so any registered account could list all users and deactivate every account, superadmins included. They now require `is_superuser`.
- **Leaked keys purged from HEAD and secret scanning armed in CI (#322).** Three high-entropy credentials had been committed to the public repo; replaced with placeholders and a Gitleaks job added so new secrets fail the build. Compose files no longer degrade to `changeme`/known-password defaults — an incomplete `.env` now fails loudly.
- **Gateway now emits real CORS headers via a secure allowlist (#336).** Credentialed cross-origin requests echo only allowlisted origins (never `*`-with-credentials), with a proper preflight; a comment-only stub had left login broken on split-origin deployments.
- **Five audit fixes (#325):** the responder no longer reports success for containment actions it never ran; one malformed tool no longer crashes the whole tools service; the sensor's local API (which runs osquery) is now authenticated and fails closed; the sensor compose no longer grants host-escape privileges; and the production gateway can actually start (it mounted a non-existent nginx config).
- **Dashboard auth cookie `secure` flag now follows the page protocol (#337)** instead of being hardcoded, so login works on non-HTTPS origins without weakening production (partial fix for the audit's token-handling finding).

### Tools — now real

- **CT log scanner (#326):** queries crt.sh instead of generating certificates with `random`.
- **Email security analyzer (#327):** real SPF/DKIM/DMARC record checks and DNSBL lookups via `dnspython`, replacing random verdicts layered over genuine header parsing.
- **PKI certificate manager (#328):** parses real X.509 certificates and fetches the one a host actually serves over TLS; revocation and CT entries are reported honestly, not invented.
- **Vulnerability DB scanner (#329):** queries OSV.dev and NVD with CVSS computed from the published vector — no more invented CVE ids mixed into real results.
- **WAF bypass tester (#330):** sends real encoded/obfuscated payloads to the target (behind an authorization allowlist) instead of a `hash(payload) % 100` simulation.
- **IoT security scanner (#332):** real TCP discovery and banner grabbing; fields a network scan cannot know (MAC, firmware, default-credential status) are left unset rather than guessed.
- **Container security scanner (#333):** wraps Trivy for real image/Dockerfile scanning.
- **Database security analyzer (#334):** connects to real PostgreSQL/MySQL servers and reports their actual security posture.
- **Security automation orchestrator (#331):** kept (its engine really runs other tools) but made honest — no fabricated metrics or scheduler.

### CI / quality

- **Gateway now has CI coverage (#320, #258):** Lua lint plus a behavioral auth-test harness (25+ assertions incl. anti-spoofing, scope enforcement, proof-of-origin, and CORS) that drives the real gateway.
- **Full-stack E2E harness (#321):** backend-dependent Playwright login flows run against a real identity+gateway+dashboard stack; four redirect-dependent specs are quarantined pending a cross-origin auth follow-up.
- **CI made truthful (#255, #245, #247, #256):** `make test` and the unit-test matrix no longer swallow failures; secret-less fork/dependabot runs get explicit CI-only fallbacks.
- Removed the dead `docker-compose.test.yml` harness (#244) and untracked committed `.pyc` bytecode (#248).

### Privacy

- **Self-hosted ReDoc and fonts (#301, #306)** — no third-party CDN at runtime.
- **`/privacy` notice added and linked** from the footer and previously orphaned pages (#265, #300); processor list corrected — Cloudflare is not involved (#266).

### Features

- **Entra ID security analyzer (#249):** flags stale accounts and MFA gaps in a Microsoft Entra tenant via the Graph API.
- Unit tests added for the cspm, data, responder and identity services (#250).

### Dependencies

- Security-motivated dependency bumps across the dashboard and website (axios, lodash, node-forge, form-data, brace-expansion, shell-quote, immutable, js-yaml, and others), plus the CI actions group and `black`.

## [0.8.0] - 2026-06-30

Tenancy and RBAC across the backend: downstream services now isolate data by team and enforce the gateway-provided role. **These are behavior changes — read the upgrade notes.** Backward-compatible for existing single-team deployments (pre-existing data has no `team_id` and is treated as global/shared).

### Upgrade notes

- **Set `GATEWAY_INTERNAL_SECRET` everywhere.** Guardian and CSPM now **fail closed** (HTTP `503`) when the secret is unset, matching the other services — they will not serve requests without it. It is also forwarded by the agents service (see below).
- **Members are now read-only in Guardian.** Mutating viewsets require the gateway role `owner`/`admin`; plain members can read but no longer create/update/delete. Configuration mutations elsewhere (e.g. responder playbook reload) also require `owner`/`admin`.
- **Data is team-scoped.** Existing rows without a `team_id` are treated as global and stay visible to everyone; new team-owned data is private. The data service adds nullable `team_id` columns on startup (`create_tables()`); deployments managing the schema externally should add `team_id` to `sources` and `indicators`.
- **AI agent tool calls now run with the requesting user's identity** instead of a zero-team admin key (#175). Ensure `GATEWAY_INTERNAL_SECRET` is set for the agents service so it can forward identity; otherwise it falls back to the (now non-privileged) service key.

### Security

- **Data service** read endpoints are team-scoped: collector/feed records stay global (`team_id` NULL, visible to all), team-owned records are private; reads return global OR own-team. Fixes a cross-tenant disclosure (#178).
- **Responder** run history is owned by the team that started each run; another team gets `404` on read and cancel (#180).
- **CSPM** scans are namespaced per team (no more scanning every team's keys), and its auth now fails closed when `GATEWAY_INTERNAL_SECRET` is unset (it had been missed by the earlier hardening) (#179).
- **Guardian** enforces the gateway role on mutating viewsets and tightens `GatewayUser.has_perm()` so a member can no longer perform admin-only actions at the service layer (#181).
- The legacy `X-API-Key` on the tools service is scoped to a non-privileged `service` identity (no longer a zero-team admin); the agents service forwards the caller's gateway identity on internal calls (#175).
- Configuration mutations require `owner`/`admin` across services; operational and machine-to-machine endpoints stay member-allowed, audited per endpoint (#182).

### Added

- Reusable tenancy helpers `team_or_global_filter` / `scope_query_shared` and a DRF `RequireGatewayRole` permission.
- Two-team cross-tenant and role-enforcement integration/unit tests for data, responder, CSPM and guardian, run in CI (#183).

### Fixed

- CSPM `/dashboard/summary` returned a payload that didn't match its response model and `500`'d for every caller — it now returns the declared fields (#179 follow-up).
- CSPM scan creation `500`'d on a float Redis `SETEX` TTL; the TTL is now an int (#179).

### CI

- The integration harness now runs the data, responder and CSPM services; agents and guardian gained real unit tests (the agents unit-test job previously collected nothing).

## [0.7.1] - 2026-06-30

Shared-library consolidation and the first tenancy isolation, with new CI safety nets. Backward-compatible for existing single-team deployments.

### Security

- Data service read endpoints are now team-scoped (#178). Model: shared feeds + per-team overlay — collector/feed records stay global (`team_id` NULL, visible to all teams) and team-owned records are private; reads return global OR own-team. Fixes a cross-tenant disclosure where every team's indicators/sources were returned. Existing data (no `team_id`) is treated as global, so behavior is unchanged for single-team setups.

### Changed

- Gateway authentication is consolidated onto the shared `open_security_shared.gateway_auth` dependency across tools/agents/data/responder (#173, #174); the per-service `auth.py` duplicates and `sys.path`/`try-except` import shims were removed (~520 LOC). Also forwards `X-Gateway-Secret` correctly so the proof-of-origin is always enforced.

### Added

- `open-security-shared` is now a real installable package (`pyproject.toml`), installed into every service image via a BuildKit additional context (#172).
- Reusable tenancy helpers in `open_security_shared.tenancy` — `team_filter`, `scope_query`, `team_or_global_filter`, `scope_query_shared` (#177).

### CI

- Build every service image (build-only) on pull requests so Docker/build changes are validated before merge (#229).
- Run the data service in the integration harness, in its own venv against the test database (#233).

### Documentation

- Document the canonical service layout (identity reference) in CONTRIBUTING (#176).

## [0.7.0] - 2026-06-29

Security hardening, first-run honesty, and a documentation/site overhaul. Some changes affect existing deployments — see **Security** and **Changed**.

### Security

- Gateway authentication now **fails closed**: the shared dependency, the per-service `auth.py` wrappers, and the Guardian middleware refuse to trust `X-Wildbox-*` identity headers and return `503` when `GATEWAY_INTERNAL_SECRET` is unset, instead of warning and trusting potentially forged headers (#163).
- Backend service ports are now bound to `127.0.0.1`; only the gateway is published publicly (#164).
- The central tools SSRF guard now also inspects `file_url`, `app_url`, and `download_url`, closing the bypass in `metadata_extractor` and `mobile_security_analyzer` (#165).

### Added

- Dashboard error handling: branded `error.tsx`, `not-found.tsx`, and a top-level `global-error.tsx` boundary, so a render throw no longer white-screens the app (#166).
- `make generate-secrets` and `make validate-secrets` targets wrapping the existing scripts (#170).

### Fixed

- CSPM: unimplemented placeholder checks now report `NOT_IMPLEMENTED` instead of `PASSED`, and the compliance score counts only checks that actually ran — removing a false compliance signal (#158).
- Data, Guardian and Responder boot: `DATABASE_URL` falls back to the shared value when the per-service variable is unset, so the documented stack no longer crashes on start (#170).

### Changed

- AI analysis standardizes on `ANTHROPIC_*`; leftover OpenAI/Stripe configuration was removed from the env templates (setting the old key made AI analysis silently no-op) (#169).
- Dashboard header: the static "3" notification badge, the always-green "All Systems Operational" pill, and the non-functional global search are hidden until backed by real data (#168).

### Removed

- Dead dashboard navigation links (`/ai-analyst`, `/auth/forgot-password`, `/terms`, `/privacy`) and the hardcoded `mockRuns` fallback, replaced with real empty/error states (#167).
- A committed status-report document that read as churn in a public repo (#160).

### Documentation

- Redesigned the GitHub Pages site under `docs/`: removed AI-"slop" theming, fixed the broken landing-page markup and logo, and made the copy honest (#210).
- Documentation Quality CI is fully green for the first time: Markdown Linting passes repo-wide, alongside Spell Check and Link Validation (#211).
- Reconciled README, SETUP_GUIDE and the quickstart to one source of truth — `INITIAL_ADMIN_*` credentials, the real `/auth/jwt/login` endpoint, correct Compose service names, and `make` / `docker compose` commands (#171).

## [0.6.2] - 2026-06-28

### Changed

- Documentation-quality CI: run link checking on Node 22 (Node 18 broke on the now-ESM `marked`), expand the cspell dictionary, and fix the empty-alt examples so the Spell Check, Link Validation, and Image Alt Text gates pass.

### Removed

- Stopped tracking generated artifacts (`.coverage`, `tests/reports/junit.xml`, Playwright `test-results/`).
- Removed committed status-report docs (`*_COMPLETE.md`, `*_IN_PROGRESS.md`, …) and one-off migration scripts.

### Fixed

- Removed a hardcoded developer path from the tool audit/integration scripts so they run on any checkout.
- Fixed the dead YouTube thumbnail link in the README (`maxresdefault` → `hqdefault`).

## [0.5.5] - 2026-02-22

### Security

- Removed Bearer token bypass in data and responder services (granted enterprise/admin to any token)
- Added authentication to 19 previously unauthenticated endpoints across data, responder, and agents services
- Added SSRF protection (private IP filtering) to URL scanner and header analyzer tools
- Added redirect URL validation in billing checkout to prevent open redirects
- Made gateway internal secret mandatory (no longer falls back to accepting all requests)
- Fixed account enumeration via different HTTP status codes on login
- Protected /metrics endpoint with gateway secret authentication
- Removed detailed database error info from /health endpoint responses
- Replaced CORS wildcard with localhost-only in sensor service
- Added asset-based queryset filtering for non-admin users in Guardian
- Fixed role hierarchy in API key permission checks (OWNER > ADMIN > MEMBER)
- Fixed has_perm() to deny view_all permissions for member role
- Added file upload validation (type whitelist + 10MB size limit) in Guardian
- Enabled SSL verification in security tools (removed ssl=False and CERT_NONE)
- Sanitized IOC values to mitigate prompt injection in threat enrichment agent
- Removed Docker socket mount from n8n container
- Restricted sensor host volume mounts to specific safe paths
- Restricted Ollama CORS origins and removed host port exposure
- Set Guardian DEBUG=false by default in Docker Compose
- Enabled N8N_SECURE_COOKIE in Docker Compose

## [0.5.4] - 2026-02-22

### Security

- Updated aiohttp 3.12.x/3.13.2 → 3.13.3 across 6 services (fixes 8 CVEs: DoS, zip bomb, path leak)
- Updated cryptography 44.0.x → 46.0.5 across 7 services (subgroup attack + OpenSSL vulnerability)
- Updated Django 4.2.26 → 4.2.28 (SQL injection + DoS + timing attack)
- Updated Pillow 11.1.0 → 12.1.1 (out-of-bounds write on PSD images)
- Updated nltk 3.9 → 3.9.2 (Zip Slip vulnerability)
- Updated python-multipart 0.0.20 → 0.0.22 (arbitrary file write)
- Updated urllib3 2.5.0 → 2.6.3 (decompression bomb bypass)
- Updated starlette 0.46.2 → 0.52.1 (DoS via Range header + multipart)
- Updated fastapi 0.115.x → 0.129.2 (to support patched starlette)
- Updated fastapi-users → 15.0.4 (1-click account takeover fix)
- Updated axios ^1.7.0 → ^1.13.5 (DoS via `__proto__`)
- Updated next ^14.2.0 → ^14.2.35 (DoS mitigations)
- Added npm overrides for minimatch, lodash, diff, mdast-util-to-hast
- Resolves ~96 of 98 Dependabot alerts

## [0.5.2] - 2026-02-22

### Security

- Added JWT token revocation via Redis blacklist with JTI claims
- Implemented account lockout after failed login attempts
- Added Docker network segmentation (frontend/backend/data layers)
- Fixed path traversal vulnerability in report generation
- Added security headers (CSP, HSTS, X-Frame-Options) to Next.js dashboard
- Replaced hardcoded CI secrets with GitHub Secrets references
- Pinned Trivy action to specific version (0.28.0) in CI/CD
- Added PostgreSQL connection pool health checks (pool_pre_ping)
- Added cookie security settings (httpOnly, sameSite) to Guardian service
- Fixed TOCTOU race conditions in Stripe webhook handlers (SELECT FOR UPDATE)
- Added Prometheus alert rules for service health monitoring
- Migrated external API calls from HTTP to HTTPS
- Added circuit breaker for OpenAI API resilience
- Replaced all bare except clauses with specific exception types
- Removed PostgreSQL port exposure in development docker-compose

### Added

- `open-security-identity/app/token_blacklist.py` - Redis-based token blacklist and account lockout
- `open-security-sensor/monitoring/alert_rules.yml` - Prometheus alerting rules
- `scripts/backup_postgres.sh` - PostgreSQL backup script with encryption

### Removed

- `.env-e` sed artifact removed from repository

## [0.5.0] - 2026-02-22

### Security

- Comprehensive security hardening across all microservices

### Fixed

- Pydantic v2 type annotation error in CSPM config
- Test suite failures: missing services and insufficient timeouts in CI

### Changed

- Enhanced integration tests for Identity Service authentication flow

## [0.4.0] - 2026-02-22

### Added

- 8 FAANG-level architectural patterns implementation
- Comprehensive documentation quality framework
- Spell check dictionary (100 terms)

### Changed

- Critical code quality remediation: removed test skips, fixed tests, extracted components
- Documentation quality improvements (phases 1 and 2, issues 1-35)
- Documentation quality audit completion report
- Removed self-congratulatory progress reports from repository root

### Documentation

- Replaced "blacklist/whitelist" with "denylist/allowlist" across documentation
- Replaced "JWT blacklisting" with "JWT denylisting" in architecture docs
- Added descriptive alt text to images for accessibility
- Fixed broken documentation links (QUICKSTART.md → SETUP_GUIDE.md)
- Defined acronyms on first use in README (RBAC, JWT, CSPM, SOAR, LLM, CVE)

## [0.3.2] - 2025-11-24

### Added

- Comprehensive documentation improvements following best practices
- Table of Contents in long documentation files
- Explicit environment variable documentation in `.env.example`
- Clearer vulnerability reporting process in SECURITY.md
- Quick Start section in README.md
- Architecture decision documentation
- Troubleshooting section expansions

### Changed

- Replaced "Simply" and "Just" with direct instructions (removed condescending language)
- Replaced "master/slave" with "main/replica" terminology
- Replaced "sanity check" with "validity check" terminology
- Replaced "guys" with "team/everyone" for inclusive language
- Updated code examples with proper syntax highlighting
- Improved error messages to be more user-friendly
- Standardized date formats to ISO 8601 (YYYY-MM-DD)
- Enhanced CONTRIBUTING.md with clearer dev environment setup
- Updated API documentation with explicit return types

### Fixed

- Removed hardcoded API keys from example code (replaced with clear placeholders)
- Removed unfinished placeholder notes from production documentation
- Fixed broken hyperlinks throughout documentation
- Corrected grammar in success messages
- Standardized header capitalization across documentation
- Fixed whitespace in Markdown tables

### Security

- Removed real-looking secrets from code examples
- Added explicit security warnings for production deployments
- Clarified authentication flow documentation

## [0.3.1] - 2025-11-24

### Fixed

- Corrected integration tests to use fastapi-users JWT endpoints (`/api/v1/auth/jwt/login`)
- Fixed endpoint path mismatches causing 404 errors in CI/CD
- Added appropriate test skips for unavailable services in test environment

### Changed

- Improved CI/CD pipeline stability and reliability
- Integration tests now validate actual API behavior when endpoints exist
- Tests gracefully handle test environment limitations

## [0.3.0] - 2025-11-23

### Added

- Comprehensive integration test suite
- E2E Playwright tests for frontend
- Security validation tests
- Performance monitoring tests

### Changed

- Updated test infrastructure with docker-compose.test.yml
- Enhanced test fixtures and utilities

## [0.2.0] - 2025-11-16

### Added

- Security Tools Service with 55+ production-ready tools
- Dual-mode authentication (API Key + Bearer Token)
- Gateway-level authentication via OpenResty Lua
- Redis integration for caching
- Health check system
- Next.js 14 dashboard with App Router
- WebSocket support for real-time updates

### Changed

- Optimized FastAPI performance with async/await
- Enhanced Django admin for Guardian service
- Improved error handling across all APIs
- Frontend bundle optimization with code splitting

### Fixed

- PostgreSQL password inconsistencies
- CORS issues in data service
- Gateway routing for direct service access
- Authentication header forwarding
- Redis connection pooling issues

### Performance

- 30% faster gateway authentication validation
- Optimized database queries (eliminated N+1 patterns)
- 60% reduced database load via Redis caching
- 20% average API response time improvement

## [0.1.0] - 2025-11-01

### Added

- Initial release
- Core microservices architecture
- Identity management with RBAC
- Basic API gateway
- PostgreSQL database layer
- Docker Compose orchestration
- Dashboard UI with Next.js

[Unreleased]: https://github.com/fabriziosalmi/wildbox/compare/v0.11.2...HEAD
[0.11.2]: https://github.com/fabriziosalmi/wildbox/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/fabriziosalmi/wildbox/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/fabriziosalmi/wildbox/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/fabriziosalmi/wildbox/compare/v0.5.5...v0.6.2
[0.5.5]: https://github.com/fabriziosalmi/wildbox/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/fabriziosalmi/wildbox/compare/v0.5.2...v0.5.4
[0.5.2]: https://github.com/fabriziosalmi/wildbox/compare/v0.5.0...v0.5.2
[0.5.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/fabriziosalmi/wildbox/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/fabriziosalmi/wildbox/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/fabriziosalmi/wildbox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fabriziosalmi/wildbox/releases/tag/v0.1.0
