# Deployment Guide

How to run Wildbox on a server you control. Wildbox is in an early evaluation
phase: it is suitable for testing, staging and community deployments, and
real-world deployment feedback is welcome in
[Discussions](https://github.com/fabriziosalmi/wildbox/discussions) and
[Issues](https://github.com/fabriziosalmi/wildbox/issues).

This guide builds on the [Quick Start](quickstart.md); read it first. Ports
and service names are listed once, in [Service ports](ports.md).

---

## 1. Server Requirements

- Linux with Docker Engine 23.0 or later and the Compose plugin 2.24.4 or
  later:
  - Compose 2.24.4, because `docker-compose.prod.yml` uses the `!override`
    tag, which older versions reject;
  - Engine 23.0, because the images are built with named build contexts
    (`additional_contexts` in `docker-compose.yml`, to copy
    `open-security-shared` into each service). Named contexts need BuildKit
    0.10 (Dockerfile frontend 1.4), and Engine 23.0 is the first release
    that ships it and builds with BuildKit by default
- 8 GB RAM minimum (16 GB recommended), 50 GB SSD
- A DNS name for the server and a TLS certificate for it
- Somewhere off the server to keep backups

Open only what the gateway needs. Every other service is bound to `127.0.0.1`
by `docker-compose.yml`, and PostgreSQL and Redis publish nothing:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp     # SSH; restrict to your addresses if you can
sudo ufw allow 443/tcp    # HTTPS through the gateway
sudo ufw allow 80/tcp     # optional: /health and the redirect to HTTPS
sudo ufw enable
```

Docker publishes ports through its own iptables rules, which can bypass ufw.
That is why the backend ports are bound to `127.0.0.1` in the Compose file;
do not change those bindings.

---

## 2. Get the Code and Generate Secrets

```bash
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox
make generate-secrets
make validate-secrets
```

Then edit `.env` and set the values that describe your deployment rather
than secrets:

- `INITIAL_ADMIN_EMAIL`: the first administrator's login
- `CORS_ORIGINS`: the other HTTPS origins whose pages may call the API from
  a browser, comma-separated, for example `https://wildbox.example.com`
  (here and below, replace `wildbox.example.com`, a name reserved for
  documentation, with your host name). The production overlay passes it to
  identity, tools, guardian, responder and agents, and `docker-compose.yml`
  to data; identity also accepts a JSON list. It can be left empty when the dashboard and the API share the
  gateway's origin, as they do in this stack: an empty value allows no
  cross-origin requests, and same-origin requests need none
- `ENVIRONMENT=production` (the template default)
- `NEXT_PUBLIC_GATEWAY_URL`: leave it empty. The gateway serves the
  dashboard, and an empty value makes the dashboard call the API on the
  origin it was loaded from. See [The dashboard's browser
  settings](#the-dashboards-browser-settings) for when to set it

Do not generate secrets by hand or copy them from documentation. The
[Credentials guide](credentials.md) explains every generated value and how to
rotate it.

---

## 3. TLS Certificate

The gateway reads its certificate from `open-security-gateway/ssl/`, mounted
at `/etc/ssl/wildbox/`:

- `open-security-gateway/ssl/wildbox.crt`: certificate, with the full chain
- `open-security-gateway/ssl/wildbox.key`: private key

If neither file exists when the gateway starts, it generates a self-signed
development certificate there. For a real deployment, put your certificate in
place before the first start, for example from Let's Encrypt:

```bash
sudo certbot certonly --standalone -d wildbox.example.com
sudo install -m 0644 /etc/letsencrypt/live/wildbox.example.com/fullchain.pem \
  open-security-gateway/ssl/wildbox.crt
sudo install -m 0600 /etc/letsencrypt/live/wildbox.example.com/privkey.pem \
  open-security-gateway/ssl/wildbox.key
```

TLS terminates at the gateway; no other proxy is needed in front of it.

`certbot --standalone` needs port 80 free, so run it before the stack starts or
stop the gateway while it renews. After replacing the files, restart the
gateway: `docker compose restart gateway`.

---

## 4. Start the Stack

`make start-prod` composes `docker-compose.yml` with `docker-compose.prod.yml`
(`restart: always`, log rotation, tuned connection limits, and network
segmentation: only the gateway and the dashboard share the public-facing
network, and PostgreSQL and Redis sit on an internal network reachable only
by the services that use them; the map is at the top of
`docker-compose.prod.yml`). To check it on a host:
`python3 scripts/check_network_segmentation.py config`, and with the stack
running, `COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml python3
scripts/check_network_segmentation.py runtime`.

```bash
make start-prod
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
```

Databases are created by `scripts/init-databases.sql` on PostgreSQL's first
start, and the identity service creates the first administrator from
`INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD`. Nothing needs to be created
by hand.

Optional services:

```bash
docker compose --profile automations up -d   # n8n workflows
docker compose --profile monitoring up -d    # Prometheus and Alertmanager (section 7)
docker compose --profile backup up -d        # scheduled PostgreSQL backups
```

### The dashboard's browser settings

The dashboard is a Next.js application, and Next.js writes every
`NEXT_PUBLIC_*` variable into the JavaScript it sends to the browser when the
image is **built**. The production overlay passes them as build arguments,
read from `.env`; setting them on the running container changes nothing.
After changing one, rebuild the dashboard image:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml build dashboard
make start-prod
```

| Variable | Default | Set it when |
|----------|---------|-------------|
| `NEXT_PUBLIC_GATEWAY_URL` | empty: the API is called on the dashboard's own origin | the dashboard is served from a different origin than the gateway. Use the gateway's public HTTPS origin, for example `https://api.wildbox.example.com`; it is also added to the dashboard's Content-Security-Policy `connect-src` |
| `NEXT_PUBLIC_USE_GATEWAY` | `true` | never in production; `false` is for development against a bare service |
| `NEXT_PUBLIC_APP_URL` | empty (`http://localhost:3000` in page metadata) | you want absolute links in the page metadata to name your host, for example `https://wildbox.example.com` |

In this stack the gateway serves the dashboard and the API on one origin, so
the defaults are what a deployment needs, whatever host name it is reached
by. Images built before this setting existed fell back to
`http://localhost:80`: in a browser on any other machine every API call,
the login first, went to that machine and failed.

### The gateway's per-team rate limit

`RATE_LIMIT_PER_HOUR` in `.env` is the number of API requests a team may make
in an hour, through the gateway, on every authenticated route. The default is
10000. The gateway enforces it per minute, as one sixtieth of the hourly
figure (at least one request a minute), and reports it on every response in
`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` and
`X-RateLimit-Policy`. The value must be a whole number between 1 and
1000000000: with any other value the gateway logs
`RATE_LIMIT_PER_HOUR must be a whole number ...` and does not start. Restart
the gateway after changing it (`docker compose up -d gateway`).

### Guardian's per-user rate limit

Under the gateway's limit, guardian allows each user
`GUARDIAN_RATE_LIMIT_USER` requests to its own API: `1000/hour` unless `.env`
sets it. The value is `<count>/<period>` with a period of `second`, `minute`,
`hour` or `day` (for example `20/minute`), or `off` to rely on the gateway's
limit alone. The count is kept per user, as the gateway identifies the user,
so one member of a team cannot use up guardian for the others. With any other
value guardian logs `GUARDIAN_RATE_LIMIT_USER=...: expected <count>/<period>
...` and does not start. Restart guardian after changing it
(`docker compose up -d guardian`). Guardian's health check is not rate
limited.

### Redis memory

Redis is not a cache here. It holds the token blacklist, failed-login lockout
counters, Celery and Dramatiq queues and results, and scan, run and task state
that exists nowhere else. It therefore runs with
`--maxmemory-policy noeviction`, in production as in development: an eviction
policy would delete those keys under memory pressure, so a revoked token
would work again and a lockout would lift early.

What happens at the limit: once the dataset reaches `REDIS_MAXMEMORY`, Redis
refuses every command that would add memory with
`OOM command not allowed when used memory > 'maxmemory'`. Reads, deletes and
`PING` keep working, nothing already stored is lost, and Redis and its health
check stay up. The service that issued the write gets the error, so new tasks
cannot be queued and new state cannot be recorded until memory is freed or
the limit is raised. Raise it and restart Redis:
`docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d wildbox-redis`.

Two settings in `.env` size it:

| Variable | Default | Meaning |
| --- | --- | --- |
| `REDIS_MAXMEMORY` | `1gb` | The dataset ceiling at which writes are refused |
| `REDIS_MEMORY_LIMIT` | `2g` | The container's memory limit |

Keep `REDIS_MEMORY_LIMIT` at least twice `REDIS_MAXMEMORY`. `maxmemory`
bounds the dataset, not the process: an AOF rewrite forks, and copy-on-write
under writes can double resident memory. When the container limit is lower,
the kernel kills Redis (exit 137) before `noeviction` gets to refuse anything,
and up to the last second of writes (`appendfsync everysec`) is lost. Measured on `redis:7-alpine`
with a 128 MB `maxmemory`: a limit equal to it was OOM-killed while filling,
a limit of 1.5x was killed during an AOF rewrite, and at 2x Redis refused the
excess writes and stayed up. Check a configuration before starting it:

```bash
python3 scripts/check_redis_config.py config --env-file .env
```

Monitor the headroom and alert well before the ceiling, for example when
`used_memory` passes 80% of `maxmemory`, and on any increase of
`errorstat_OOM`, the count of refused writes:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec \
  -e REDISCLI_AUTH="$REDIS_PASSWORD" wildbox-redis \
  sh -c 'redis-cli INFO memory | grep -E "^(used_memory|maxmemory):"; redis-cli INFO errorstats'
```

With the stack running,
`COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml python3
scripts/check_redis_config.py runtime --env-file .env` reads the live settings
and the applied limit and prints the memory in use and its peak.

### guardian's scheduled tasks

`guardian-beat` sends guardian's periodic tasks to `guardian-worker`. The
schedule is defined in `open-security-guardian/guardian/schedule.py`; when
`guardian-beat` starts it writes each entry into django-celery-beat's
`PeriodicTask` table, where the Django admin shows it. Crontab times are in
`CELERY_TIMEZONE`, UTC unless set.

| Task | Default | Why | Variable |
| --- | --- | --- | --- |
| SLA violation check | every 15 minutes | The shortest SLA is 4 hours (P1), so a breach is reported within 15 minutes of it. The assignee is e-mailed at most once every 24 hours per vulnerability, however often the check runs (see Notification recipients) | `GUARDIAN_SCHEDULE_SLA_CHECK` |
| Alert rules | every 15 minutes | A condition is noticed within 15 minutes of becoming true. A rule notifies when it starts firing and when it recovers, not on every evaluation (below), so a shorter interval detects sooner without sending more mail | `GUARDIAN_SCHEDULE_ALERT_RULES` |
| Risk score recalculation | daily, 02:00 | A full pass over open vulnerabilities, so off-peak. Edits and threat-intel enrichment already recalculate one vulnerability at a time; the pass catches what does not, such as a change to an asset's criticality | `GUARDIAN_SCHEDULE_RISK_SCORES` |
| Expired report cleanup | daily, 03:00 | Reports expire 30 days after generation; a day's precision is enough | `GUARDIAN_SCHEDULE_REPORT_CLEANUP` |
| Vulnerability history cleanup | daily, 03:30 | One year of history is kept; running daily keeps each deletion to one day of rows | `GUARDIAN_SCHEDULE_HISTORY_CLEANUP` |
| Asset inventory | daily, 04:30 | Marks assets not seen for 30 days inactive | `GUARDIAN_SCHEDULE_ASSET_INVENTORY` |
| Overdue compliance assessments | daily, 08:00 | Prepares one reminder per overdue assessment on every run, at the start of the working day. Compliance notifications have no recipients yet, so none is e-mailed (see Notification recipients) | `GUARDIAN_SCHEDULE_OVERDUE_ASSESSMENTS` |
| Expiring compliance exceptions | Mondays, 08:00 | Looks 30 days ahead and prepares a reminder on every run: weekly gives about four reminders per exception, daily would give thirty. Not e-mailed, like the reminder above | `GUARDIAN_SCHEDULE_EXPIRING_EXCEPTIONS` |
| User-defined schedules | every minute | Queues the discovery rules and report schedules that are due (below). Their cron fields have a one-minute resolution, so each starts within a minute of its time; a sweep that finds nothing due is two indexed queries | `GUARDIAN_SCHEDULE_USER_SCHEDULES` |

To change one, set its variable in `.env` and restart the scheduler:

```bash
# Every 10 minutes; five crontab fields; or off.
GUARDIAN_SCHEDULE_SLA_CHECK=600
GUARDIAN_SCHEDULE_REPORT_CLEANUP="15 1 * * *"
GUARDIAN_SCHEDULE_EXPIRING_EXCEPTIONS=off
```

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d guardian-beat
docker compose logs guardian-beat
```

- A value is a number of seconds, five crontab fields (`minute hour
  day-of-month month day-of-week`) or `off`, which disables the task. An
  invalid value stops `guardian-beat` at start-up with the variable's name in
  the error.
- The variables are the source of truth. An edit to one of these entries in
  the Django admin lasts until `guardian-beat` restarts, when the configured
  value is written back.
- A run that is still queued when the next one is due (for the daily and
  weekly tasks, an hour after its slot) is dropped rather than run late, so a
  worker that was down does not come back to a burst of identical reminders.
  The sweeps that send notifications or rewrite every vulnerability also skip
  a run while another one is still in progress.
- Run exactly one `guardian-beat`. Beat has no leader election: a second
  instance would send every task twice. The service has a fixed container
  name, so `--scale guardian-beat=2` fails.
- Its health check reads a heartbeat file the scheduler refreshes after every
  tick (at least every 5 seconds); the container turns unhealthy when the file
  is older than a minute, that is when beat is running but no longer
  scheduling.
- The SLA and assignment e-mails prefix their vulnerability link with
  `GUARDIAN_BASE_URL`; unset, the link is a relative path.

#### Schedules defined through the API

The dispatcher in the last row runs the schedules users create:

| Schedule | Defined by | Runs | What can be scheduled |
| --- | --- | --- | --- |
| Asset discovery rule (`/api/v1/guardian/assets/discovery-rules/`) | `schedule`: five crontab fields, in `CELERY_TIMEZONE` (UTC unless set), with the same syntax as the variables above | the rule's network scan, on the `scanning` queue | `network_scan` rules only. Cloud API and CMDB discovery are placeholders and agent reports and DNS zone transfers have no code, so the API refuses those types |
| Report schedule (`/api/v1/guardian/reports/schedules/`) | `next_run` (the first run) and `frequency`: once, daily, weekly, monthly or quarterly | a report, generated on the `reporting` queue and e-mailed to the schedule's `recipients` when it is ready; a schedule without recipients sends no e-mail (see Notification recipients) | vulnerability summary, asset inventory, compliance status and executive dashboard reports, as JSON or HTML. The other report types have no data behind them and the other formats are not written yet, so the API refuses them |
| Scan schedule (`/api/v1/guardian/scanners/scan-schedules/`) | `cron_expression` | nothing | nothing: guardian cannot start a scan on an external scanner yet, so creating, changing, triggering or enabling one answers 400. Existing ones can still be listed, disabled and deleted |

- Each due time runs once. The dispatcher claims a run by moving `next_run`
  on in the same statement that checks it, so two overlapping sweeps, or a
  sweep and a manual run, cannot both queue it; `last_run` records when it
  was queued.
- A schedule that missed several runs (guardian was down, or the schedule
  was paused) runs once and then continues from the next run after now; the
  missed ones are not replayed. A one-off report schedule is set to
  `disabled` once it has run.
- An invalid cron expression is refused by the API. One written another way
  (the admin) is logged by every sweep and never run.
- Reports are written to the `guardian_media` volume, which `guardian-worker`
  (which generates them) and `guardian` (which serves their downloads) share.

#### Alert rules

An alert rule (`/api/v1/guardian/reports/alerts/`) names a metric in
`data_source`, narrows it with filters in `condition_config`, and fires when
the value compares with `threshold_value` as `operator` says (`gt`, `gte`,
`lt`, `lte`, `eq`, `ne`). Only `threshold` conditions are evaluated; the API
refuses `change`, `trend` and `anomaly`, and any metric or filter not listed
here.

| Metric | Value | Filters |
| --- | --- | --- |
| `vulnerabilities.unresolved` | vulnerabilities open or in progress | `severity` (list), `asset` (id) |
| `vulnerabilities.overdue` | open vulnerabilities past their due date, as the SLA check counts them | `severity`, `asset` |
| `vulnerabilities.max_risk_score` | highest risk score (0-10) among unresolved vulnerabilities, 0 when there are none | `severity`, `asset` |
| `compliance.non_compliant_results` | compliance results found non-compliant | `risk_level` (list) |
| `compliance.overdue_assessments` | planned or in-progress assessments past their due date | none |

For example, "more than 5 unresolved critical vulnerabilities":
`{"data_source": "vulnerabilities.unresolved", "condition_config":
{"severity": ["critical"]}, "condition_type": "threshold", "operator": "gt",
"threshold_value": 5}`.

- A rule notifies when it starts firing, once when it recovers, and while it
  keeps firing at most once per `GUARDIAN_ALERT_RENOTIFY_INTERVAL` (seconds,
  default 86400, or `off` for no reminders). A day, because a condition still
  true after a day is a backlog to be reminded of, like the SLA check's daily
  reminder, and not news every 15 minutes.
- Notifications are e-mailed to `notification_config.recipients`. A rule
  that names none sends no e-mail (see Notification recipients). Each
  notification is recorded, delivered or not, and
  `GET /api/v1/guardian/reports/alerts/{id}/notifications/` lists them.
- The rule shows its `state` (`ok` or `firing`), `firing_since`,
  `last_value` and `last_evaluated_at`. `trigger_count` counts the times it
  started firing.

#### Team memberships

guardian lets a team name only its own members: as the assignee of a
vulnerability, the owner of an asset, the people a dashboard is shared with.
identity owns memberships, so guardian learns of them in two ways:

- Every request the gateway authenticates tells guardian that the user is
  in the team now. guardian counts a user as a member for
  `GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS` from their last request.
- When a member is removed from a team, or an account is deleted, identity
  tells guardian at `GUARDIAN_INTERNAL_URL`, after it has made the change.
  guardian stops accepting the user at once and clears the roles they held
  in that team.

| Variable | Read by | Default | Meaning |
| --- | --- | --- | --- |
| `GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS` | `guardian`, `guardian-worker`, `guardian-beat` | `30` | Days a user stays one of a team's users without making a request in it, from 1 to 365. Any other value stops the three containers at start-up: there is no way to switch the window off, since that would keep a former member for good. Shorter bounds a lost notice more tightly; a member who has not opened guardian for longer than this cannot be assigned work until their next request |
| `GUARDIAN_INTERNAL_URL` | `identity` | `http://open-security-guardian:8013/internal/team-memberships/revoke/` | Where identity tells guardian that a membership ended. Set it to an empty value only in a deployment that does not run guardian: identity then sends nothing |

- The notice does not go through the gateway, which proxies guardian's
  `/api/v1/` only. identity and guardian share a network in both Compose
  files, and guardian refuses the notice without `GATEWAY_INTERNAL_SECRET`,
  which both already have.
- Removing a member does not wait for guardian. If guardian does not
  confirm the notice (three attempts), the member is removed all the same
  and identity logs an error that begins `guardian was not told of`. The
  gateway already refuses the member, and guardian stops counting them when
  the window runs out. To apply the notice without waiting, run it by hand
  in guardian's container, with the ids from identity:

  ```bash
  docker compose exec guardian python manage.py revoke_team_membership \
    --team <team UUID> --user <user UUID>
  # an account that was deleted:
  docker compose exec guardian python manage.py revoke_team_membership \
    --user <user UUID> --all-teams
  ```

  `--dry-run` reports what would be cleared and changes nothing. Use it
  only for a user identity has removed: the roles it clears do not come
  back.
- Deactivating an account sends no notice: the account keeps its
  memberships and can be reactivated. It cannot make requests, so it stops
  counting in guardian when the window runs out.
- After the upgrade, an existing membership counts from the day guardian
  first saw the user, not from the upgrade. A member who has used guardian
  since is unaffected; one first seen more than 30 days ago is counted
  again from their next request.

#### Notification recipients

guardian e-mails a notification to the recipients its own team named, and to
nobody else. There is no platform-wide recipient: the
`DEFAULT_NOTIFICATION_RECIPIENTS` and `SECURITY_TEAM_EMAIL` settings that
earlier versions looked for are no longer read, and defining them changes
nothing. One address for the whole platform would receive every team's asset
names, vulnerability titles and findings.

| Notification | Sent to | Without a recipient |
| --- | --- | --- |
| Alert rule | the rule's `notification_config.recipients` | not sent; the notification is recorded with `delivered: false` and listed by `GET /api/v1/guardian/reports/alerts/{id}/notifications/` |
| Scheduled report | the schedule's `recipients` | not sent; the report is generated and listed, and `guardian-worker` logs a warning that names the schedule |
| SLA violation | the vulnerability's assignee, while they are a member of its team and the account has an e-mail address | not sent; the vulnerability's history (`GET /api/v1/guardian/vulnerabilities/{id}/history/`) records the violation once, as `SLA violation notification not sent (no assignee to e-mail)`, and `guardian-worker` logs a warning |
| Vulnerability assignment | the assignee, while they are a member of the vulnerability's team and the account has an e-mail address | not sent; `guardian-worker` logs a warning |
| Compliance (high-risk finding, assessment started, completed or overdue, exception expiring) | nobody: an assessment, a result and an exception name no recipients | not sent; `guardian-worker` logs `Notification not sent, it has no recipients (compliance)` with the subject |

- An account has an e-mail address in guardian only if an operator set one
  on its user in the Django admin: guardian mirrors the identity service's
  users by id and does not copy their addresses.
- An SLA violation whose e-mail could not be delivered is recorded as
  `not sent (delivery failed)` and tried again a day later.

### cspm's scan worker

`cspm-worker` runs the cloud security scans that `cspm` queues, one at a
time per worker process. It uses cspm's image and settings and, in the
production overlay, sits on `data` (Redis) and `egress` (the cloud provider
APIs). Without it every scan stays `queued`, and the compliance pages, the
cloud security overview and the reports have nothing to show.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CSPM_SCAN_TIMEOUT_SECONDS` | `3600` | Time limit of one scan, from 120 to 86400 seconds. The worker is also given this long to stop, so `docker compose stop` or `down` can wait this long while a scan runs |
| `CSPM_REPORT_RETENTION_DAYS` | `90` | Days a scan and its report are kept in Redis; see [Redis memory](#redis-memory) |

Check that it is up and reading its queue:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps cspm-worker
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec cspm-worker \
  sh -c 'celery -A app.worker:celery_app inspect active_queues -d "celery@$HOSTNAME"'
```

The second command lists one queue, `celery`. `GET /health` on cspm also
reports `"celery": "healthy"` once a worker answers.

- **Capacity.** One worker runs two scans at once (`--concurrency=2`, one
  CPU, 1 GB). For more, run more workers,
  `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale cspm-worker=3`,
  or raise the concurrency together with the container's limits. The cspm
  README, "The scan worker", compares the two.
- **Credentials.** The API keeps a scan's encrypted credentials in Redis for
  five minutes; a scan that no worker takes within that time fails. The
  worker deletes them as soon as it has read them.
- **Providers.** Only AWS can be scanned. A scan for GCP or Azure is
  refused with 400 when it is submitted ("Unsupported provider: gcp.
  Supported providers: aws."), before anything is stored or queued, and a
  batch that names one is refused whole. `GET /api/v1/cspm/providers` lists
  the providers that can be scanned, with their number of checks.

### The responder's playbooks

A playbook run calls the tools, data, guardian and agents services as the
user who started it: each request carries that user's gateway identity and
`GATEWAY_INTERNAL_SECRET`, and the service authorizes it for that user and
team. The playbook worker runs inside the `responder` container, so the
container's environment is what it uses.

| Variable | Default | Meaning |
| --- | --- | --- |
| `RESPONDER_WILDBOX_API_URL` | `http://open-security-tools:8000` | Tools service, passed as `WILDBOX_API_URL` |
| `RESPONDER_WILDBOX_DATA_URL` | `http://open-security-data:8002` | Data service, passed as `WILDBOX_DATA_URL` |
| `RESPONDER_WILDBOX_GUARDIAN_URL` | `http://open-security-guardian:8013` | Guardian, passed as `WILDBOX_GUARDIAN_URL` |
| `RESPONDER_WILDBOX_AGENTS_URL` | `http://open-security-agents:8006` | Agents service, passed as `WILDBOX_AGENTS_URL` |

The defaults are the services' addresses in both compose files. In the
production overlay the responder reaches them on `backend`;
`scripts/check_network_segmentation.py runtime` checks that it does.

- **Permissions follow the user.** A step the user may not take fails:
  Guardian lets only owners and admins create a vulnerability, so
  `all_star_e2e` records none when a member runs it.
- **Results belong to the user.** A tool task or an AI analysis a run
  queues is listed and readable by the user who ran it, and by nobody else.

### The agents service's tools and limits

The AI analysis calls the tools service, and the data and guardian services
when you enable their tools, as the user who submitted it: each request
carries that user's gateway identity and `GATEWAY_INTERNAL_SECRET`. Set
these in `.env`; both compose files pass them to the `agents` container.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WILDBOX_API_URL` | `http://api:8000` | Tools service |
| `AGENT_TEAM_DATA_TOOLS` | empty | The team-data tools the model is given; see below before setting it |
| `AGENTS_WILDBOX_DATA_URL` | `http://open-security-data:8002` | Data service, passed as `WILDBOX_DATA_URL`; the threat-indicator search |
| `AGENTS_WILDBOX_GUARDIAN_URL` | `http://open-security-guardian:8013` | Guardian, passed as `WILDBOX_GUARDIAN_URL`; the vulnerability search. The host must be in Guardian's `ALLOWED_HOSTS` |
| `ANALYZE_RATE_LIMIT` | `5/minute` | Analyses each user may submit, in the `limits` notation (`5/minute;50/day` for several) |
| `ANALYZE_TEAM_RATE_LIMIT` | empty | Optional ceiling for all users of one team together |

A URL that is not an absolute `http` or `https` URL, a limit that cannot be
parsed, or an `AGENT_TEAM_DATA_TOOLS` value that names anything but the two
tools stops the agents service at start. The limit counters are kept in
Redis and survive a restart. In the production overlay the agents service
reaches the three services on `backend`;
`scripts/check_network_segmentation.py runtime` checks that it does.

#### Giving the AI analysis your team's data

By default an analysis looks the indicator up outside (reputation, WHOIS,
DNS, geolocation, redirects, open ports) and reads nothing Wildbox holds.
Two more tools exist, and the model is given one only if you name it:

```bash
# .env; either name alone, or both
AGENT_TEAM_DATA_TOOLS=threat_intel_query_tool,vulnerability_search_tool
```

- `threat_intel_query_tool` searches the data service's indicators: those
  of the user's team and of the feeds shared by every team.
- `vulnerability_search_tool` searches the vulnerabilities Guardian
  records on the team's assets.

Both act as the user who submitted the analysis, so they return what that
user may see. Decide with these two facts in hand:

- **What it sends to Anthropic.** Every tool output is part of the
  conversation with the model. For each search the model makes, and it
  chooses the search text and may search several times: up to 25
  indicators (type, value, threat types, confidence, severity, description,
  tags, dates), or up to 25 vulnerabilities (title, CVE ID, severity,
  status, priority, scores, asset name and type, due date), and the number
  of matches.
- **The injection risk.** That data then sits in the model's context beside
  text the other tools fetched from the internet: WHOIS records, DNS
  answers, and the redirects and headers of the URL being analyzed. The
  model also holds tools that reach outside, with arguments it writes
  (`url_analysis_tool`, `dns_lookup_tool`, `whois_lookup_tool`). Someone
  who controls the fetched text can write it as instructions, asking the
  model to search your vulnerabilities and pass the result out in one of
  those arguments. The prompt tells the model to treat tool output as data
  and not to do this; that is a request to the model, not a control.

With the setting empty, neither tool is in the model's tool list or its
prompt, and the agents service makes no request to the data service or to
Guardian.

### Internal targets of the network tools

The network tools (port and vulnerability scanners, the TLS and
certificate analyzers, `network_scanner`, `iot_security_scanner`,
`database_security_analyzer`, `dns_enumerator`, and the image registry of
`container_security_scanner`) refuse internal targets: private, loopback,
link-local, multicast, reserved and shared addresses, ranges that contain
one, names that resolve to one, and the stack's own service names. A
range holds at most 1024 addresses. A synchronous run that is refused
answers 400 with the reason; an asynchronous run ends as a task with status
`failed` and the reason in `error`.

To scan an internal lab, list its ranges and hosts in `.env`, then
recreate `api` and `tools-worker`:

```bash
TOOLS_ALLOWED_INTERNAL_TARGETS=10.20.0.0/16,192.168.50.0/24,lab-dc01
```

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d api tools-worker
```

- **Entries.** CIDR ranges with their host bits zero, IP addresses and
  host names, comma-separated. A name is matched exactly. A bad entry
  stops both containers at start-up; `docker compose logs api` names it.
- **Keep the stack out.** Every caller of every network tool can scan
  what is listed. Do not list the stack's Docker networks (by default in
  `172.16.0.0/12`); its service names stay refused unless listed by name.

The tools README, "Network targets", lists the fields checked per tool.

### The sensor's telemetry

The `sensor` service sends host telemetry to the gateway,
`https://open-security-gateway/api/v1/data/ingest`, authenticated with an
identity personal API key; the data service stores it under the key's team.
It trusts the gateway's certificate, which the gateway copies (never its key)
into the `gateway_cert` volume at every start, so a certificate you replace
under `open-security-gateway/ssl/` reaches the sensor at the next restart of
both. In the production overlay the sensor is on `frontend` with the gateway:
it reaches no backend service directly.

It forwards nothing until it has a key:

1. As a team owner or admin, add a member for the sensor (Settings > Team >
   Add member) in the team the telemetry belongs to, and sign in as it once
   to change its password.
2. As that member, create a personal API key with the **Telemetry Ingest**
   (`data:ingest`) scope only (Settings > API keys).
3. Put it in `.env` and restart the sensor:

   ```bash
   SENSOR_DATA_LAKE_API_KEY=wsk_...
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d sensor
   docker compose -f docker-compose.yml -f docker-compose.prod.yml exec sensor \
     python main.py --config /etc/security-sensor/config.yaml --test-connection
   ```

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENSOR_DATA_LAKE_API_KEY` | empty | The sensor's key. Empty: the sensor runs and forwards nothing |
| `SENSOR_DATA_LAKE_ENDPOINT` | `https://open-security-gateway` | The gateway's HTTPS URL as the sensor reaches it |
| `SENSOR_DATA_LAKE_CA_BUNDLE` | `/etc/ssl/wildbox/wildbox.crt` | The certificate the sensor trusts for the gateway. Set it to an empty value to use the system trust store instead |
| `SENSOR_DATA_LAKE_SENSOR_ID` | `open-security-sensor` | The sensor's name in the data service, unique within the team |

Revoking the key, or removing the member from the team, stops the sensor's
telemetry at its next batch. Sensors on other hosts are set up the same way;
see the sensor README, "Sending telemetry to Wildbox".

---

## 5. Verify

```bash
curl -s http://localhost/health                      # gateway
curl -sI https://wildbox.example.com/ | head -20     # TLS and security headers
```

Then log in through the gateway with the sequence in the
[Quick Start](quickstart.md#5-log-in-and-call-the-api), using your host name
and dropping `--cacert` once the certificate is publicly trusted. The health
loop on the [Service ports](ports.md#checking-the-stack) page checks every
backend from the server itself.

---

## 6. Backups and Restore

```bash
make backup          # PostgreSQL and Redis, into ./backups
make restore-drill   # prove the PostgreSQL backup restores
```

Both work on the default stack with nothing but Docker on the host. They run
`pg_dump`, `pg_restore`, `psql` and `redis-cli` inside the stack's own
containers with `docker compose exec`, so the database port stays
unpublished, no client tools are installed, and no password is passed on a
command line. Set `COMPOSE_FILE` (and `COMPOSE_PROJECT_NAME`, if you use one)
the way you start the stack; `ENV_FILE` names the env file when it is not
`.env`.

### What a backup contains

`scripts/backup_postgres.sh` writes one set of files per run, named by the
run's timestamp:

| File | Contents |
| :--- | :--- |
| `identity_<stamp>.sql.gz`, `data_<stamp>.sql.gz`, `guardian_<stamp>.sql.gz` | A `pg_dump` custom-format archive of each database. |
| `redis_<stamp>.rdb.gz` | An RDB snapshot of every Redis database. |

Redis is in the backup because it is not a cache here. It holds the only
copy of CSPM scan metadata and reports, responder playbook run state, agents
analysis results, tools task ownership, identity's revoked-token list and
account lockouts, and the Celery queues.

A run either completes or keeps nothing: if any database or Redis fails, the
script exits non-zero and removes the files it wrote, so every timestamp in
the directory is a complete set. Leaving Redis out is something you ask for
with `SKIP_REDIS=true`, and the output says so. Files are written with mode
`600` in a mode `700` directory, since they hold every password hash and
stored credential. Archives older than `BACKUP_RETENTION` days (30 by
default) are removed after a successful run.

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `BACKUP_DIR` | `./backups` (`/backups/postgres` in host mode) | Where the files go. |
| `BACKUP_RETENTION` | `30` | Days of archives to keep. |
| `DATABASES` | `identity,data,guardian` | Databases to dump; also `--databases`. |
| `SKIP_REDIS` | unset | `true` leaves Redis out. |
| `GPG_RECIPIENT` | unset | Encrypts every file for this recipient. |
| `S3_BUCKET` | unset | Target of `--upload-s3`. |

Copy the archives off the server: a backup on the same disk is not a backup.

### Scheduled backups

The `backup` Compose profile runs the same script in a container on the
Compose network every `BACKUP_INTERVAL_SECONDS` (one day by default) and
keeps the archives in the `wildbox_backups` volume:

```bash
docker compose --profile backup up -d backup
docker compose logs backup
```

A failed run logs `[backup] FAILED` and keeps nothing; alert on it.

### An external database

For a PostgreSQL the stack does not run (a managed database, another host),
use host mode: the script connects from the machine it runs on. It needs
`pg_dump`, `pg_restore` and `psql` of the server's major version on `PATH`,
and `redis-cli` unless `SKIP_REDIS=true`.

```bash
BACKUP_MODE=host POSTGRES_HOST=db.internal POSTGRES_USER=postgres \
  POSTGRES_PASSWORD=... REDIS_HOST=redis.internal REDIS_PASSWORD=... \
  BACKUP_DIR=/var/backups/wildbox ./scripts/backup_postgres.sh
```

Setting `POSTGRES_HOST` selects host mode by itself. The passwords are read
from the environment and handed to the client tools through their
environment; no password file is written.

### Restoring

`make restore-drill` (`scripts/verify_restore.sh`) takes a backup, restores
it into scratch databases named `<db>_restore_drill`, compares every table's
row count with the source, and drops the scratch databases. The live
databases are only read. Run it on a schedule: a restore that has never been
tested is not one.

To restore for real, stop the services first, then:

```bash
docker compose stop
docker compose start postgres
./scripts/restore_postgres.sh --timestamp 20261005_120000   # or --latest
./scripts/restore_redis.sh --timestamp 20261005_120000
docker compose up -d
```

`restore_postgres.sh` restores over the live databases; `--into-suffix
_check` restores into `<db>_check` instead, and `--dry-run` only reads the
archives. `restore_redis.sh` replaces the Redis data volume and refuses to
run while Redis is running. It exists because Redis runs with the
append-only file enabled and then ignores a `dump.rdb` at start: copying the
snapshot into the volume by hand gives an empty Redis.

---

## 7. Monitoring

The `monitoring` profile starts two services:

```bash
docker compose --profile monitoring up -d
```

With the production overlay, give every `docker compose` command in this
section the same `-f docker-compose.yml -f docker-compose.prod.yml` you
started the stack with; without them Compose recreates the two services on
the development network.

| Service | Address | What it does |
| --- | --- | --- |
| `prometheus` | `127.0.0.1:9090` | Scrapes the services (`monitoring/prometheus.yml`), evaluates the alert rules (`monitoring/alert_rules.yml`) and sends what fires to Alertmanager |
| `alertmanager` | `127.0.0.1:9093` | Groups the alerts it receives, shows them, lets you silence them, and notifies the receiver its configuration names |

Neither has authentication, so both are bound to localhost; reach them from
another machine through an SSH tunnel
(`ssh -L 9090:127.0.0.1:9090 -L 9093:127.0.0.1:9093 <host>`). There is no
Grafana in `docker-compose.yml`; connect your own if you want dashboards.

### Out of the box, nobody is notified

The configuration that ships, `monitoring/alertmanager.yml`, sends every alert
to a receiver named `no-notifications`, which has no integration. A firing
alert is then visible in two places and nowhere else:

- the Alertmanager UI, `http://127.0.0.1:9093`;
- the Prometheus alerts page, `http://127.0.0.1:9090/alerts`.

No e-mail, webhook or chat message is sent until you configure a receiver.
This is deliberate: the repository cannot know your mail server, and a default
that tried one would fail every notification instead of saying that none is
configured.

### The alerts

| Alert | Fires when | What it does not see |
| --- | --- | --- |
| `WildboxServiceDown` | Prometheus cannot scrape `/metrics` on identity, tools, data, responder, CSPM or agents for 2 minutes | guardian, the gateway, the dashboard, the workers, PostgreSQL and Redis are not scraped |
| `WildboxHighErrorRate` | more than 5% of the HTTP requests one of those services handled ended in a 5xx, for 10 minutes | requests the gateway refused or could not forward: each service counts its own |
| `WildboxSyncToolFailureRate` | more than 25% of the synchronous tool runs (`POST /api/v1/tools/{tool}`) raised an error the tool does not handle, for 15 minutes | asynchronous runs (`.../async`), which the next alert measures. Timeouts, refused runs and a failure the tool reports in its result (`success: false`) are not counted as failures |
| `WildboxAsyncToolFailureRate` | more than 25% of the asynchronous tool runs (`POST /api/v1/tools/{tool}/async`) failed, for 15 minutes: the tool raised an error it does not handle, or the task failed in the worker after its retries | synchronous runs. Timeouts (a task killed at the hard time limit included), canceled tasks, tasks that ended before the tool started (input that does not validate, a refused target or caller) and a failure the tool reports in its result are not counted as failures. A count the worker could not write to Redis is lost |
| `WildboxAsyncToolTasksNotConsumed` | asynchronous tool tasks have been in the queue for 15 minutes and no worker took any task in that time: `tools-worker` is stopped, restarting or cannot reach Redis | a backlog that a busy worker is working through, and tasks a worker had already taken when it was killed: the broker returns those to the queue only after its visibility timeout, an hour |
| `WildboxAsyncToolMetricsUnreadable` | the tools API has not been able to read the asynchronous counters from Redis for 10 minutes | nothing else: while it fires, the two alerts above cannot |
| `WildboxAlertmanagerDown` | Prometheus cannot scrape Alertmanager for 5 minutes | it cannot be delivered: it is shown on the Prometheus alerts page only |
| `WildboxAlertNotificationsFailing` | Alertmanager failed to send a notification in the last 15 minutes | if the failing receiver is the only one it cannot be delivered either: it is shown in both UIs |

`tools-worker`, which executes the asynchronous runs, is not scraped: it
serves no HTTP, and on the production networks Prometheus cannot reach it.
It counts in Redis how each task ended, and the tools API, which is
scraped, exports the counts (`wildbox_tool_async_executions_total`), the
length of the task queue (`wildbox_tool_async_queue_length`) and how many
tasks the worker has taken (`wildbox_tool_async_tasks_consumed_total`).
The counts live as long as the Redis data, so a restart of the API or the
worker does not reset them.

There is no alert on the threat-feed collection, on scans or on backups:
none of them exports a metric Prometheus can read.

### Being notified

Alertmanager does not read environment variables, and a password on its
command line would be visible to anyone who can list processes. A receiver is
therefore configured with two things you mount: a configuration file, which
holds no secret, and a directory of secret files that the configuration names.

| Variable in `.env` | Default | What it is |
| --- | --- | --- |
| `ALERTMANAGER_CONFIG_FILE` | `./monitoring/alertmanager.yml` | The configuration file, mounted read-only |
| `ALERTMANAGER_SECRETS_DIR` | `./monitoring/secrets` | Mounted read-only at `/etc/alertmanager/secrets`. Git ignores everything in the default directory |
| `ALERTMANAGER_EXTERNAL_URL` | `http://127.0.0.1:9093` | The address notifications link to. Not a secret |
| `PROMETHEUS_EXTERNAL_URL` | `http://127.0.0.1:9090` | The address an alert's "source" link points to. Not a secret |

Two examples are provided; CI validates both with `amtool check-config`.

**E-mail.** Copy the example, replace the `example.com` values (mail server,
sender, user name, recipient), and put the SMTP password in a file:

```bash
mkdir -p monitoring/local
cp monitoring/examples/alertmanager-email.yml monitoring/local/alertmanager.yml
$EDITOR monitoring/local/alertmanager.yml

touch monitoring/secrets/smtp_password
chmod 600 monitoring/secrets/smtp_password
$EDITOR monitoring/secrets/smtp_password            # the password, one line
sudo chown 65534 monitoring/secrets/smtp_password   # Linux hosts
```

**Generic webhook.** Alertmanager sends an HTTP POST with a JSON body to a URL
of yours ([format](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)).
The URL usually carries a token, so it goes in a file too; the example needs
no other change:

```bash
mkdir -p monitoring/local
cp monitoring/examples/alertmanager-webhook.yml monitoring/local/alertmanager.yml

touch monitoring/secrets/webhook_url
chmod 600 monitoring/secrets/webhook_url
$EDITOR monitoring/secrets/webhook_url              # the URL, one line
sudo chown 65534 monitoring/secrets/webhook_url     # Linux hosts
```

The example also shows, commented out, how to send a bearer token read from
`monitoring/secrets/webhook_token`.

Alertmanager runs as UID 65534 (`nobody`) and reads a secret file each time it
notifies, which is why the file is given to that user on a Linux host. Docker
Desktop on macOS presents a mounted file as owned by the container's user, so
the `chown` is not needed there. `monitoring/local/` and `monitoring/secrets/`
are ignored by Git.

Then, for either example, set the configuration file in `.env`, check it and
recreate the container (also after every later change to the file):

```bash
echo 'ALERTMANAGER_CONFIG_FILE=./monitoring/local/alertmanager.yml' >> .env

docker compose --profile monitoring run --rm --no-deps --entrypoint amtool \
  alertmanager check-config /etc/alertmanager/alertmanager.yml
docker compose --profile monitoring up -d --force-recreate alertmanager
```

`amtool check-config` checks the syntax only: it does not open the secret
files or contact the mail server. Send a test alert to see a notification
arrive (after `group_wait`, 30 seconds in the examples):

```bash
docker compose --profile monitoring exec alertmanager amtool alert add \
  WildboxTestNotification severity=info \
  '--annotation=summary="Test notification sent by hand"' \
  --alertmanager.url=http://127.0.0.1:9093
```

If nothing arrives, `docker compose logs alertmanager` gives the reason at
once. The usual causes are a secret file that UID 65534 cannot read, a wrong
password, and a server the container cannot reach.
`WildboxAlertNotificationsFailing` follows, but not at once: Alertmanager
counts a notification as failed when it stops retrying, which is immediately
for a secret file it cannot read and after `group_interval` (5 minutes in the
examples) for a wrong password or an unreachable server, and the alert fires
5 to 6 minutes after that: about 11 minutes after the first failed attempt in
the second case. An invalid configuration file keeps Alertmanager restarting;
`WildboxAlertmanagerDown` then fires in Prometheus.

In the production overlay Alertmanager is on the `backend` network with
Prometheus. That network has a route out, so a mail server or webhook outside
the stack is reachable; PostgreSQL and Redis are not.

To use an Alertmanager you already run instead, change the `alerting:` target
in `monitoring/prometheus.yml` to its address.

### Logs

Container logs are rotated by the production overlay for the services it
configures; read them with `docker compose logs <service>`.

---

## 8. Updating

Read the notes for your target version in
[UPGRADING.md](https://github.com/fabriziosalmi/wildbox/blob/main/UPGRADING.md)
before pulling; they list what an existing deployment has to do.

```bash
git pull
make validate-secrets       # new releases can add required secrets
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
make start-prod
```

The images are built from the repository, and `make start-prod` does not
rebuild an image that already exists: build first, or the services keep
running the previous release. The same applies to the dashboard's
`NEXT_PUBLIC_*` settings, which take effect only in a rebuilt image.

---

## Troubleshooting

- **A container keeps restarting**: `docker compose logs <service>`; a missing
  secret is reported by name.
- **Clients get certificate errors**: check that `wildbox.crt` contains the
  full chain and matches your host name.
- **Requests on port 80 return 301**: expected; only `/health` is served over
  HTTP.
- **PostgreSQL**:
  `docker compose exec postgres psql -U postgres -c 'SELECT 1'`.

## Support

- [Security policy](../security/policy.md) and [Security status](../security/status.md)
- [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues)
- Security reports: see [SECURITY.md](https://github.com/fabriziosalmi/wildbox/blob/main/SECURITY.md)
