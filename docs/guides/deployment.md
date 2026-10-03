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

- Linux with Docker Engine 20.10+ and the Compose plugin 2.24.4 or later
  (`docker-compose.prod.yml` uses the `!override` tag, which older versions
  reject)
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
- `CORS_ORIGINS`: the HTTPS origins that may call the API, for example
  `https://wildbox.example.com` (here and below, replace `wildbox.example.com`,
  a name reserved for documentation, with your host name). identity does not
  read it: the browser reaches identity through the gateway, on the same
  origin as the dashboard
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
docker compose --profile monitoring up -d    # Prometheus with monitoring/alert_rules.yml
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
| SLA violation check | every 15 minutes | The shortest SLA is 4 hours (P1), so a breach is reported within 15 minutes of it. Each vulnerability is notified at most once every 24 hours, however often the check runs | `GUARDIAN_SCHEDULE_SLA_CHECK` |
| Alert rules | every 15 minutes | A condition is noticed within 15 minutes of becoming true. A rule notifies when it starts firing and when it recovers, not on every evaluation (below), so a shorter interval detects sooner without sending more mail | `GUARDIAN_SCHEDULE_ALERT_RULES` |
| Risk score recalculation | daily, 02:00 | A full pass over open vulnerabilities, so off-peak. Edits and threat-intel enrichment already recalculate one vulnerability at a time; the pass catches what does not, such as a change to an asset's criticality | `GUARDIAN_SCHEDULE_RISK_SCORES` |
| Expired report cleanup | daily, 03:00 | Reports expire 30 days after generation; a day's precision is enough | `GUARDIAN_SCHEDULE_REPORT_CLEANUP` |
| Vulnerability history cleanup | daily, 03:30 | One year of history is kept; running daily keeps each deletion to one day of rows | `GUARDIAN_SCHEDULE_HISTORY_CLEANUP` |
| Asset inventory | daily, 04:30 | Marks assets not seen for 30 days inactive | `GUARDIAN_SCHEDULE_ASSET_INVENTORY` |
| Overdue compliance assessments | daily, 08:00 | Sends one reminder per overdue assessment on every run, at the start of the working day | `GUARDIAN_SCHEDULE_OVERDUE_ASSESSMENTS` |
| Expiring compliance exceptions | Mondays, 08:00 | Looks 30 days ahead and reminds on every run: weekly gives about four reminders per exception, daily would give thirty | `GUARDIAN_SCHEDULE_EXPIRING_EXCEPTIONS` |
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
| Report schedule (`/api/v1/guardian/reports/schedules/`) | `next_run` (the first run) and `frequency`: once, daily, weekly, monthly or quarterly | a report, generated on the `reporting` queue and e-mailed to the schedule's `recipients` (or `DEFAULT_NOTIFICATION_RECIPIENTS`) when it is ready | vulnerability summary, asset inventory, compliance status and executive dashboard reports, as JSON or HTML. The other report types have no data behind them and the other formats are not written yet, so the API refuses them |
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
- Notifications are e-mailed to `notification_config.recipients`, or to
  `DEFAULT_NOTIFICATION_RECIPIENTS` when the rule names none. Each one is
  recorded, delivered or not, and
  `GET /api/v1/guardian/reports/alerts/{id}/notifications/` lists them.
- The rule shows its `state` (`ok` or `firing`), `firing_since`,
  `last_value` and `last_evaluated_at`. `trigger_count` counts the times it
  started firing.

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
- **Providers.** Only AWS scans run; GCP and Azure scans fail when the
  worker takes them.

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

### Internal targets of the network tools

The network tools (port and vulnerability scanners, the TLS and
certificate analyzers, `network_scanner`, `iot_security_scanner`,
`database_security_analyzer`, `dns_enumerator`, and the image registry of
`container_security_scanner`) refuse internal targets: private, loopback,
link-local, multicast, reserved and shared addresses, ranges that contain
one, names that resolve to one, and the stack's own service names. A
range holds at most 1024 addresses. Refusals answer 400.

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

`scripts/backup_postgres.sh` writes `pg_dump` archives of every database,
with optional GPG encryption (`GPG_RECIPIENT`) and S3 upload (`--upload-s3`,
`S3_BUCKET`). `scripts/restore_postgres.sh` restores them, and
`scripts/verify_restore.sh` is a drill: back up, restore into scratch
databases, check the data, clean up.

The `backup` Compose profile runs the backup script in a container on the
Compose network every `BACKUP_INTERVAL_SECONDS` (one day by default) and keeps
`BACKUP_RETENTION` days of archives in the `wildbox_backups` volume:

```bash
docker compose --profile backup up -d backup
docker compose logs backup
```

`make backup` and `make restore-drill` run the same scripts from the host.
They connect to `POSTGRES_HOST` (default `wildbox-postgres`), which the
default Compose file does not publish to the host, so run them from a machine
or container that can reach the database.

Copy the archives off the server: a backup on the same disk is not a backup.
Run the restore drill on a schedule; a restore that has never been tested is
not one either.

---

## 7. Monitoring

The `monitoring` profile starts Prometheus on `127.0.0.1:9090` with the
scrape configuration in `monitoring/prometheus.yml` and the alert rules in
`monitoring/alert_rules.yml`. There is no Grafana in `docker-compose.yml`;
connect your own if you want dashboards.

Container logs are rotated by the production overlay; read them with
`docker compose logs <service>`.

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
