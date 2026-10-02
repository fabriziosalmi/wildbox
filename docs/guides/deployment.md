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

TLS terminates at the gateway; no other proxy is needed in front of it. The
`haproxy/` directory in the repository belongs to the blue/green experiment in
`docker-compose.blue-green.yml` and is not used by `docker-compose.yml` or
`docker-compose.prod.yml`.

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
| Alert rules | every 15 minutes | A firing rule notifies on every evaluation (there is no repeat suppression yet), so a shorter interval sends more mail: 96 a day per firing rule at 15 minutes, 288 at 5 | `GUARDIAN_SCHEDULE_ALERT_RULES` |
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
- `docker-compose.blue-green.yml` keeps that rule across colors: a worker
  per color (`guardian-worker-blue`, `guardian-worker-green`) and one
  `guardian-beat` for both, running the image of `GUARDIAN_ACTIVE_COLOR`
  (blue by default). `scripts/shell-scripts/blue_green_guardian_tasks.sh
  <blue|green>`, which the deploy and rollback scripts call after switching
  the traffic, starts the new color's worker, moves beat to the new image
  and stops the old worker once its running tasks finish.
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
running the previous release.

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
