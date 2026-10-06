# Upgrading

This file records changes that an **existing deployment** has to act on. A fresh
install needs none of it: `make generate-secrets` and the
[Quick Start](https://www.wildbox.io/guides/quickstart/) cover everything here.

## Upgrading to 0.12.2

From 0.12.1 nothing is required: rebuild the images and recreate the
containers.

```bash
git fetch --tags && git checkout v0.12.2
docker compose build
docker compose up -d
```

Use the same `-f` files, or `COMPOSE_FILE`, you start the stack with. No
setting is added or removed, and no service has a schema change. Coming
from 0.12.0, this is all there is to do as well; coming from 0.11.2 or
earlier, follow [Upgrading to 0.12.0](#upgrading-to-0120) with `v0.12.2`
checked out in its step 2.

What you may notice:

- **Logs of the FastAPI services.** An unhandled error is logged with its
  class, the place it was raised at and its frames, without its text, in
  the service's own record and in uvicorn's: the text can hold what a
  caller sent. Look an error up by class and place.
- **tools: an asynchronous task whose tool raises is not retried.** It
  used to read `retrying` and then `failed`, in state `FAILURE`, after the
  tool had been called three times; it now reads `failed`, in state
  `SUCCESS`, after one call, with `error` `Tool execution failed
  (<class>)`. A tool that failed on its first call and succeeded on a
  retry now fails.
- **tools: the text of a refused target** no longer holds the target. A
  client that matched on the text should read
  `error.details.errors[0].type`, which is new on that `400`
  (`target_internal`, `target_too_large`, `target_invalid`,
  `url_refused`). The statuses are the same. A target written with an
  IPv6 zone id answers `400` in `dns_servers`, `ip_range` and `network`.
- **gateway.** A redirect the HTTPS listener writes carries a path in
  `Location` (`/api/v1/data/`), where it carried
  `https://<host>/api/v1/data/` without the port the client had called.
  `http://wildbox.local/...` and `http://<name>.wildbox.local/...` are
  redirected to HTTPS on that same name; any other `Host` goes to the
  first configured name, as before.
- **guardian.** `manage.py import_vulnerabilities --source json` and
  `--source csv`, which always failed, import; `--source nist`, `nessus`
  and `openvas` end with an error and a status that is not 0, where they
  printed "not yet implemented" and ended with 0. An IPv6 host a discovery
  finds from now on, without a reverse DNS name, is named
  `host-2606-2800-...`, with hyphens; no stored name changes. The worker's
  line for a network that could not be queued reads
  `Failed to queue the scan of network '<range>': <ErrorClass>`.
- **cspm.** `Access Management` is no longer among the categories of
  `GET /api/v1/cspm/checks`: its two checks are in `Identity and Access
  Management`, and the old name still works as a filter. A batch that
  fails partway leaves no scan queued; when it cannot withdraw them, the
  `503` lists them in `error.details.queued_scans`.
- **data.** A source's `error_count` counts failures in a row and is reset
  by a success. A feed whose collector returns `failed` ten times in a row
  is disabled, where it was collected without end; `manage.py sources
  enable` brings it back with its count at 0. `last_error` holds the class
  of the error and the HTTP status, not its text.
- **sensor.** The last line of a stop may count more events than before
  (it counted too few), and the status has two new counters,
  `entries_failed` and `lines_failed`. A stop takes at most 29 seconds,
  still inside the 30 the Compose files give.
- **Images.** guardian, data, identity, agents, tools and responder no
  longer contain `pytest` or the linters, and data and tools no longer
  contain `httpx`: `docker compose exec identity pytest` now answers "not
  found". To run a service's unit tests, install `pytest==9.1.1
  pytest-cov==7.1.0 pytest-asyncio==1.4.0` after its `requirements.txt`,
  with `pytest-django==4.5.2` for guardian and `httpx==0.28.1` for data
  and tools. cspm and guardian run redis-py 5.0.8.

## Upgrading to 0.12.1

From 0.12.0 nothing is required: rebuild the images and recreate the
containers.

```bash
git fetch --tags && git checkout v0.12.1
docker compose build
docker compose up -d
```

Use the same `-f` files, or `COMPOSE_FILE`, you start the stack with. No
setting is added or removed. guardian applies one migration at start
(`assets.0004`, a column that may be empty); no other service has a schema
change, and 0.12.0 runs on the migrated database, so going back to 0.12.0
is a checkout and a rebuild.

Coming from 0.11.2 or earlier, follow
[Upgrading to 0.12.0](#upgrading-to-0120) with `v0.12.1` checked out in its
step 2. This section then adds nothing to do.

What you may notice:

- **identity: a login lockout in progress at the upgrade ends with it.**
  The lockout's Redis keys are named with a keyed digest of the address,
  not with the address as it was typed, and the keys of earlier releases
  are not read; they expire by themselves within the lockout period. To
  lift a lock by hand, `redis-cli DEL "login:lockout:<address>"` no longer
  finds the key: `docs/guides/authentication.md` has the new command.
- **cspm:** a Redis that does not answer is a `503` after 3 seconds, where
  the request used to wait, and `/health` answers within 4 seconds. A
  deployment that set `socket_timeout` or `socket_connect_timeout` in the
  query string of `REDIS_URL` keeps its values. The compliance percentages
  of a scan (`GET /api/v1/cspm/scans/{id}/compliance`, and a report's
  `summary.compliance_frameworks`) are over the passed and failed results:
  a scan with skipped or failed-to-run checks reads higher than before, one
  in which every check ran reads the same. A scan canceled while a worker
  ran it stays `cancelled`. `categories` of `GET /api/v1/cspm/checks` lists
  `Logging and Monitoring` and `Identity and Access Management` once each;
  the `category` filter takes the spelling with `&` too.
- **guardian:** `POST vulnerabilities/` answers `400` for a second finding
  on the same asset and CVE without a `port`, as it did with one. A
  discovery rule has `last_run_result`, which names the networks a run
  skipped and why. A port scan of an IPv6 asset connects over IPv6; on a
  default stack, whose Docker networks are IPv4 only, it still finds no
  route and reports the ports closed. A path without its trailing slash is
  redirected with a `Location` that is a path, so the client stays on the
  host and port it called.
- **gateway:** `GATEWAY_DEBUG` in `.env` is ignored. The image has no
  compiler, `make`, `envsubst` or `unzip`.
- **sensor:** the image has no `pytest`, `black`, `flake8` or `mypy`; the
  local API sends no CORS header; the start-up line `Platform:` is one
  short line; a stop takes at most 28 seconds, still inside the 30 the
  Compose files give.
- **data:** a `DATABASE_URL` that is not PostgreSQL's is refused with a
  message that says so (it could not work before); a source in `error` is
  scheduled when the scheduler starts, not ten minutes later.
- **identity and data:** the log line of a database error has the class,
  the SQLSTATE and the constraint, not the database's message, which can
  hold a value.
- **`scripts/restore_postgres.sh --overwrite-live-databases`** removes, and
  lists, the tables, views and sequences made after the backup, so a
  database holds what its archive holds. The work directory (`TMPDIR`)
  needs room for the largest archive once more. Going back to 0.11.2 no
  longer needs the databases dropped and created first
  ([Going back to 0.11.2](#going-back-to-0112)).

Optional. `collection_runs.error_message` and `sources.last_error` of the
data service, written before 0.12.0, can hold a feed's URL and with it a
key (section 22 of "Upgrading to 0.12.0"). To blank the values that hold a
URL and leave the others, on the data service's database:

```sql
UPDATE sources
   SET last_error = 'Removed: the stored error text held a URL'
 WHERE last_error LIKE '%://%';
UPDATE collection_runs
   SET error_message = 'Removed: the stored error text held a URL'
 WHERE error_message LIKE '%://%';
```

## Upgrading to 0.12.0

From 0.11.2: the changes an existing deployment has to act on. Coming from
an earlier release, follow [Upgrading to 0.11.0](#upgrading-to-0110) and the
two sections after it first. The numbered sections are grouped by who has
to act (every operator, then operators who use a given part, then API
clients); apply them in the order of the checklist that follows, where each
step names the sections it comes from.

### Order of operations for 0.12.0

Every step is marked **required** or **conditional**, with its condition.
Run the commands from the repository root. Steps 1 to 5 run while the
0.11.2 stack is still up; step 7 recreates the containers. From the
checkout of step 2 until then, do not restart or reload the gateway
container (section 1).

1. **Point Compose at your files (required).** Use the same files in every
   step, as for 0.11.0:

   ```bash
   export COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml
   ```

2. **Check out 0.12.0 (required).** Nothing runs the new code yet; the
   scripts of the next steps are the new ones.

   ```bash
   git fetch --tags && git checkout v0.12.0
   ```

3. **Back up the databases, Redis and `.env` (required).** Ten guardian
   migrations run in step 7; six of them cannot be reversed in data, and
   two of those delete stored credentials (sections 5 and 6). `make backup` now
   works on a default stack and writes to `./backups` (section 13):

   ```bash
   umask 077
   cp -p .env .env.pre-0.12.0
   make backup
   ```

   Keep these files private and copy them off the server.

4. **Look at what the upgrade removes (conditional, with the old stack
   up).**
   - If teams sent guardian credentials of scanners, external systems,
     webhooks or notification channels: list the records that hold one,
     with the query of section 6.
   - If the `automations` profile has been in use: check who owns the n8n
     instance (section 7).
   - If guardian discovers or port-scans hosts on your own network: note
     the ranges; they have to be listed in step 5, or those scans answer
     400 after the upgrade (section 20).
   - If someone wrote rows into guardian's attachment table by hand:
     guardian will not start until the table is empty (section 5).
   - If you run sensors with a `log_sources` section or a configuration of
     your own: validate it with the new code (section 16).

5. **Edit `.env` (required review; each change as marked).**
   - Required: `ENVIRONMENT` is set. Compose refuses to start without it
     (section 2).
   - Required check: `CORS_ORIGINS` holds origins only, or is empty. With
     `*`, a trailing slash, a path or a bare host name the gateway does not
     start (section 3).
   - Required check, if present: `ANALYZE_RATE_LIMIT` and
     `ANALYZE_TEAM_RATE_LIMIT` are now read from `.env`. A value that was
     ignored until now takes effect, and one that cannot be parsed stops
     the agents service (section 10).
   - Required with the production overlay: every entry of `CORS_ORIGINS`
     is an origin for guardian too, which now reads it (section 3).
   - Conditional, required if guardian scans internal addresses:
     `GUARDIAN_ALLOWED_INTERNAL_TARGETS` lists those ranges (section 20).
   - Conditional, to receive guardian's e-mail: `GUARDIAN_EMAIL_HOST`,
     `GUARDIAN_DEFAULT_FROM_EMAIL`, `GUARDIAN_CONTACTS_SECRET` and their
     siblings (section 8).
   - Conditional, optional settings: `GUARDIAN_RATE_LIMIT_USER`
     (section 9), `GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS` and
     `GUARDIAN_INTERNAL_URL` (section 8), `AGENT_TEAM_DATA_TOOLS`
     (section 10), `ALERTMANAGER_CONFIG_FILE` and its siblings
     (section 15), `GATEWAY_RATE_LIMIT_PER_SECOND` and its two siblings
     (section 21).
   - Remove if present, since nothing reads them: `RESPONDER_DATABASE_URL`,
     `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW`, `N8N_BASIC_AUTH_ACTIVE`,
     `N8N_BASIC_AUTH_USER`, `N8N_BASIC_AUTH_PASSWORD`, `ENABLE_METRICS`,
     `METRICS_PORT`, `NEXTAUTH_SECRET`, `GRAFANA_ADMIN_PASSWORD`,
     `GUARDIAN_DB_PASSWORD`, `N8N_ENCRYPTION_KEY`, `SESSION_TIMEOUT`,
     `MAX_LOGIN_ATTEMPTS`, `LOCKOUT_DURATION`, `REQUIRE_EMAIL_VERIFICATION`,
     `REQUIRE_MFA` (section 18).

   Then check the result:

   ```bash
   make validate-secrets
   docker compose config -q
   ```

6. **Rebuild every image (required).** The gateway and the services must
   change together (section 1):

   ```bash
   docker compose build
   ```

7. **Start the new stack (required).** One `up -d` recreates the gateway,
   the services, PostgreSQL and Redis together (sections 1 and 4). guardian's
   migrations run in the image's entrypoint (section 5); no other service
   has a schema change.

   ```bash
   docker compose up -d
   docker compose logs -f gateway guardian
   ```

8. **Give the data service a source it can collect (conditional: you use
   the threat-intelligence feeds).** The scheduler disables every source no
   collector can run, which is every source the old defaults created
   (section 22):

   ```bash
   docker compose exec data python manage.py sources add-defaults
   ```

9. **Rotate `REDIS_PASSWORD` (conditional: the responder's container logs
   were readable by others or left the host).** The responder printed the
   password in its log at every start, up to 0.11.2 (section 23):

   ```bash
   ./scripts/rotate_secrets.sh --secret REDIS_PASSWORD
   ```

   Then run the command it prints.

10. **Recreate the monitoring profile (conditional: you run it).** It
    gains Alertmanager and moves to Prometheus 3 (section 15). Pass the
    same `-f` files:

    ```bash
    docker compose --profile monitoring up -d
    ```

11. **Rebuild and restart the sensors (conditional: you run them).**
    Section 16 lists what a sensor's configuration and its consumers have
    to change.

12. **Verify (required).** Follow
    [Verifying the upgrade](#verifying-the-upgrade). `make health` now
    exits non-zero when something is unhealthy (section 14).

13. **Tell API clients and log consumers what changed (required when
    anything but the dashboard calls the API or reads the logs).**
    Sections 22 to 27:
    - Ingest clients of the data service: a batch is stored whole or
      refused whole (section 22).
    - Log parsers: no query string in the access logs, fields in the tools
      service's lines (section 23).
    - Error bodies: `error.details` for a dict detail, cspm's errors in
      the common shape, identity's `detail` replaced by `error.message`,
      no `input` in the field errors of a 422 (section 24).
    - guardian: twenty routes removed, several answers changed, filters
      that now filter, relative pagination links, JSON only, credential
      fields and internal scan targets refused with 400 (sections 20
      and 25).
    - tools, agents, responder and cspm: asynchronous submissions refused
      at once, `result_url` and `status_url` under `/api/v1/`, a failed
      analysis that reads `failed`, cspm routes that answered 500
      (section 26).
    - API keys: scopes checked on every route, `/api/v1/automations/` gone
      (sections 7 and 27).

### Going back to 0.11.2

The backup of step 3 is the way back: six of guardian's migrations cannot
be reversed in data (section 5). With `COMPOSE_FILE` set as in step 1, and
the 0.12.0 checkout still in place for its scripts:

```bash
docker compose stop
docker compose start postgres
for db in identity data guardian; do
  docker compose exec -T postgres psql -U postgres \
    -c "DROP DATABASE \"$db\" WITH (FORCE)" -c "CREATE DATABASE \"$db\""
done
./scripts/restore_postgres.sh --timestamp <timestamp of step 3> --overwrite-live-databases
git checkout v0.11.2
docker compose build
docker compose up -d
```

Use your `POSTGRES_USER` for `-U`. Everything written since the backup is
lost.

**With the scripts of 0.12.0, drop and create each database before the
restore**, as above. From 0.12.1 the restore removes what was made after
the backup, and the `for` loop is not needed (it does no harm). 0.12.0's
`restore_postgres.sh` restores what the archive holds into the database
that is there, and leaves a table made after the backup: the one this
release adds (`core_teammembershiprevocation`, in guardian) would stay.
0.11.2 runs with it, and the next upgrade then stops in guardian's
migrations with `relation "core_teammembershiprevocation" already exists`
([#773](https://github.com/fabriziosalmi/wildbox/issues/773)). If you
already went back without dropping the databases, drop that one table
before upgrading again:

```bash
docker compose exec -T postgres psql -U postgres -d guardian \
  -c 'DROP TABLE core_teammembershiprevocation'
```

The `.env` of step 5 can stay as it is: 0.11.2 ignores what this release
added. Redis needs no restore to go back; to have it as it was too, see
`scripts/restore_redis.sh` in the deployment guide.

### 1. Rebuild every image and start them together (required)

`docker compose up -d` does not rebuild an image that exists. This release
changes every image, and three changes need both sides at once:

- **The gateway and data, tools, guardian, agents and the responder.** The
  gateway now sends `X-Wildbox-Auth-Type` and `X-Wildbox-Scopes`, and the
  services check them. data and guardian refuse every API request, and
  tools every tool run, that carries the gateway's secret without
  `X-Wildbox-Auth-Type` (`403 GATEWAY_AUTH_TYPE_REQUIRED`). Behind a gateway
  that was not rebuilt, the dashboard's data and vulnerability pages and
  every tool run fail until it is. The same holds for agents and responder
  images that were not rebuilt: their calls to tools, data and guardian are
  refused. A new gateway in front of old services changes nothing.
- **The gateway and guardian.** guardian's pagination links are now
  relative and carry the gateway's prefix, which the gateway sends. A new
  guardian behind an old gateway answers links without `/guardian`.
- **The tools API and its worker** are one image. An old worker counts no
  asynchronous run and does not read the record of a cancellation
  (sections 11 and 26).
- **The gateway image and its configuration.** The Compose stack mounts
  `open-security-gateway/nginx` from the checkout, and the new `nginx.conf`
  includes a file that only the new image's entrypoint writes
  (section 21). An image built before this release does not write it, and
  nginx stops with
  `open() "/run/wildbox-gateway/limit_req_zones.conf" failed`. For the same
  reason the 0.11.2 gateway must not be restarted or reloaded between the
  checkout and the `up -d` below: it would read the new configuration.

```bash
docker compose build
docker compose up -d
```

Use the same `-f` files, or `COMPOSE_FILE`, you start the stack with.

Scripts or monitoring that call data, guardian or the tools execution
routes directly, with `X-Gateway-Secret` and the `X-Wildbox-*` headers,
must add `X-Wildbox-Auth-Type: session` (or `service`). Requests through
the gateway need no change, and sending either new header through the
gateway has no effect.

The images of data, guardian, sensor, cspm, identity, tools and the
responder lose the packages no code imported (data's lock goes from 124 to
67 packages, guardian's from 138 to 83). Nothing to do beyond the rebuild.

On arm64, an image of tools built before this release holds an x86-64
Trivy; the rebuild installs the arm64 one. Building the tools or sensor
image for an architecture other than amd64 and arm64 fails, by design.

The Compose images are pinned by digest: `docker compose pull` fetches
exactly those bytes, and a registry mirror must serve images by digest.

### 2. `.env` must set `ENVIRONMENT` (required)

`docker compose up` now fails without `ENVIRONMENT`, before changing
anything, and `make validate-secrets` reports the same. A `.env` made by
`make generate-secrets` already has `ENVIRONMENT=production`.

- **A stack that ran without the line was running as development.** Add
  `ENVIRONMENT=production`. The services then apply their start-up checks:
  identity needs `API_KEY_HASH_SECRET` (run `make init-api-key-hash` first,
  so existing API keys keep working), data needs `DATA_SECRET_KEY` and
  `DEBUG=false`. The API schemas stop being served (section 12).
- **Any value other than `development` is held to the same checks**,
  `staging` included. Only `development` is a development stack.
- **`docker-compose.prod.yml` sets `production` on every service.** A
  `.env` that says `development` no longer makes part of a production stack
  a development one.
- A service started on its own without `ENVIRONMENT` (a bare `docker run`)
  is held to the checks too.

### 3. `CORS_ORIGINS` must hold origins; the gateway reads it (required check)

The gateway now answers CORS preflight requests itself, from
`CORS_ORIGINS`: a comma-separated list, or a JSON list, of `https://host` or
`https://host:port`.

- **With `*`, a trailing slash, a path or a bare host name the gateway does
  not start.** Check the value before upgrading. Empty is fine.
- `localhost` and `127.0.0.1` are no longer allowed on every port.
  `docker-compose.yml` defaults `CORS_ORIGINS` to `http://localhost:3000`,
  the dashboard's development server; for another port or host, list it.
- A dashboard served from another origin now works: list its origin and
  recreate the gateway.
- A client that sent `OPTIONS` as a health probe keeps getting 405.
- **guardian reads the same value under the production overlay**, as
  `CORS_ALLOWED_ORIGINS`, by the gateway's grammar. It allows exactly those
  origins (none when `CORS_ORIGINS` is empty) instead of eight development
  origins written in its settings, and stops at start-up on an entry that
  is not an origin, with a message naming the entry. Nothing to do for a
  deployment whose dashboard is served by the gateway.

### 4. PostgreSQL and Redis are recreated; Redis's health check authenticates (nothing to do)

The definitions of both containers changed, so the `docker compose up -d`
of step 7 recreates them: the images are now pinned by digest
(`postgres:15` and `redis:7-alpine` at the digests the repository names), and
Redis has a new environment variable and health check. The data volumes
are kept; the services are without their database and without Redis for
those seconds, in the same `up -d` that recreates them too.

A Redis that refuses the password it was created with is now `unhealthy`.
After a `REDIS_PASSWORD` rotation that is the case until the command the
rotation prints has been run (section 13).

### 5. guardian applies ten migrations at start (back up first)

`python manage.py migrate` runs in the image's entrypoint, as before:

| Migration | What it does |
| --- | --- |
| `core.0004` | Adds `TeamMembership.last_seen`, set to `first_seen` for existing rows |
| `core.0005` | A new table for revoked memberships |
| `integrations.0003` | A webhook path is unique within its team, not on the platform |
| `integrations.0004`, `scanners.0003` | Delete the stored credentials (section 6) |
| `reporting.0004` | Adds `AlertNotification.failure_reason` |
| `vulnerabilities.0003` | Dates resolved vulnerabilities from their history and clears the date of those that are not resolved |
| `assets.0003` | Switches off discovery rules of the types guardian does not implement |
| `integrations.0005` | Drops `IntegrationLog.request_data` and `response_data`, which guardian never wrote; the log says how many rows held a value |
| `vulnerabilities.0004` | Drops the attachment table, when it is empty |

None needs an operator step on a database guardian itself wrote.
`vulnerabilities.0003`, `assets.0003`, the two that delete credentials and
the two that drop columns or a table cannot be reversed in data: going back
needs the backup of step 3, restored as
[Going back to 0.11.2](#going-back-to-0112) says.

**If someone wrote rows into `vulnerabilities_vulnerabilityattachment` by
hand**, guardian stops at start with `AttachmentsExist` and the number of
rows, and changes nothing in that table; `integrations.0005` has been
applied by then. Copy what you need, empty the table and start again. To
check beforehand:

```bash
docker compose exec -T postgres psql -U postgres -d guardian -tAc \
  'SELECT count(*) FROM vulnerabilities_vulnerabilityattachment'
```

`assign_guardian_team`: the output of `--dry-run` changed, and `--list`
together with `--team` or `--dry-run` is now refused.

The Celery task `apps.vulnerabilities.tasks.scan_vulnerability_remediation`
no longer exists. Nothing dispatched it, so no queued message refers to it.

### 6. guardian deletes the credentials it stored and never used

guardian accepted a scanner's API key or password, an external system's
`auth_config`, a webhook's `secret_token` and a notification channel's
`config`, stored them in plain text and used none of them. The columns are
dropped; the values are deleted, not migrated. Nothing stops working.

- To see beforehand which records hold one (names only), run this against
  the guardian database with the old stack up, for example through
  `docker compose exec -T postgres psql -U postgres -d guardian`:

  ```sql
  SELECT 'scanner' AS record, name FROM scanners_scanner WHERE api_key <> '' OR password <> ''
  UNION ALL SELECT 'external system', name FROM integrations_externalsystem WHERE auth_config::text NOT IN ('{}', 'null')
  UNION ALL SELECT 'webhook endpoint', name FROM integrations_webhookendpoint WHERE secret_token <> ''
  UNION ALL SELECT 'notification channel', name FROM integrations_notificationchannel WHERE config::text NOT IN ('{}', 'null');
  ```

  After the upgrade, `docker compose logs guardian | grep "guardian stored"`
  shows how many rows of each kind held one.
- **Backups written before the upgrade still hold those values in plain
  text**, the one of step 3 included; so do volume snapshots and WAL
  archives. Delete them as soon as you can do without them. If the
  database or one of those backups may have been read, change the secrets
  where they were issued (at the scanner, the ticketing system, Slack).
- A request that sends a value in one of those fields now answers `400` on
  that field (section 25).
- Rolling the two migrations back adds the columns back empty.

### 7. The gateway no longer routes to n8n (check who owns the instance)

`/api/v1/automations/` answers 404. n8n's editor is on
`http://127.0.0.1:5678` of the host, with the `automations` profile
started; from another machine, `ssh -L 5678:127.0.0.1:5678 <host>`. Nothing
shipped used the route. A workflow of your own that was started through
`/api/v1/automations/webhook/...` is no longer reachable from outside the
host.

**If the `automations` profile has been in use**, check who owns the n8n
instance (Settings > Users in the editor): until its owner account was
created, any Wildbox user could create it through the gateway.

```bash
curl -s http://127.0.0.1:5678/rest/settings | jq .data.userManagement.showSetupOnFirstLoad
```

- `true`: no owner exists yet. Create it now.
- The owner is not you: stop the profile, review the workflows and
  credentials, and reset with
  `docker compose exec automations n8n user-management:reset`.

In both cases also rotate `GATEWAY_INTERNAL_SECRET`
(`./scripts/rotate_secrets.sh --secret GATEWAY_INTERNAL_SECRET`, see
`docs/SECURITY_SECRETS_ROTATION.md`) and clear n8n's execution history:
every request that reached n8n through the gateway carried the secret, and
n8n keeps the data of past executions, the headers of a webhook request
among them.

`N8N_BASIC_AUTH_ACTIVE`, `N8N_BASIC_AUTH_USER` and
`N8N_BASIC_AUTH_PASSWORD` never protected n8n 1.x and are no longer read;
`validate_secrets.py` no longer asks for the password.

`N8N_ENCRYPTION_KEY` was generated and never passed to n8n: its encryption
key is the `config` file of `open-security-automations/n8n-data/`. Keep
that file with every backup of that directory's database, and do not add
`N8N_ENCRYPTION_KEY` to a running instance: n8n refuses to start with a
key other than the one in its data directory.

### 8. guardian can send e-mail, to people of the team concerned

Until this release no e-mail from guardian was delivered. Without the
settings below that stays so, and each notification is now recorded as not
sent, with the reason.

**To receive e-mail**, set in `.env` and recreate `guardian-worker` and
`identity`:

- `GUARDIAN_EMAIL_HOST` and `GUARDIAN_DEFAULT_FROM_EMAIL` (required
  together), and as needed `GUARDIAN_EMAIL_PORT`, `GUARDIAN_EMAIL_USE_TLS`,
  `GUARDIAN_EMAIL_USE_SSL`, `GUARDIAN_EMAIL_HOST_USER`,
  `GUARDIAN_EMAIL_HOST_PASSWORD`. A login without TLS, both TLS modes at
  once, or a port that is not a number stop guardian at start-up.
- `GUARDIAN_CONTACTS_SECRET`: a new value of at least 32 characters
  (`openssl rand -hex 32`), different from every other secret. identity
  does not start if it equals the gateway-internal secret, the JWT key or
  the API-key hash secret. New installations get one from
  `make generate-secrets`.
- `GUARDIAN_BASE_URL`, if the e-mails should carry links. It must be an
  origin (`https://wildbox.example.com`): a value with a path, a query or
  credentials stops guardian at start-up.

**Who is written to.** Once a mail server is configured, the owners and
admins of a team receive its compliance notifications, the alerts and
scheduled reports of rules and schedules that name no recipients, and one
e-mail per SLA violation that has no assignee who can be told. To keep an
alert rule's e-mail away from them, give the rule its own recipients.

**Team memberships.** guardian learns who belongs to a team from the
requests it serves and, now, from identity:

- Removing a member from a team, or deleting an account, ends what they
  were assigned in guardian in that team: vulnerabilities, remediation tickets,
  workflows and steps, asset owner and technical contact, assessor,
  dashboard shares. When guardian is down the removal takes up to about
  7 seconds longer and then succeeds; identity logs
  `guardian was not told of ...`. Apply it later with
  `docker compose exec guardian python manage.py revoke_team_membership --team <team UUID> --user <user UUID>`.
- A member guardian has not seen for more than 30 days cannot be assigned
  work until their next request in the team
  (`GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS`, 1 to 365; an invalid value
  stops guardian, its worker and its scheduler at start-up).
- A member removed from a team and added back within ten minutes can be
  assigned or shared with only after the ten minutes.

**A deployment with its own manifests** must pass
`GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS` and `GUARDIAN_INTERNAL_URL` as the
Compose files do, let identity reach `open-security-guardian:8013` and
`guardian-worker` reach identity on the internal network, and pass both
containers the contacts secret. Set `GUARDIAN_INTERNAL_URL` empty only if
the deployment does not run guardian. One that already set `EMAIL_HOST`
must also set `DEFAULT_FROM_EMAIL`: there is no default sender any more,
and guardian does not start without one.

`EMAIL_BACKEND`, `DEFAULT_NOTIFICATION_RECIPIENTS` and
`SECURITY_TEAM_EMAIL` are not read. A deployment that relied on the console
backend to see e-mails in the worker's log no longer sees them there; one
that defined the two recipient settings in a custom settings module sets
`notification_config.recipients` on alert rules and `recipients` on report
schedules instead.

### 9. guardian's rate limit is per user and can be set

guardian's throttle limited nobody and reported the service unhealthy for
ten minutes of every hour. It is now a per-user limit.

- To change it set `GUARDIAN_RATE_LIMIT_USER` in `.env` (for example
  `500/hour`, or `off`). A malformed value stops guardian at start instead
  of failing every request.
- `API_RATE_LIMIT` in the root `.env` never had an effect and still has
  none. A guardian run outside Compose with `API_RATE_LIMIT` set still
  applies it, to the per-user rate only, and validates it: a value DRF
  tolerated by accident (`10/hours`) stops the start. There is no anonymous
  rate any more.

### 10. agents: team-data tools are opt-in; the limits are read from `.env`

- **The analysis does not read your team's data unless you opt in.**
  `threat_intel_query_tool` and `vulnerability_search_tool` now work, and
  are off: set `AGENT_TEAM_DATA_TOOLS` in `.env` to one or both names to
  give them to the model. Doing so sends what they return (the team's
  indicators; guardian's vulnerabilities with asset names) to Anthropic,
  and exposes it to instructions hidden in text the other tools fetch.
  Read "Giving the AI analysis your team's data" in
  `docs/guides/deployment.md` first. Any other value stops the agents
  service at start.
- Four lookup tools that always failed now work (reputation, DNS, URL
  redirects, file hash), so an analysis uses more of them.
- **`ANALYZE_RATE_LIMIT` and `ANALYZE_TEAM_RATE_LIMIT` are read from
  `.env`.** The Compose override that 0.11.0 asked for is no longer needed
  (it still wins). A value already in `.env`, ignored until now, takes
  effect; one that cannot be parsed stops the service at start.
- **The counters move to Redis** and start from zero. A Redis outage now
  answers `503` on submission. `completed_today` and `failed_today` restart
  from zero and reset at 00:00 UTC.
- **Without `ANTHROPIC_API_KEY`**, submissions are still accepted and each
  task now fails at once, saying that AI analysis is not configured.
- `TASK_TIMEOUT` below 60 stops the service at start; the root Compose
  file does not pass it.
- New optional variables: `AGENTS_WILDBOX_DATA_URL`,
  `AGENTS_WILDBOX_GUARDIAN_URL`. A deployment that runs the agents service
  outside the Compose files and relied on the `localhost` defaults of
  `WILDBOX_API_URL`, `WILDBOX_DATA_URL` or `WILDBOX_GUARDIAN_URL` must set
  them. `WILDBOX_RESPONDER_URL` is gone: a `.env` file in
  `open-security-agents/` that still sets it, which only a run outside the
  stack reads, stops the service at start with an error naming the key.
- The dashboard has a new sidebar entry, AI Analysis. The page keeps the
  indicators submitted from a browser in that browser's `localStorage`, per
  account, until removed there.

### 11. tools: a shared hourly limit, fewer unauthenticated routes

- **`REDIS_URL` is required to run the tools that act for a caller** (today
  `sql_injection_scanner`). The root Compose files set it for the API and
  the worker. Without it, or while Redis is unreachable, a synchronous run
  answers 503 `Rate limiting temporarily unavailable` and an asynchronous
  one fails. Every caller starts with a full allowance after the upgrade.
- **`/api/system/info`, `/api/system/metrics`,
  `/api/system/operational-metrics` and `/api/system/health-aggregate`
  answer 404.** The gateway never routed them; a script or monitor that
  called them on the service port should use `/metrics`, `/health` and the
  other services' own health checks.
- **`GET /health` and `GET /api` on the service port answer less.**
  `environment`, `available_tools`, `max_concurrent_tools`,
  `default_timeout` and `response_time_ms` are gone from `/health`, and
  `available_tools` from `/api`; `version` is `0.1.6`, not `1.0.0`.
  `active_executions` is no longer always 0. The health checks read the
  status and are unaffected. The tool list is `GET /api/v1/tools` through
  the gateway.
- A task whose worker process dies three times while running it ends as
  `failed`, with that reason. It used to be restarted without end.
- Two Redis keys per task are new, in the tools database, expiring after a
  day: the cancellation record and the start count.
- An override of your own that sets `WEB_CONCURRENCY` or adds `--workers`
  to the tools API should drop it: the API is one process by design.
- A standalone tools checkout whose `open-security-tools/.env` still sets
  `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW`, `ENABLE_RATE_LIMITING` or one
  of the seven `*_SERVICE_URL` keys stops at start-up with
  `Extra inputs are not permitted`. Delete those lines. The image is not
  affected: it contains no `.env` file.

### 12. The API schemas are served in development only

`/openapi.json`, `/docs` and `/redoc` answer 404 on every service unless
`ENVIRONMENT` is exactly `development`; a service started without
`ENVIRONMENT` does not serve them either. No client of the gateway is
affected: none of these paths was routed.

- A production deployment only loses data's and tools' `/openapi.json` on
  their service ports. One with any other value, `staging` for example,
  loses the three paths on identity, agents and the responder as well.
- cspm no longer follows `DEBUG`: `DEBUG=true` with
  `ENVIRONMENT=production` no longer serves the pages.
- The sensor serves its route list at `/` and `/docs` only with
  `ENVIRONMENT=development`; it used to serve it unless the value was
  `production`.
- `scripts/generate-api-docs*` are removed.
  `https://www.wildbox.io/api/agents-api.html` and `.../responder-api.html`
  redirect to the endpoint references. For an OpenAPI schema, run the
  service with `ENVIRONMENT=development` and read `/openapi.json` on its
  local port (guardian: `/api/schema/` with `DEBUG`).

### 13. Backup, restore and rotation scripts

**Backup.**

- `make backup` works on a default stack: it runs inside the stack's
  `postgres` container, also snapshots Redis, and writes to `./backups` (it
  was `/backups/postgres`, which the host usually cannot create). The
  `backup` profile container still writes to `/backups/postgres` in the
  `wildbox_backups` volume. `BACKUP_DIR` is no longer restricted to
  `/backups/` or `/tmp/`.
- **A backup without Redis now fails** instead of warning. If you run
  `scripts/backup_postgres.sh` yourself against an external database and
  have no `redis-cli` or `REDIS_PASSWORD` there, provide them or set
  `SKIP_REDIS=true`.
- **Host mode is selected by `POSTGRES_HOST`.** A cron line that sets
  `POSTGRES_HOST` and `POSTGRES_PASSWORD` keeps working. One that set only
  `POSTGRES_PASSWORD` and relied on the `wildbox-postgres` default must add
  `BACKUP_MODE=host`, or it now runs in Compose mode.
- Unknown arguments to the backup script are now an error.

**Restore.**

- **`scripts/restore_postgres.sh` no longer restores over the live
  databases by default.** A command or script that relied on that now exits
  with status 2 and changes nothing. Add `--overwrite-live-databases` where
  overwriting is intended. It stops at the first error and rolls that
  database back, where it used to carry on and exit non-zero at the end;
  its output changed: the archives are read first, then the databases are
  restored.
- **`scripts/restore_redis.sh` needs `--replace-redis-data`**, and room in
  the Redis volume for the old data and the new at once.
- `--latest` can refuse, in both scripts: when the newest run lacks a
  database that was asked for, or has no Redis snapshot. Name the run with
  `--timestamp`.
- `make restore-drill` restores into scratch databases through the
  container and compares exact row counts. Its output changed
  (`every row count equals the source's`), and it no longer writes to
  `/tmp/wildbox-restore-drill`; an old directory there can be deleted.

**Rotation.**

- **Rotating `POSTGRES_PASSWORD` or `REDIS_PASSWORD` needs the stack
  running** and changes the password in the server itself. Do not run
  `\password` by hand before or after it. Set `COMPOSE_FILE` (and
  `COMPOSE_PROJECT_NAME`, if you use one) the way you start the stack.
- Afterwards run the one command the script prints
  (`docker compose up -d --no-deps <services>`, no longer
  `--force-recreate` of everything). For Redis it recreates Redis and the
  services that use it; until then a restart of the Redis container brings
  the old password back, and Redis reads `unhealthy` (section 4). The
  command names the `backup` container only when that profile is active.
- **If you rotated `POSTGRES_PASSWORD` with an earlier version**, `.env`
  may hold a `POSTGRES_PASSWORD` that neither the server nor the connection
  strings use. Running the rotation again repairs it.
- Rotated values have the generator's shapes: `API_KEY` is
  `wsk_prod.<64 hex>`; `JWT_SECRET_KEY`, `GATEWAY_INTERNAL_SECRET` and
  `API_KEY_HASH_SECRET` are 64 hex characters; `REDIS_PASSWORD` is 24
  characters. If you rotated `API_KEY` with an earlier version and
  `make start` now fails on `validate-secrets`, rotate it once more.
- Commands copied from the guides that pass `-e REDISCLI_AUTH="..."` still
  work; replace them with the new form, which keeps the password out of the
  process list.

### 14. `make health` exits non-zero when something is unhealthy

If a deployment script or cron job calls `make health`, it will start
failing on stacks it used to pass: a service answering an error, guardian
down, PostgreSQL missing a database, Redis down or refusing the
`REDIS_PASSWORD` of `.env`. That is the fix; check anything that runs
`make health && ...`.

- It no longer creates the `data` database or restarts the gateway. If you
  relied on that, run
  `./scripts/shell-scripts/comprehensive_health_check.sh fix`.
- It fails when it finds no Redis password to check with. Set `ENV_FILE` if
  the stack uses another env file.
- With the `automations` or `monitoring` profile, set `COMPOSE_PROFILES`
  (`COMPOSE_PROFILES=automations,monitoring make health`) to require those
  services. Without it they are checked when they answer and skipped when
  they do not; `alertmanager` has a line of its own.
- `scripts/shell-scripts/system_monitor.sh` is removed. Nothing called it.

### 15. Monitoring profile: Alertmanager, Prometheus 3, new alert names

For a deployment that runs `--profile monitoring`. Others notice nothing.

- `docker compose --profile monitoring up -d` now also starts
  `alertmanager` on `127.0.0.1:9093` (the port must be free) and creates
  the volume `alertmanager_data`. With the production overlay, keep passing
  the same `-f` files, or the two services are recreated on the development
  network.
- **You are still not notified.** Alerts now reach Alertmanager, whose
  shipped configuration sends them to `no-notifications`. To receive them,
  follow "Being notified" in `docs/guides/deployment.md`, section 7: copy
  an example to `monitoring/local/`, put the secret in
  `monitoring/secrets/` (readable by UID 65534), set
  `ALERTMANAGER_CONFIG_FILE` in `.env`, recreate the container, send the
  test alert. `ALERTMANAGER_SECRETS_DIR`, `ALERTMANAGER_EXTERNAL_URL` and
  `PROMETHEUS_EXTERNAL_URL` are optional too; none is a secret.
- **Prometheus moves from 2.55.1 to 3.13.4.** The data volume is read as it
  is; going back is possible to 2.55 and not earlier. If you added rules or
  scrape targets of your own: range selectors exclude a sample that falls
  exactly on the lower bound, and a target must answer `/metrics` with a
  valid `Content-Type`. The web UI is the new one. Console templates are no
  longer shipped.
- **Alert names.** `WildboxToolFailureRate` is
  `WildboxSyncToolFailureRate`; `WildboxNoToolExecutions` is gone;
  `WildboxAlertmanagerDown`, `WildboxAlertNotificationsFailing`,
  `WildboxAsyncToolFailureRate`, `WildboxAsyncToolTasksNotConsumed`
  (critical) and `WildboxAsyncToolMetricsUnreadable` are new. Anything of
  yours that matches the old names, or routes by name or severity, needs
  the new ones. The tools API exports four new `wildbox_tool_async_*`
  metrics.
- If you added an `alerting:` section to `monitoring/prometheus.yml`
  yourself, `git pull` will conflict there; keep whichever target you use.

### 16. Sensor: configuration, delivery and local API

Rebuild the sensor image; it moves to osquery 5.23.1. Validate a
configuration with the new code before restarting, from
`open-security-sensor/`:

```bash
python main.py --config <file> --validate-config
```

**Log sources.**

- A sensor with log forwarding on and no `log_sources` section reads what
  it read before: the per-platform defaults.
- **A sensor whose configuration has a `log_sources` section now reads
  exactly the enabled sources of that section**, and no longer
  `/var/log/syslog`, `/var/log/auth.log` and the journal, which it read
  whatever the section said. To keep those, list them:

  ```yaml
  log_sources:
    - {name: syslog, path: /var/log/syslog, format: syslog}
    - {name: auth, path: /var/log/auth.log, format: syslog}
    - {name: journald, type: journald}
  ```

- **A `log_sources` section the sensor cannot understand stops it at
  start-up** (exit code 2; the message names each entry). The `filters` key
  the web-attack-detection use case showed was never implemented: remove
  it. A `log_sources:` key with every entry commented out is refused too:
  write `log_sources: []` or remove the key.
- In the container a source's path is the container's, and no host log is
  mounted. Mount the log directory read-only and name the mounted path
  (sensor README, "What a source can read"). The container runs as uid
  999: logs that are not world-readable need `group_add`.
- A configuration copied from the use case has `logging.format: json`,
  which prints the word `json` for every log record. Remove that line.

**Stricter start-up.** These now stop the sensor with a message: a
`logging.format` or `logging.level` the logging module cannot use; a
`fim.paths` that is not a list of absolute paths; `fim.exclude_patterns`
given as one string (it silently excluded every file), an invalid
`fim.max_depth` or `fim.max_files`; a `data_dir` that does not exist or is
not writable by the sensor's user; no working `osqueryi` on the `PATH`
while an osquery collection setting is on. No `osqueryd` is started any
more.

**Positions and buffering.**

- The container configurations set `data_dir: /var/lib/security-sensor`,
  the existing `sensor_data` volume. The first start after the upgrade
  behaves as before (`read_from` applies, the file monitor takes its
  baseline); from then on a restarted sensor goes on where it stopped, and
  reports the file changes made while it was stopped. A configuration of
  your own keeps positions in memory until you add `data_dir`. One sensor
  per directory.
- **A sensor whose key is refused stops collecting when its buffer is
  full**, instead of reading on and discarding. `delivery_state` in
  `GET /api/v1/stats` and `main.py --status` say so; alert on it.
- `data_lake.retry_attempts` is ignored, with a warning: remove it. New
  optional keys: `data_lake.retry_max_delay`, `buffer_max_events`,
  `buffer_max_bytes`, `rate_limit_share` (0.5) and `fim.max_files`
  (50,000).
- `config.yaml` (the host configuration) listed the container's
  `/host/...` paths under `fim.paths`, which exist on no host; it now lists
  `/etc`, `/bin`, `/usr/bin` and `/opt`. A host started from that file
  begins to watch them.
- `main.py --status` exits 1 when no sensor answers; a script that relied
  on its constant 0 must be changed.
- The `security-sensor` and `ossensor` commands are gone; start the sensor
  with `python main.py --config <file>`, as the image does.
- A sensor that was stuck on a batch the data service answered `503` for,
  because of a value the database refuses, delivers the rest of its buffer
  once the data service is upgraded, and drops the event at fault
  (section 22).

**Stopping.** Nothing to do for a stack started from the repository's
Compose files: `stop_grace_period` is still 30 s, and the stop now fits in
it (the collectors get 8 s instead of 15, the pipeline 12 instead of 15).

- A stop asked for while the sensor is starting is now received, and ends
  with exit status 0 and one of two new lines:
  `Security Sensor not started: a stop was asked for while it was starting`
  or `A stop was asked for while the sensor was starting: the start is
  abandoned, and what it had started is stopped`. It used to be lost, and
  the container was killed when the grace period ended.
- **If you run the sensor with a `command:` or an image of your own**, keep
  `env --block-signal=TERM --block-signal=INT` in front of
  `python main.py`, as the image's `CMD` has it. Without it a stop that
  falls in the interpreter's own start is not received.
- Wherever else you run it, give the sensor at least 30 s to stop
  (`docker run --stop-timeout 30`, `terminationGracePeriodSeconds: 30`).
- New in the logs:
  `File integrity monitoring: stopped with N changes found and not queued
  yet`, and, when a worker thread outlives the stop by 2 s,
  `The sensor has stopped and its process has not ended after 2 seconds`.
  The count in `Stopped with N events still on their way to the sender`
  includes the event a collector was waiting to queue and the events the
  processor was holding.
- The image no longer has `osqueryd` on its `PATH`, nor `osqueryctl`.

**Inventory.** `system_inventory.*` events arrive when the sensor starts
and every `performance.inventory_interval` seconds after that (default
3600), not every `performance.query_interval`. Set
`performance.inventory_interval: 0` to keep the old pace. Anything that
took the absence of a recent inventory event as a sign of a silent sensor
should look at another event type.

**Events.**

- On Windows, `user_events.logon_events` is gone; it never returned a row.
  Configure a `windows_event` log source on the `Security` log.
- Unified-log events are `log.<name>` (were `log.unified`) and Windows
  events `log.<name>` (were `log.windows.<log>`), as documented.
  `process_events.process_events`, `network.socket_events` and
  `user_events.user_events` are no longer produced; they never carried a
  row.
- `metadata.log_file` is the file the line came from. A line longer than
  16 KiB is cut and carries `metadata.truncated: true`. Bytes that are not
  UTF-8 arrive as U+FFFD instead of disappearing. An unfinished line is no
  longer sent in two parts, and a journald source no longer sends
  `journalctl`'s last ten entries at each start.
- `network.process_open_sockets` rows of `systemd` and `dbus` processes are
  no longer filtered out. With osquery 5.23.1, `users` returns only the
  users of `/etc/passwd`, so the user name of a process owned by a
  directory account is empty in the process tree.

**Local API** (`127.0.0.1` of the sensor).

- `GET /api/v1/stats` has more fields and real values; `throttled` is
  renamed `over_limits`; `delivery_state` and `delivery_since` are new;
  `events_in_pipeline` also counts events being processed.
- `GET /api/v1/components`: under `data_forwarder`, `events_failed` and
  `current_batch_size` are gone, `delivery`, `pacing` and `buffer` are new,
  and `events_dropped_refused` counts single events;
  `osquery_manager.process_alive` is gone (`osqueryi`, `osquery_version`,
  `queries_run`, `queries_failed`, `last_error` instead); `file_monitor`
  gains `max_files`, `files_over_limit`, `baseline` and `changes_failed`; `log_forwarder`
  gains `default_sources`, `stats`, per file source `path`, `format`,
  `files` and `problems`, and `behind` on its positions.
- `GET /api/v1/config` gains `log_sources` (`null` without the section)
  and `inventory_interval`.
  `GET /api/v1/dashboard/metrics` lost the fields the sensor never
  measured.

### 17. Standalone Compose files and images of your own

For the platform stack (`docker-compose.yml`, with or without the
production overlay) nothing here applies. With the production overlay ten
more services rotate their log, once the containers are recreated.

- Removed, since none could start:
  `open-security-gateway/docker-compose.dev.yml`,
  `open-security-data/docker-compose.yml`,
  `open-security-sensor/docker-compose.dev.yml` and
  `open-security-sensor/docker-compose.scale.yml`. Run the data service
  from the root file (`docker compose up -d data data-scheduler gateway`).
- `open-security-sensor/docker-compose.yml` starts the sensor only. If you
  ran the old file: `docker compose down --remove-orphans` once, to remove
  its Redis, and delete the volumes `redis_data`, `prometheus_data` and
  `grafana_data` of that project if you do not want them. The
  `security-suite` network is no longer needed; to attach the sensor to
  another stack's network, name it in a `docker-compose.override.yml`.
- `open-security-cspm/docker-compose.yml` no longer mounts `./config`.
- `open-security-gateway/docker-compose.yml` could not start and is
  removed, with its `Makefile`, `scripts/setup.sh`, `scripts/test_config.sh`,
  `test/integration_test.sh` and `.env.example`. Run the gateway from the
  root stack.
- The tools standalone Compose files require `API_KEY`.
- Removed, since nothing ran them: `scripts/setup.sh` (use
  `make generate-secrets` and `make start`), the dashboard's and tools'
  `Makefile`s and `open-security-tools/.env.template`.
- **A `.env` file in a service's own directory** (a run outside the
  Compose stack) stops tools, responder, cspm or agents at start if it
  still names a removed setting: `API_KEY_NAME`, `LOG_FORMAT`,
  `TOOL_RESULT_TTL`, `ENABLE_CACHING`, `DATABASE_URL`,
  `ENABLE_AUDIT_LOGGING`, `ENABLE_SECURITY_HEADERS`, `TOOLS_DIRECTORY`,
  `AUTO_RELOAD_TOOLS` (tools); `WILDBOX_SENSOR_URL`, `API_KEY`,
  `DEFAULT_STEP_TIMEOUT`, `MAX_CONCURRENT_EXECUTIONS`, `DRAMATIQ_PROCESSES`,
  `DRAMATIQ_THREADS` (responder); `REDIS_PASSWORD`,
  `ACCESS_TOKEN_EXPIRE_MINUTES`, `REPORTS_STORAGE_PATH`,
  `PROMETHEUS_ENABLED`, `PROMETHEUS_PORT`, `WILDBOX_IDENTITY_URL`,
  `WILDBOX_API_URL`, `WILDBOX_GUARDIAN_URL` (cspm); `DEBUG`,
  `INTERNAL_API_KEY`, `MAX_CONCURRENT_TASKS` (agents). Remove the line. In
  the Compose stack nothing changes: those variables were never passed, or
  are ignored.
- The dashboard's standalone Compose file could not start either and is
  removed; run the dashboard from the root stack.
- The remaining standalone files publish their ports on `127.0.0.1`
  instead of every interface: tools (8000, Redis 6379) and agents (8006,
  Redis 6382). To reach one from another machine, use an SSH tunnel or a
  Compose override that names the address.
- `open-security-tools/Dockerfile.dev` is Python 3.11 and needs the
  `shared` build context: a bare `docker build -f Dockerfile.dev .` needs
  `--build-context shared=../open-security-shared`.
- **A Dockerfile of your own that installs `open-security-shared`** must
  name the extras of the modules it uses, for example
  `"/tmp/open-security-shared[fastapi,metrics]"`: the package no longer
  pulls in FastAPI, Pydantic or prometheus-client by itself. The
  `observability`, `tracing`, `auth` and `events` extras do not exist any
  more, and `install_observability()` has no `enable_tracing` argument: no
  service used them. An image build fails where a lock does not provide
  what the shared modules in use require.

### 18. Settings that are gone

Leftover lines in `.env` are ignored and can be deleted.

| Setting | Was |
| --- | --- |
| `RESPONDER_DATABASE_URL` | Passed to the responder, which has no database. The container no longer waits for PostgreSQL |
| `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW` | tools settings that never limited anything. The per-team limit is the gateway's `RATE_LIMIT_PER_HOUR` |
| `N8N_BASIC_AUTH_ACTIVE`, `N8N_BASIC_AUTH_USER`, `N8N_BASIC_AUTH_PASSWORD` | Ignored by n8n 1.x (section 7) |
| `ENABLE_METRICS`, `METRICS_PORT`, `WORKERS` for the tools API | Passed to no container, or without effect |
| `API_RATE_LIMIT` | Never applied to guardian in the Compose stack (section 9) |
| `NEXTAUTH_SECRET`, `NEXT_PUBLIC_DEBUG` | Passed to the dashboard, which has no NextAuth and reads neither. `./scripts/rotate_secrets.sh --secret NEXTAUTH_SECRET` answers that it is not a rotatable secret |
| `GRAFANA_ADMIN_PASSWORD`, `GUARDIAN_DB_PASSWORD`, `N8N_ENCRYPTION_KEY` | Generated, and interpolated by no Compose file (section 7 for n8n's key) |
| `SESSION_TIMEOUT`, `MAX_LOGIN_ATTEMPTS`, `LOCKOUT_DURATION`, `REQUIRE_EMAIL_VERIFICATION`, `REQUIRE_MFA` | Offered by the template, read by nothing. They switched nothing on or off |
| `POSTGRES_MAX_CONNECTIONS`, `POSTGRES_SHARED_BUFFERS` (production overlay) | Set on the postgres container, whose image reads neither: PostgreSQL has always run with 100 connections and 128MB. To raise them, add `command: postgres -c max_connections=200 -c shared_buffers=256MB` in an override file |
| `LOG_FILE` and the `guardian_logs` volume | guardian logs to the console only. The volume was always empty; `docker volume rm <project>_guardian_logs` removes it |
| `ENVIRONMENT` for guardian, the gateway, the dashboard, postgres and n8n; `WILDBOX_ENV`, `GATEWAY_LOG_LEVEL`, `LOG_LEVEL` for the gateway | Passed and read by none of them. guardian's development mode is `DEBUG` |
| `WILDBOX_API_URL`, `WILDBOX_API_KEY`, `WILDBOX_DATA_URL`, `WILDBOX_DATA_API_KEY` for guardian; `API_BASE_URL`, `CORS_ORIGIN`, `CUSTOM_KEY` for the dashboard | Read by nothing |
| `WORKER_CONCURRENCY`, `CELERY_WORKER_PREFETCH_MULTIPLIER` (production overlay, agents and responder) | Read by nothing: the workers' concurrency is set in their entrypoints |

### 19. A gateway configuration of your own

The shipped configuration needs nothing. A server block of your own must
declare three variables, or every authenticated request answers 500 and
scope-limited keys need `admin`:

```nginx
set $wildbox_route_uri $uri;
set $wildbox_auth_type "";
set $wildbox_scopes "";
```

A location that calls `authenticate()` needs a row in `ROUTE_SCOPES`
(`auth_handler.lua`); without one, scope-limited keys need `admin` there.

An `nginx.conf` of your own must take the `limit_req` zones from the file
the entrypoint writes, and define none itself (section 21):

```nginx
include /run/wildbox-gateway/limit_req_zones.conf;
```

### 20. guardian refuses internal scan targets (`GUARDIAN_ALLOWED_INTERNAL_TARGETS`)

guardian's discovery and port scans now apply the target policy the tools
service has applied since 0.11.0: a private, loopback, link-local,
multicast, reserved, shared or cloud-metadata address is refused. In the
Compose stack `guardian-worker` shares a network with PostgreSQL, Redis and
identity, and Docker takes the stack's networks from the same private
ranges a LAN uses, so no default can open the LAN without opening those
too.

- **After the upgrade**, a discovery (`assets/assets/discover/`), a new or
  edited discovery rule and a port scan (`assets/assets/{id}/scan/`) aimed
  at such an address answer `400`. To keep scanning your own network, add
  its ranges to `.env` as comma-separated CIDR ranges and IP addresses,
  then recreate `guardian` and `guardian-worker`:

  ```bash
  GUARDIAN_ALLOWED_INTERNAL_TARGETS=192.168.50.0/24,10.20.0.0/16
  ```

- A discovery must lie inside the listed ranges entirely; the limit of
  1,024 addresses for each discovery still applies.
- No host names in the list, and a range must have its host bits zero. A
  bad entry stops `guardian` and `guardian-worker` at start-up;
  `docker compose logs guardian` names the variable and the entry.
- `TOOLS_ALLOWED_INTERNAL_TARGETS` does not open anything for guardian. If
  the tools service and guardian both scan the lab, set both.
- **Stored discovery rules keep their networks.** Each run skips the
  internal networks that are not listed, and `guardian-worker` logs the
  network and the variable; the run still ends `completed`, with those
  networks not counted in `networks_queued`. Such a rule cannot be saved
  again with that network until the range is listed.
- Assets at internal addresses stay in the inventory and can be created as
  before; they are not port scanned, on creation or on request, until
  their range is listed.
- Do not list the stack's Docker networks, loopback or the cloud metadata
  address.
- API clients: the `400` bodies are `{"network_range": [message]}`,
  `{"target_specification": [message]}` and `{"error": message}`; the
  message names `GUARDIAN_ALLOWED_INTERNAL_TARGETS`.

### 21. The gateway's per-address limits are settings

Nothing changes for a deployment that sets nothing. The three limits the
gateway applied to every client address were written in `nginx.conf`; they
are now optional settings with the same values as defaults:

| Setting | Default | Protects |
| --- | --- | --- |
| `GATEWAY_RATE_LIMIT_PER_SECOND` | 100 | Every request to the HTTPS server |
| `GATEWAY_AUTH_RATE_LIMIT_PER_SECOND` | 5 | Login, registration and forgotten password |
| `GATEWAY_STATIC_RATE_LIMIT_PER_SECOND` | 500 | Static assets |

- A value that is not a whole number from 1 to 100000 stops the gateway at
  start-up, with a message naming the setting. A change needs the
  container recreated; an nginx reload does not apply it.
- The bursts are unchanged and are not settings.
- The gateway image must be rebuilt (section 1).
- To run the integration or Playwright suites against a stack of your own,
  add the three settings at 10000 (and `RATE_LIMIT_PER_HOUR=1000000`) to
  its `.env`, as `tests/README.md` says. With the defaults the integration
  suite warns before its first test.

### 22. data: ingest is all or nothing; only sources that can be collected run

**Ingest clients.** A batch is stored whole or not at all, and every answer
other than `200` means nothing was stored:

| Answer | When | What the sender does |
| --- | --- | --- |
| `200`, `events_ingested` equal to `events_received`, empty `errors` | Everything is stored | Nothing |
| `422`, naming the event by its index | An event is invalid | Sends the others without it |
| `422 BATCH_NOT_STORABLE` | The database refuses a value the schema let through | Splits the batch |
| `503` with `Retry-After` | Another database error | Sends the batch again |

`sensor_id` and `source_host` are limited to 255 characters, and
`sensor_id`, `source_host` and `raw_data` may not contain a NUL character.
Such events were never stored: they answered a `503` every time, or a `200`
with nothing stored, and are now refused with a `422` that names them.
Sensors need no change.

**Sources.** After the upgrade the scheduler disables every enabled source
whose `source_type` has no collector, with the reason in `last_error`. On a
deployment that ran `manage.py sources add-defaults` or
`scripts/init_feeds.py`, that is every source they created (types `txt`,
`json`, `api`, `feed`); none of them ever collected anything. Custom
sources of type `http`, `https`, `json`, `csv`, `txt`, `rss` or `atom` are
disabled too: no collector could run them.

```bash
docker compose exec data python manage.py sources add-defaults
```

gives the default that works: it turns the "Feodo Tracker" row of the old
defaults into the one that can be collected, in place, and enables it.
`scripts/init_feeds.py` is gone. The threat-intelligence pages show fewer
active feeds, which is now the number of feeds that are collected.

`recent_collections` of `GET /api/v1/data/stats` counts the caller's and
the global sources' runs, where it counted every team's.

`collection_runs.error_message` and `sources.last_error` now hold the class
and HTTP status of a failed collection, not the client's error text. Rows
written before the upgrade keep what they have: a feed whose URL holds a
key may have it in those two columns, and in old log files. Clear them, or
rotate the key, if that matters to you.

### 23. Logs: nothing a caller submits is written by value

**The responder printed the Redis password at every start.** From 0.6.1 to
0.11.2 its entrypoint wrote `REDIS_URL`, password included, to the
container's log: `docker logs open-security-responder`, the file Docker
keeps for the container under `/var/lib/docker/containers/`, and wherever
the deployment ships container logs. The line is gone, and recreating the
container in step 7 discards its log file.

- Redis is not published outside the stack's Docker network in the shipped
  Compose files, so the password opens nothing from outside by itself: it
  is useful to someone who can also reach that network.
- **If those logs were readable by anyone who should not hold the password,
  or left the host** (a log collector, a support bundle, a pasted
  `docker logs`), rotate it after the upgrade:
  `./scripts/rotate_secrets.sh --secret REDIS_PASSWORD`, then the command
  it prints (section 13). Copies shipped elsewhere are yours to purge:
  search them for `Redis URL: redis://`.
- If the logs never left the host and only its administrators can read
  them, there is nothing to rotate.

- **Access logs lose the query string.** The gateway's access log and each
  service's uvicorn access log have the method, the path and the status.
  The gateway's also loses `"$http_referer"`: a parser of the `gateway`
  format must drop that field.
- **The tools service's log lines gain fields**: `request_id`, `tool`,
  `user_id`, `team_id`, `input_fields` (names, not values), `status`,
  `duration`. They carried none before.
- **Flower** shows `{'tool_name': ..., 'user_id': ..., 'input_data': '<n
  field(s)>'}` for a task, not its input.
- **identity** logs a locked account by a digest of the address:
  `printf %s user@example.com | shasum -a 256`, first twelve digits.
- Log lines of the HTTP client libraries (httpx, urllib3, botocore) below
  WARNING are no longer written, whatever `LOG_LEVEL` is.

### 24. API clients: error bodies

Statuses do not change, except where said.

- **tools, data, agents, responder: an error whose detail is a dict.**
  `error.message` is the explanation, where it was a Python dict literal,
  and `error.details` holds the dict:

  ```json
  {"error": {"code": 403, "type": "HTTPException", "request_id": "...",
    "message": "This action requires one of these roles: owner, admin",
    "details": {"error": "Insufficient permissions",
                "message": "This action requires one of these roles: owner, admin",
                "code": "INSUFFICIENT_ROLE"}}}
  ```

  A client that matched on a substring of `error.message`, such as
  `GATEWAY_AUTH_REQUIRED`, must read `error.details.code`. Through the
  gateway a client meets this in one place today:
  `POST /api/v1/responder/playbooks/reload` as a member or viewer.
- **cspm: every error an endpoint raises has the common shape.** Read
  `error.message` instead of the top-level `message`, and `error.code`
  instead of `details.status_code`. `error` is an object, not the string
  `"HTTPException"`. There is no `timestamp`; `error.request_id` identifies
  the request in the logs.
- **identity: 404, 500 and 503 have the common shape.** A client that read
  `detail` must read `error.message`. The message of a route-raised 404 is
  the route's (`User not found`), not `Endpoint not found`. A 500 from the
  analytics routes or from the deletion of a user reads
  `An internal error occurred`, with a `request_id`; the cause is in the
  service log under that id.
- **The field errors of a 422** no longer carry `input`, `ctx` or `url`;
  `type`, `loc` and `msg` are unchanged. The validation message for an IOC
  no longer ends with the value.
- **Invalid input that a model's validator refuses answers 422** with the
  field errors, where it answered 500 (for example
  `POST /api/v1/agents/analyze` with an IOC value of the wrong format). A
  client that retried that 500 gets a 422 it should not retry.
- The `error_message` of a failed tools workflow step no longer contains
  the text of a connection error, an exception's class or a module path;
  an invalid parameter is reported as `<field>: <message>`.
- cspm's `/health` answers `"error": "Health check failed"` where it named
  an exception class, and **503** when its body says `unhealthy` (Redis
  unreachable, or the check itself failed). It answered 200 when a check
  raised and 500 when Redis was down. `degraded` (no worker answers) is
  still 200. A monitor that read the code now sees an unhealthy cspm as
  such, and so does `make health`.
- **cspm, with Redis unreachable:** every route that needs it answers
  **503** (`Scan store or task queue temporarily unavailable`) where it
  answered 500. A client that retries on 503 and not on 500 now retries.

### 25. API clients: guardian

Paths are under `/api/v1/guardian/`. Nothing in the dashboard, the
responder, the agents or the shipped automations used what is removed.

**Lists.**

- `next` and `previous` are relative references such as
  `/api/v1/guardian/assets/assets/?page=2`. Resolve them against the URL
  you requested. The former absolute links could not be followed.
- `?page_size=N` is honored on every list, up to 200.
- `vulnerabilities/` and `vulnerabilities/stats/`: `severity`, `status`,
  `priority` and `threat_level` now filter; a client that sent one of them
  and showed the (always empty) answer now gets the matching rows.
  `?search=` also finds a vulnerability by its asset's address, its scanner
  or its service, and requires every word of the text.
- A true/false filter given `false` selects the rows that are not so
  (`overdue`, `due_today`, `due_this_week`, `unassigned`, `is_overdue`,
  `needs_review`). It used to be ignored.
- `?format=json` and `?format=api` no longer choose the renderer; use the
  `Accept` header. On `reports/reports/`, `format` is the filter on a
  report's format. A request with `Accept: text/html` only answers `406`:
  JSON is the only representation unless `DEBUG=true`.
- `assets/assets/?ip_range=` with an IPv6 range of more than 256 addresses
  answers `400`; a range includes its network and broadcast addresses.
  `?tags=a,` ignores the empty entry.

**Removed routes** (`404`, unless said):

| Route | Use instead |
| --- | --- |
| `POST integrations/systems/{id}/test_connection/`, `health_check/` | Nothing: guardian contacts no external system |
| `GET integrations/systems/{id}/sync_status/` | `GET integrations/systems/{id}/` and read `last_sync` |
| `POST integrations/mappings/{id}/test_mapping/`, `sync_now/` | Nothing: there is no synchronization |
| `GET integrations/sync-records/sync_statistics/` | `GET integrations/sync-records/?sync_status=failed` (or another status) and read `count` |
| `POST integrations/sync-records/{id}/retry_sync/` | Nothing |
| `POST integrations/webhooks/{id}/test_webhook/`, `trigger_webhook/` | Nothing: guardian sends no webhooks |
| `GET integrations/logs/error_summary/` | `GET integrations/logs/?level=error` and read `count` |
| `POST integrations/notifications/{id}/test_notification/`, `send_notification/` | Nothing: guardian delivers nothing through a notification channel |
| `POST scanners/scanners/{id}/test_connection/` | Nothing: guardian cannot reach a scanner |
| `POST scanners/scans/{id}/start/`, `stop/`, `pause/`, `resume/` | `PATCH scanners/scans/{id}/` with `{"status": "..."}` |
| `POST scanners/scans/import_results/` (`405`) | `POST scanners/scan-results/` and `POST vulnerabilities/` |
| `POST scanners/scan-schedules/{id}/trigger/`, `enable/` | Nothing: guardian runs no scan schedule. `POST`, `PUT` and `PATCH` on `scanners/scan-schedules/` answer `405` |
| `POST remediation/tickets/{id}/sync_external/` | `PATCH remediation/tickets/{id}/` |
| `POST remediation/workflows/{id}/pause/` | `PATCH remediation/workflows/{id}/` with `{"status": "deferred"}` |
| `GET vulnerabilities/{id}/attachments/` | Nothing: no attachment could be stored |

**Changed answers.**

| Route | Before | Now |
| --- | --- | --- |
| `DELETE integrations/logs/cleanup_logs/` | `200`, nothing deleted | **Deletes** the team's logs older than `older_than_days` (default 30); `400` unless 1 to 36500 |
| `POST remediation/tickets/{id}/assign/` | `200` for any `assignee_id`, ticket unchanged | Sets `assigned_to`; `400` unless a current member of the team |
| `POST remediation/tickets/{id}/update_status/` | Stored any string | `400` for a status the model does not define |
| `POST remediation/templates/{id}/clone/` | `200`, nothing created | `201` with the copy; optional `name` |
| `POST remediation/templates/{id}/apply/` | `200`, no workflow | `201` with the created workflow; `409 WORKFLOW_EXISTS`; `400 TEMPLATE_STEPS_INVALID` |
| `POST remediation/workflows/{id}/start/`, `complete/` | Status only | Also set the actual start and completion dates |
| `POST vulnerabilities/bulk_action/` | `reopen`, `untag`: nothing done. `assign`: cleared the field not given | Performed; `assign` leaves the field not given as it was; `close` writes the resolution metadata and a history entry |
| `POST vulnerabilities/{id}/assign/` | `200` with neither `assigned_to` nor `assignee_group` | `400` |
| `POST vulnerabilities/` | `cve_id` required; no `id` in the answer | `cve_id` optional; `id` in the answer |
| `PUT`, `PATCH vulnerabilities/{id}/` changing `assigned_to` | No e-mail | Queues the assignment e-mail, as `bulk_action/` `assign` does |
| `resolved_at` of a vulnerability | Set by `close/` only | Follows the status on every save |
| `GET vulnerabilities/trends/` | `500` for a `days` that is not a number | `400` unless `days` is 0 to 366; `total_open` and `avg_risk_score` are of what was open on that day |
| `asset_details.environment` in `GET vulnerabilities/{id}/` | `null`, or `500` | The environment's name, or `null` |
| `file_path` on a report | Server path | Field removed |
| `POST assets/assets/discover/` | Any `network_range`, any `scan_type` | `400` unless a network of at most 1,024 addresses and `basic` or `comprehensive` |
| A discovery rule's `target_specification` | Networks of any size and number | `400` over 1,024 addresses a network or 32 networks |
| `POST assets/discovery-rules/{id}/execute/`, `enable/` on a type that is not `network_scan` | `200` | `501 DISCOVERY_TYPE_NOT_IMPLEMENTED`; `PATCH` with `"enabled": true` answers `400` |
| `POST integrations/webhooks/` | A path was unique on the platform | Unique within the team; a duplicate answers `400` on `endpoint_url` |
| `api_key`, `password` (scanners), `auth_config` (external systems), `secret_token` (webhooks), `config` (notification channels) | Stored | `400` on that field when a value is sent. Leave the field out; it was never returned |

A path without its trailing slash, followed through the gateway, now leads
to the route: the redirect guardian answers used to lead to a `404`. Keep
writing the slash; a redirected `POST` is resent as a `GET` by most
clients. `/admin/` answers `404`; it answered `500` in the image. Scans of
internal addresses answer `400` unless their range is listed (section 20).

**Notifications.** `GET reports/alerts/{id}/notifications/` gains
`failure_reason`, and `recipients` lists the owners and admins a
notification was addressed to. SLA entries in a vulnerability's history
read `sent`, `sent to the team's owners and admins (no assignee to
e-mail)` or `not sent (<reason>)`. An assignment notification adds a
history entry with `field_name` `assignment_notification`.

### 26. API clients: tools, agents, responder, cspm

- **`POST /api/v1/tools/{tool}/async` refuses what the synchronous route
  refuses**: 404 for a name that is no tool, 422 for input the tool's
  schema refuses, 400 for a target the network target policy refuses. It
  used to answer 202, and the task then read `failed`. A responder
  playbook step with `async_execution` gets the refusal from the
  submission too.
- **A canceled tools task reads `cancelled` immediately**, and a second
  `DELETE /api/v1/tasks/{id}` answers 400. The error of a task refused when
  it runs names the field and the kind of error
  (`Input validation failed (iterations: int_parsing)`).
- **An asynchronous run whose tool raised** reads
  `error: "Tool execution failed (<class>)"`, and no longer the text of the
  error. A failed step of `security_automation_orchestrator` has a new
  `error_code`; one whose tool raised on its input reads
  `Tool execution failed: the tool could not process its input`. A `403`
  for a target a caller may not test names the target's host, not its URL.
- **agents:** `result_url` is `/api/v1/agents/analyze/{task_id}` (was
  `/v1/analyze/{task_id}`). An analysis that fails reads `status: failed`
  with a specific `error`, where it read as a completed analysis with
  verdict `Informational` and confidence 0. `status` can be `revoked`.
  `started_at` and `completed_at` are the task's start and end; both were
  the time of the request. `GET /api/v1/agents/stats` gains
  `model_configured`, and `failed_today` includes tasks killed at the time
  limit.
- **responder:** `status_url` in the answer of
  `POST /api/v1/responder/playbooks/{id}/execute` is
  `/api/v1/responder/runs/{run_id}` (was `/v1/runs/{run_id}`).
  `GET /api/v1/responder/connectors` no longer returns `config`.
  `GET /api/v1/responder/playbooks` lists a sixth playbook,
  `asset_vulnerabilities`; the steps that call guardian now work, so
  `all_star_e2e` can record a vulnerability when its conditions hold.

A client that built `result_url` or `status_url` from the identifier is
unaffected; one that prefixed the returned value itself must stop.

**cspm.**

- `GET /api/v1/cspm/checks` answers 200 with the catalog where it answered
  500. Each check carries `references` and `remediation`. An unknown
  `provider` value answers an empty list.
- `GET /api/v1/cspm/scans/{id}/compliance` answers 200 for a completed scan
  where it answered 500. `generated_at` is an ISO 8601 time in UTC without
  an offset.
- `DELETE /api/v1/cspm/scans/{id}` answers **409** for a scan that already
  completed, failed or was canceled, where it answered 200 and recorded
  `cancelled`. A client that deleted finished scans to clear them must
  stop: nothing was cleared. A scan canceled before a worker took it is no
  longer run.
- `GET /api/v1/cspm/scans/{id}/report` answers the scan's own id in
  `scan_id`, and `GET /api/v1/cspm/compliance/findings` the same id in
  `scan_id` and `finding_id`; they carried an id no route knows. Reports
  stored before the upgrade are read with the right id too.

### 27. API keys: the documented scope is required on every route

- A key scoped `tools:read` or `tools:execute` can list the tools at
  `GET /api/v1/tools`. Other methods on that path need `tools:execute`
  instead of `write`; the tools service has no such route.
- A key holding `tools:admin` keeps working; the scope now grants what
  `tools:execute` grants.
- API paths ending in `.js`, `.css`, `.png`, `.jpg`, `.jpeg`, `.gif`,
  `.svg`, `.woff`, `.woff2`, `.ttf`, `.eot` or `.ico` now reach their
  service and need a credential.
- What a session or an API key can do through the gateway is otherwise
  unchanged.
- The dashboard's `/api/proxy/*` answers 404, and its own `/api/*` routes
  no longer send `Access-Control-Allow-Origin`. Nothing shipped used them.

## Upgrading to 0.11.2

From 0.11.1, nothing is required for a production deployment: the
changes are in the development stack and in a script's output. If you run
the default `docker-compose.yml` (the development stack), rebuild and
recreate the dashboard, since its container now mounts only `src/` and
`public/`:

```bash
git fetch --tags && git checkout v0.11.2
docker compose up -d --build dashboard
```

After that, a change to `package.json` or to a root config file
(`next.config.js`, `tsconfig.json`, `postcss.config.js`) also needs
`docker compose up -d --build dashboard`. Coming from an earlier release,
follow [Upgrading to 0.11.1](#upgrading-to-0111) first.

## Upgrading to 0.11.1

From 0.11.0, rebuild the dashboard image and recreate it; nothing else
changes. Coming from an earlier release, follow
[Upgrading to 0.11.0](#upgrading-to-0110) first.

```bash
git fetch --tags && git checkout v0.11.1
docker compose build dashboard
docker compose up -d dashboard
```

Use the same `-f` files, or `COMPOSE_FILE`, you start the stack with. The
dashboard now builds with Tailwind CSS 4, which needs Safari 16.4, Chrome
111 or Firefox 128 or later; older browsers can render the pages
without parts of their styles.

## Upgrading to 0.11.0

From 0.10.0: the changes an existing deployment has to act on. The numbered
sections below follow the order in which the changes were merged, not the
order in which to apply them. Apply them in the order of the checklist that
follows; each step names the sections it comes from.

### Order of operations

Every step is marked **required** or **conditional**, with its condition.
Run the commands from the repository root. Steps 1 to 7 run while the 0.10.0
stack is still up: no section needs it stopped, and step 9 recreates the
containers. The commands assume the production overlay; if you start the
stack with other files, name those in `COMPOSE_FILE` instead, and keep them
the same in every step (section 1).

1. **Point Compose at your files (required).** `docker compose` then uses
   the same files in every step, and so does the rotation guard of
   `scripts/rotate_secrets.sh` (section 38). The production overlay needs
   Docker Compose 2.24.4 or later (section 10).

   ```bash
   export COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml
   docker compose version
   ```

2. **Back up the databases and `.env` (required).** guardian's own API keys
   are dropped in step 9 (section 30), and the migrations of step 9 cannot
   be undone without a backup. `make backup` runs
   `scripts/backup_postgres.sh` from the host, which reaches PostgreSQL
   only where `POSTGRES_HOST` resolves; on a default stack, dump the three
   databases through the container (use your `POSTGRES_USER`):

   ```bash
   umask 077
   cp -p .env .env.pre-0.11.0
   for db in identity data guardian; do
     docker compose exec -T postgres pg_dump -U postgres -Fc "$db" > "wildbox-pre-0.11.0-$db.dump"
   done
   ```

   Keep these files private and copy them off the server: they hold every
   secret and every password hash.

3. **Check out 0.11.0 (required).** Nothing runs the new code yet.

   ```bash
   git fetch --tags && git checkout v0.11.0
   ```

4. **Seed `API_KEY_HASH_SECRET` (required, before any new image starts).**
   Without it every existing API key answers 401 (section 38). Run it once,
   while `.env` still holds the `JWT_SECRET_KEY` the running identity uses:

   ```bash
   make init-api-key-hash
   ```

5. **Edit `.env` (required review; each change as marked).**
   - Required check: `RATE_LIMIT_PER_HOUR` is a whole number from 1 to
     1000000000, or empty (section 32).
   - Required with the production overlay: `NEXT_PUBLIC_GATEWAY_URL=`
     (empty) unless the dashboard is served from another origin than the
     gateway (section 16).
   - Required with the production overlay: `CORS_ORIGINS` lists the
     origins you serve; identity now receives it (section 10).
   - Conditional, production Redis: size `REDIS_MAXMEMORY` and
     `REDIS_MEMORY_LIMIT` (at least twice as much) for the host
     (sections 24 and 42).
   - Conditional, optional settings: `CSPM_REPORT_RETENTION_DAYS`
     (section 24), `CSPM_SCAN_TIMEOUT_SECONDS` (section 27),
     `TOOLS_ALLOWED_INTERNAL_TARGETS` if you scan an internal lab
     (section 29), `GUARDIAN_SCHEDULE_*` set to `off` to hold back the
     first runs (section 13), `GUARDIAN_SCHEDULE_USER_SCHEDULES`
     (section 15), `GUARDIAN_ALERT_RENOTIFY_INTERVAL` (section 14),
     `GUARDIAN_BASE_URL` (section 13), `RESPONDER_WILDBOX_API_URL` and its
     siblings (section 31), `IDENTITY_REDIS_URL` (section 2),
     `GATEWAY_INTERNAL_URL` (section 3). `ANALYZE_RATE_LIMIT` and
     `ANALYZE_TEAM_RATE_LIMIT` need a Compose override, not `.env`
     (section 43).
   - Keep `API_KEY` and `GATEWAY_INTERNAL_SECRET` (sections 11 and 31).
   - Remove if present, since nothing reads them: `INTERNAL_API_KEY`,
     `GUARDIAN_API_KEY`, `API_KEY_HEADER`, `ENCRYPTION_KEY`,
     `NEXT_PUBLIC_API_BASE_URL`, the `NEXT_PUBLIC_*_API_URL` variables and
     the `REDIS_URL` line meant for identity (sections 2, 11, 16 and 30).
     `DEFAULT_NOTIFICATION_RECIPIENTS` has no effect either (section 14).
   - `SENSOR_DATA_LAKE_API_KEY` comes later, in step 12: the key is
     created in the upgraded identity.

   Then check the result:

   ```bash
   make validate-secrets
   docker compose config -q
   ```

6. **Prepare guardian and the responder (conditional, with the old stack
   up).**
   - If you wrote your own responder playbooks: they must use only known
     keys (section 8), no removed action (section 31), and test for
     `logged` instead of `sent` (section 37).
   - If you defined guardian alert rules, report schedules, discovery rules
     or scan schedules: check the rules' `data_source` (section 14), pause
     the schedules and rules you do not want run at once, and delete or
     disable scan schedules (section 15).
   - If you added a periodic task for `generate_vulnerability_reports` in
     the Django admin: delete it (section 11).

7. **Drop guardian's queued backlog (conditional: if the tasks queued
   since guardian was deployed should not run).** Run it with the old
   stack still up (section 12):

   ```bash
   docker compose exec guardian celery -A guardian purge -f
   ```

8. **Rebuild every image (required).** `docker compose up -d` does not
   rebuild an image that exists, and the dashboard compiles the
   `NEXT_PUBLIC_*` values of step 5 into its image (sections 1 and 16):

   ```bash
   docker compose build
   ```

9. **Start the new stack (required).** One `up -d` recreates identity and
   the gateway together, which sections 3, 18, 22, 25, 26, 33 and 40 need,
   and starts the new `guardian-worker`, `guardian-beat` and `cspm-worker`
   (sections 12, 13 and 27). The migrations run at start:
   - identity: `alembic upgrade head` in `scripts/init.sh`, revisions
     `a6b7c8d9e0f1` and `b7c8d9e0f1a2` (sections 18 and 22);
   - data: `alembic upgrade head` when the data API starts, revision
     `0005_telemetry_team` (section 34), unless
     `RUN_MIGRATIONS_ON_STARTUP=false` (below);
   - guardian: `python manage.py migrate` in the image's entrypoint, run by
     `guardian`, `guardian-worker` and `guardian-beat`:
     `django_celery_beat.0019`, `reporting.0002_alert_rule_state`,
     `core.0002_remove_apikey`, `core.0003_team_membership_and_tasks` and
     the `team_id` migrations (sections 7, 14, 30 and 39).

   No other service has a schema to migrate.

   ```bash
   docker compose up -d
   docker compose logs -f identity data guardian
   ```

   Conditional, with `RUN_MIGRATIONS_ON_STARTUP=false`: migrate the data
   database before the data API starts (section 34), then start the rest:

   ```bash
   docker compose run --rm --no-deps data alembic upgrade head
   docker compose up -d
   ```

10. **Give guardian's existing rows to their team (required when guardian
    holds data).** Until then no team sees them (section 39):

    ```bash
    docker compose exec guardian python manage.py assign_guardian_team --list
    docker compose exec guardian python manage.py assign_guardian_team --team <team UUID> --dry-run
    docker compose exec guardian python manage.py assign_guardian_team --team <team UUID>
    ```

    Section 39 shows how to find the team's UUID, and what a deployment
    with several teams does instead.

11. **Give legacy sensor telemetry to a team (conditional: the data
    database holds telemetry rows with no team).** Count them, then assign
    or delete them, with the SQL of section 34.

12. **Reconnect the sensor (conditional: you run it).** Create a
    `data:ingest` key for it, set `SENSOR_DATA_LAKE_API_KEY` in `.env` and
    recreate it (section 35):

    ```bash
    docker compose up -d sensor
    ```

13. **Verify (required).** Follow
    [Verifying the upgrade](#verifying-the-upgrade). In particular, check
    that an API key issued before the upgrade still works (section 38) and
    that logout answers 2xx (section 3).

14. **Tell API clients what changed (required when anything but the
    dashboard calls the API).**
    - Removed, now 404: identity's team `invite`, the gateway's
      `/api/tools/` alias and `/tools/` pages, cspm's executive summary and
      remediation roadmap (section 11).
    - Removed or changed fields: cspm's dashboard and compliance summaries
      and identity's estimated request counts (section 11),
      `users.recent_logins` (section 21); `trends_change` can be null
      (section 20), and the threat-intel figures are per team
      (section 45).
    - Direct calls to a service with `X-API-Key` stop working: go through
      the gateway with a session token or an identity API key (sections 11
      and 30). The gateway no longer takes the `auth_token` cookie in place
      of an `Authorization` header (section 11).
    - New 503 answers, safe to repeat: logout, password change, key
      revocation, account deactivation or deletion, member removal
      (sections 3, 18, 25 and 26).
    - New 403 answers: `PASSWORD_CHANGE_REQUIRED` (section 22),
      `team_membership_ended` (section 26), `GATEWAY_AUTH_REQUIRED` on a
      direct guardian request (section 30), `insufficient_scope` for a
      `data:ingest` key (section 35), the admin metrics without a
      superuser (section 40).
    - New 404 answers: another user's tools task or agents task
      (sections 19 and 43), another member's key on the self-service
      API-key routes (section 41).
    - New 400 answers: a `password` on `PATCH /auth/users/me` and an email
      change without `current_password` (sections 17 and 18), a password
      outside the policy (section 23), GCP and Azure scans (section 28),
      internal scan targets and URLs (sections 29 and 44).
    - New 429 answers: failed logins and wrong current passwords lock the
      account for 15 minutes (sections 5 and 18); agents analysis requests
      are limited per user (section 43).
    - Sessions: tokens issued before the upgrade cannot be logged out
      (section 4); a password change replaces the caller's token, and
      password-reset tokens issued before the upgrade no longer work
      (section 18).
    - API keys: the self-service routes list and revoke the caller's own
      keys only; owners and admins use the team routes (section 41).
    - Changed routes and bodies: tools tasks at `/api/v1/tasks`
      (section 19), error bodies with `error.details` (section 23),
      responder cancel and notification results (sections 36 and 37),
      playbook actions (section 31), agents routes that accept a session
      token (section 33).

### 1. Rebuild every image (required)

The images are built from the repository, and `docker compose up -d` does not
rebuild an image that already exists. Without a rebuild the stack keeps
running 0.10.0 code. This release changes, among others, the dashboard image
(Next.js 16, React 19, node 24 LTS), the gateway base image and the Python
locks of every service.

```bash
make init-api-key-hash    # first: see section 38, or existing API keys stop working
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
make start-prod
```

Use the same `-f` files you start the stack with. Steps 4, 8 and 9 of the
order of operations above place these commands among the others.

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
The best-effort flush of the whole cache that deactivating a user used to
send is gone (#593). Every change that disables a credential now goes
through this listener and waits for the gateway to confirm it, like logout:
a password change (section 18), revoking an API key, deactivating or
deleting an account (section 25) and removing a member from a team
(section 26). Without the confirmation the request answers 503 and changes
nothing.

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
adding to the flat `wildbox` network: only the gateway, the dashboard and the
sensor share `frontend` (the sensor since section 35), PostgreSQL and Redis sit on the internal `data` network with the
services that use them, and the dashboard can no longer reach them. The map
is at the top of the file.

- The `!override` tag it uses needs Docker Compose 2.24.4 or later; older
  versions refuse the file. `make start-prod` now calls `docker compose`.
- A service you added in your own overlay on the `wildbox` network no longer
  shares it with the production services; attach it to the network it needs.
- identity receives `CORS_ORIGINS` under the production overlay, like the
  other services, and now reads the comma-separated form (#531); it used to
  read a JSON list only and exited at start-up on that value. An empty
  value allows no cross-origin requests, which is fine when browsers reach
  identity through the gateway on the dashboard's own origin. Check that
  the value in `.env` lists exactly the origins you serve.
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
- identity's `POST /api/v1/admin/teams/{team_id}/invite`
  (`/api/v1/identity/admin/teams/{team_id}/invite` through the gateway) is
  removed (#570) and answers 404. It returned "Invitation sent successfully" without
  storing or sending anything, so a script that called it never invited
  anyone; drop the call.
- identity's admin analytics no longer report estimated request counts
  (#570): `summary.api_requests_today` is gone from
  `GET /api/v1/identity/analytics/admin/usage-summary`, and
  `api_usage.estimated_requests_today` and
  `api_usage.estimated_requests_week` from
  `GET /api/v1/identity/analytics/admin/system-stats` (identity's
  `/api/v1/analytics/admin/...` on its own port). They were API keys used
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
- The tools service's credential manager and `ENCRYPTION_KEY` are removed
  (#540): no service reads the variable, so remove it from `.env`. With
  them gone, `SECURITY_CONTROLS_ENABLED=true` in the tools service now
  loads its security layer; it used to fail on a missing import and switch
  the layer off.
- `make clean` no longer runs `docker system prune -f --volumes`, which
  deleted every unused volume and image on the host. It clears local
  caches only; reset the stack's data with `docker compose down -v` when
  you mean to.

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
  ever actually sent before; set `notification_config.recipients` on each
  rule for them to reach someone. The code falls back to a
  `DEFAULT_NOTIFICATION_RECIPIENTS` setting, but guardian's settings do not
  define it and Compose does not pass it, so that fallback is empty: setting
  the variable in `.env` has no effect.
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
  are ready. A schedule without recipients e-mails nobody (the
  `DEFAULT_NOTIFICATION_RECIPIENTS` fallback is empty, as in section 14).
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

`GET /api/v1/data/dashboard/threat-intel` (the data service's
`/api/v1/dashboard/threat-intel`) answers `trends_change: null`
when the previous 24 hours had no indicators; it used to report 100.0 (or
0.0 when both periods were empty). A client that reads the field must
accept null. Every other value is unchanged.

### 21. `users.recent_logins` is gone from identity's system statistics

`GET /api/v1/identity/analytics/admin/system-stats` (identity's
`/api/v1/analytics/admin/system-stats`) no longer returns
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
  change-password (`POST /api/v1/identity/admin/me/change-password` or
  `PUT /api/v1/identity/admin/me/password`) and logout, and the gateway answers 403
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
must not contain the account's email address or, when it has at least 4
characters, the part before the `@`,
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

### 32. `RATE_LIMIT_PER_HOUR` must be a whole number, or the gateway does not start

The gateway reads the per-team budget from `RATE_LIMIT_PER_HOUR` (#627). A
value that was not a number used to become the default, 10000, without a
word; the gateway now refuses to start with it and logs
`RATE_LIMIT_PER_HOUR must be a whole number ...`. Before you upgrade, check
the line in `.env`: it must be a whole number from 1 to 1000000000, or be
left out for the default. The compose file passes 10000 when it is empty.

### 33. The agents routes accept a session token and count against the team's rate limit

`/api/v1/agents/*` now authenticates like every other gateway route (#630).
Rebuild the gateway (section 1 does).

- **A session token works.** The routes accepted only `X-API-Key` and
  answered a JWT with 401 `NO_API_KEY`; both credentials work now. A
  client that relied on the `NO_API_KEY` or `INVALID_API_KEY` codes gets
  the gateway's usual 401 `authentication_required` or `invalid_token`.
- **The per-team rate limit applies** to the agents routes too, as do
  the revocation of sessions and API keys and the must-change-password
  refusal.
- **`/api/v1/agents/stats` answers** with the service's statistics,
  authenticated, where it answered 404.

### 34. Sensor telemetry belongs to a team (data schema change)

The data service stored telemetry events and sensor records without a
team, and served every team's to any caller (#641). The data service
adds `team_id` to `telemetry_events` and `sensor_metadata` (alembic
revision `0005_telemetry_team`). The data API applies it at start,
unless `RUN_MIGRATIONS_ON_STARTUP=false`.

- **A schema you migrate yourself** needs `alembic upgrade head` from
  `open-security-data` before the new data API starts, with
  `DATABASE_URL` set to the data database. The revision adds a nullable
  `team_id` column and an index to both tables. It replaces the unique
  index on `sensor_metadata.sensor_id` with a plain index and a unique
  constraint `uq_sensor_metadata_team_sensor` on `(team_id, sensor_id)`,
  so two teams can use the same sensor ID. It rewrites no rows.
- **Telemetry is always private to a team.** `POST /api/v1/ingest`
  stores events and the sensor record under the caller's team, the one
  the gateway forwards, and ignores any team the batch names. The
  events, sensors, sensor-by-ID and statistics routes return the
  caller's team's rows only: another team's sensor ID answers 404.
  Unlike indicators, telemetry has no global rows.
- **Existing rows are hidden from every team.** Rows written before the
  upgrade keep `team_id` NULL, and no API call returns or updates them.
  A sensor that reports again after the upgrade gets a new record in
  its team. To count the legacy rows, in the data database (`data` in
  the default stack):

  ```bash
  docker compose exec postgres psql -U postgres -d data -c \
    "SELECT 'events', count(*) FROM telemetry_events WHERE team_id IS NULL
     UNION ALL
     SELECT 'sensors', count(*) FROM sensor_metadata WHERE team_id IS NULL"
  ```

- **To give the legacy rows to a team**, take the team's ID from
  identity (`SELECT id, name FROM teams` in the `identity` database)
  and run the following. It is one transaction, and it merges a legacy
  sensor record into the team's record of the same sensor ID, if the
  sensor has already reported since the upgrade. Add
  `AND sensor_id = '...'` to every statement to move one sensor only.

  ```bash
  docker compose exec -T postgres psql -U postgres -d data \
    -v ON_ERROR_STOP=1 -v team='<team-uuid>' <<'SQL'
  BEGIN;
  UPDATE telemetry_events SET team_id = :'team' WHERE team_id IS NULL;
  UPDATE sensor_metadata AS t
     SET total_events = t.total_events + l.total_events,
         first_seen = LEAST(t.first_seen, l.first_seen)
    FROM sensor_metadata AS l
   WHERE l.team_id IS NULL AND t.team_id = :'team'
     AND t.sensor_id = l.sensor_id;
  DELETE FROM sensor_metadata AS l
   WHERE l.team_id IS NULL
     AND EXISTS (SELECT 1 FROM sensor_metadata AS t
                  WHERE t.team_id = :'team' AND t.sensor_id = l.sensor_id);
  UPDATE sensor_metadata SET team_id = :'team' WHERE team_id IS NULL;
  COMMIT;
  SQL
  ```

  To drop them instead: `DELETE FROM telemetry_events WHERE team_id IS
  NULL;` and `DELETE FROM sensor_metadata WHERE team_id IS NULL;`.
- **Downgrading** to `0004_trgm` restores the global unique index on
  `sensor_id`, and fails while two teams share a sensor ID. Delete or
  rename one of the records first.

### 35. Sensors send telemetry through the gateway, with an identity API key

No sensor telemetry was ever stored: the sensor posted to the data
service's `/api/v1/ingest` with a bearer key the data service never
accepted (#628). The sensor now sends to the gateway,
`https://<gateway>/api/v1/data/ingest`, authenticated with an identity
personal API key, and the data service stores the events under that key's
team. Rebuild the sensor, the data service, identity, the gateway and the
dashboard (section 1 does); the data service applies alembic revision
`0005_telemetry_team` at start.

- **Give each sensor a key.** As a team owner or admin, add a member for
  the sensor (Settings > Team > Add member), sign in as it once to change
  its password, and create a personal API key with the new
  **Telemetry Ingest** (`data:ingest`) scope only (Settings > API keys).
  Set it as `SENSOR_DATA_LAKE_API_KEY`. Its telemetry belongs to that
  member's team; revoking the key or removing the member stops the
  sensor at its next batch.
- **The sensor in `docker-compose.yml`** is already pointed at
  `https://open-security-gateway` and trusts the certificate the gateway
  publishes into the new `gateway_cert` volume. Add
  `SENSOR_DATA_LAKE_API_KEY=wsk_...` to `.env` and
  `docker compose up -d sensor`. Without a key it starts and logs
  `Telemetry forwarding is disabled`.
- **Sensors elsewhere** need three settings: `data_lake.endpoint` (or
  `SENSOR_DATA_LAKE_ENDPOINT`) set to the gateway's HTTPS URL,
  `data_lake.api_key` (or `SENSOR_DATA_LAKE_API_KEY`) set to the key, and,
  when no public CA signed the gateway's certificate,
  `data_lake.ca_bundle` (or `SENSOR_DATA_LAKE_CA_BUNDLE`) set to a PEM
  file holding it. A sensor still configured with an `http://` endpoint
  or the data service's `/api/v1/ingest` URL, or with a key that does not
  begin with `wsk_`, now stops at start-up with a message naming the
  setting. Check one with `python main.py --test-connection`.
- **Production overlay:** the sensor moves from the `backend` network to
  `frontend`. It reaches the gateway, and no longer the data service or
  any other backend service directly.
- **Telemetry is per team.** `GET /api/v1/data/telemetry/events`,
  `/telemetry/stats`, `/sensors` and `/sensors/{id}` show the caller's
  team's telemetry only. Rows written before the upgrade, which only a
  hand-made insert can have produced, have no team and are shown to no
  team.
- **API key scopes:** `data:ingest` is new. A key with `write` or
  `data:write` can still post to `/api/v1/data/ingest`; a `data:ingest`
  key gets 403 `insufficient_scope` everywhere else.

### 36. Cancelling a responder run stops it

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

### 37. The responder's notification action says it only logs

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

### 38. Seed `API_KEY_HASH_SECRET` from `JWT_SECRET_KEY` before upgrading (required)

identity keys stored API-key digests with `API_KEY_HASH_SECRET`. Compose
did not pass that variable to identity before this release, so on every
existing deployment the digests are keyed by `JWT_SECRET_KEY`, whatever
`.env` holds for `API_KEY_HASH_SECRET` (#648). This release passes it,
and the value `make generate-secrets` wrote there is a different random
one: started as is, identity would reject every API key issued so far.

Before you start the new images, while `.env` still has the
`JWT_SECRET_KEY` the running identity uses, copy that value into
`API_KEY_HASH_SECRET`. The command edits `.env` in place, backs it up
first (`.env.bak.<date>_<time>`) and prints neither value:

```bash
make init-api-key-hash
# same as: ./scripts/rotate_secrets.sh --secret API_KEY_HASH_SECRET --init
```

Then rebuild and start as usual (section 1). Existing API keys keep
working, and `JWT_SECRET_KEY` can from now on be rotated on its own.

- **Run it once.** It does nothing when the two values already match. Do
  not run it after a later JWT rotation: by then the digests are keyed by
  the old JWT key, which `API_KEY_HASH_SECRET` keeps.
- **If identity already runs this release unseeded**, existing API keys
  answer 401. Run the command, then `docker compose up -d identity` (with
  your `-f` files): the old keys work again, but keys created in between
  must be created again. Do not rotate `JWT_SECRET_KEY` before this, or
  the old keys cannot be recovered.
- **identity refuses a weak or missing value.** In every environment,
  identity exits at start-up naming `API_KEY_HASH_SECRET` when the value
  is shorter than 32 characters, a placeholder from `.env.example` or has
  fewer than 10 distinct characters. With `ENVIRONMENT=production` it also
  exits when the value is unset or empty; elsewhere it then falls back to
  `JWT_SECRET_KEY` with a warning. `docker compose config` fails without
  it in any environment, and `make validate-secrets` now requires it.
- **The JWT rotation guard checks identity, not only `.env`.**
  `./scripts/rotate_secrets.sh --secret JWT_SECRET_KEY` refuses unless
  `.env` sets `API_KEY_HASH_SECRET`, `docker` is available,
  `docker compose config` passes the variable to identity and, when an
  identity container is running, that container has it (with identity
  stopped, it checks the configuration only). If you start the stack with
  an overlay, set `COMPOSE_FILE`, for example
  `COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml`.
- **A fresh install needs nothing:** `make generate-secrets` draws the
  two values independently.

### 39. guardian keeps each team to its own data; assign the existing rows (required)

guardian stored no team: every team read and wrote every other team's
assets, vulnerabilities, scanners, integrations, remediation, compliance
and reports (#642). Each request now acts on the caller's team's rows only.

- **Migrations, applied at start.** `assets.0002_team_id`,
  `compliance.0002_team_id`, `integrations.0002_team_id`,
  `remediation.0002_team_id`, `reporting.0003_team_id`,
  `scanners.0002_team_id`, `vulnerabilities.0002_team_id` add a nullable,
  indexed `team_id` column to the models that store their team;
  `core.0003_team_membership_and_tasks` adds two tables. The migrations
  change no rows.
- **Existing rows get no team, and no team sees them.** guardian cannot
  tell which team wrote a row, and making the rows visible to every team
  would keep the disclosure this change closes. After the upgrade the
  assets, vulnerabilities, reports and the rest are missing from every
  team's view until you assign them. Compliance frameworks, their
  controls and vulnerability templates without a team are the exception:
  they become shared reference data, read by every team and changed by
  none.
- **Assign them to the team that owns them.** Find the team's UUID in
  identity's database (use your `POSTGRES_USER`), by the owner's e-mail
  address:

  ```bash
  docker compose exec postgres psql -U postgres -d identity -c \
    "SELECT t.id, t.name FROM teams t JOIN users u ON u.id = t.owner_id WHERE u.email = 'owner@example.com'"
  ```

  then:

  ```bash
  docker compose exec guardian python manage.py assign_guardian_team --list
  docker compose exec guardian python manage.py assign_guardian_team --team <team UUID> --dry-run
  docker compose exec guardian python manage.py assign_guardian_team --team <team UUID>
  ```

  It gives every row without a team to that team in one transaction; the
  rows that hang off another row (a vulnerability off its asset, a scan
  off its scanner) follow it. Add `--include-shared` to give that team
  the frameworks and vulnerability templates too, if they are its own
  rather than reference data. A single-team deployment runs the command
  once with its only team. A deployment with several teams has to split
  the rows by hand (`team_id` on each table) before or instead of the
  command, since they were shared until now.
- **Until then, background work stays with the unassigned rows.** A
  discovery rule, a report schedule or an alert rule without a team keeps
  running against the other rows without a team, and never against a
  team's.
- **Names are unique per team.** Environments, business functions, asset
  groups, discovery rules, frameworks and vulnerability templates were
  unique by name (CVE id for a template) across guardian, and remediation
  tickets by system and ticket id. They are now unique within a team.
- **Users are named within the team.** Assigning a vulnerability, a
  remediation or a step to a user, or sharing a dashboard, accepts users
  who have made a request as a member of the team since the upgrade.
- **Reports are written per team**, under `MEDIA_ROOT/reports/<team id>/`.
  Reports generated before stay where they are and can still be
  downloaded by the team their template is assigned to.
- **Commands that create rows need a team.** `import_vulnerabilities` and
  `generate_compliance_report` take a required `--team-id`.

### 40. identity's admin metrics need a superuser's token

`GET /api/v1/identity/admin/metrics` (identity's
`GET /api/v1/admin/metrics`) answered anyone, because it trusted the
gateway secret and the gateway sent that secret on every request (#664).
Rebuild identity and the gateway (section 1 does).

- **A script that read the counts** must send a platform superuser's
  bearer token. Without a token it gets 401; with a non-superuser's token,
  403. The `X-Gateway-Secret` header no longer opens the route, through
  the gateway or on identity's port. The counts are now real: they were
  always zero, with `"error": "unavailable"`.
- **The gateway sends `X-Gateway-Secret` only on routes it authenticates.**
  A custom service behind a location that does not run
  `auth_handler.authenticate()` but checks the header will now refuse
  every request. Authenticate that location, as the other service routes
  do.

### 41. The self-service API-key routes list and revoke the caller's own keys

`GET` and `DELETE /api/v1/identity/api-keys[/{key_prefix}]` acted on every
key of the caller's team, so a member could revoke the owner's key (#664).
They now act on the keys the caller created. Rebuild identity (section 1
does).

- **The dashboard's API keys page** lists your own keys only. A team owner
  or admin who managed other members' keys there uses the team routes:
  `GET /api/v1/identity/teams/{team_id}/api-keys` to list them and
  `DELETE /api/v1/identity/teams/{team_id}/api-keys/{key_prefix}` to
  revoke one.
- **A script that revoked another member's key** through
  `/api/v1/identity/api-keys/{key_prefix}` now gets 404, and the key keeps
  working. Use the team route above with an owner's or admin's token.

### 42. Production Redis refuses writes when full instead of evicting

`docker-compose.prod.yml` ran Redis with `--maxmemory-policy allkeys-lru`
at 512 MB, so under memory pressure Redis deleted revoked-token entries,
lockout counters, queued tasks and results (#530). The overlay now keeps
the base file's command: `noeviction`, with `REDIS_MAXMEMORY` (default
`1gb`), and a container memory limit of `REDIS_MEMORY_LIMIT` (default
`2g`).

- **Check the host's memory.** Redis may now use up to `REDIS_MAXMEMORY`
  for data and the container up to `REDIS_MEMORY_LIMIT`. Keep the limit at
  least twice `REDIS_MAXMEMORY`: an append-only-file rewrite can double the
  resident memory, and the kernel would kill Redis first.
- **A full Redis refuses writes for every service** instead of dropping
  keys. Watch the memory in use, and size it for cspm's stored reports
  (section 24).
- Check the rendered configuration before you start, and the running Redis
  after:

  ```bash
  python3 scripts/check_redis_config.py config
  python3 scripts/check_redis_config.py runtime
  ```

### 43. The agents service limits analysis requests per user and hides other users' tasks

`POST /api/v1/agents/analyze` was limited by client address, which is the
gateway's for every request, so the whole platform shared one budget of
five analysis requests a minute (#651). Reading or cancelling a task also
trusted a missing owner record (#650). Rebuild the agents service (section 1 does).

- **Each user has their own budget**, `5/minute` by default. A user over
  it gets 429, and the body names the user or the team limit.
- **Two new settings, optional.** `ANALYZE_RATE_LIMIT` (per user, in the
  `limits` notation, for example `5/minute;50/day`) and
  `ANALYZE_TEAM_RATE_LIMIT` (a ceiling for a whole team, empty for none).
  `docker-compose.yml` does not pass them: add them to the agents
  service's `environment` in an override file of your own. A value that
  cannot be parsed, or an empty `ANALYZE_RATE_LIMIT`, stops the service at
  start-up.
- **Another user's task answers 404.** `GET` and `DELETE
  /api/v1/agents/analyze/{task_id}` answer 404 `Task not found` for a task
  of another user, or one whose owner record is gone; `GET` used to answer
  403 for another user's task. A client that told the two apart must
  treat both as 404.

### 44. The tools service checks every URL a tool fetches

The tools service validated target URLs with free-text patterns and
checked only top-level URL fields (#561, #610). It now parses every URL in
a tool's input, nested ones and URL-typed fields included, and checks
every connection a tool makes, redirects included. Rebuild the tools
service and its worker (section 1 does).

- **Accepted now:** `http://` targets, query strings, `&` in a path and
  host names such as `shop.example.com`, which the patterns refused.
- **Refused with 400 now:** user info (`user:pass@host`), whitespace or
  control characters, a port outside 1 to 65535, numeric host spellings
  (`2130706433`, `0x7f000001`, `127.1`), `localhost` and `*.localhost`,
  any address that is not globally routable (`100.64.0.0/10` included),
  a scheme other than `http` or `https` in a URL field, and input nested
  deeper than 16 levels. `TOOLS_ALLOWED_INTERNAL_TARGETS` (section 29)
  does not lift these checks for URLs.
- **Redirects** are followed to public hosts only, at most 5 hops; a
  redirect to an internal address fails the run. `whois_lookup` follows a
  referral only to a public host name.
- **Workflow steps** of security_automation_orchestrator are validated by
  the step's tool input model and checked by the same guard, and a tool
  that acts on behalf of a caller is refused as a step.

### 45. The threat-intel dashboard figures cover the caller's team

`GET /api/v1/data/dashboard/threat-intel` counted the sources and
indicators of every team (#570). Its figures now cover the caller's team
and the global feeds, as `/api/v1/data/indicators/search` does, so they
can be lower than before. `last_updated` is the end of the last completed
collection run of a visible feed, and null when there is none; it used to
fall back to an hour ago. A client that reads it must accept null.

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
`X-Gateway-Secret` in 0.10.0 -- are at `GET /api/v1/admin/metrics`. From
0.11.0 that route takes a platform superuser's bearer token instead (see
section 40 of "Upgrading to 0.11.0").

## Verifying the upgrade

After any upgrade, with `COMPOSE_FILE` naming the files you start the stack
with:

```bash
make validate-secrets     # every required secret present, .env is 0600
docker compose config -q  # compose files resolve
docker compose ps         # every service up, and healthy where it has a check
make health
make restore-drill        # backup -> restore into scratch databases -> exact row counts
```

`make restore-drill`, like `make backup`, needs only Docker on the host. It
runs `pg_dump`, `pg_restore` and `psql` inside the stack's `postgres`
container with `docker compose exec`, so no database port has to be published
and no `POSTGRES_HOST` has to resolve. It restores into `<db>_restore_drill`,
compares every table's row count with the source as the backup's own snapshot
saw it, and drops the scratch databases; the live databases are only read.
For a database the stack does not run, set `BACKUP_MODE=host` (or
`POSTGRES_HOST`) and run it from a machine that reaches the database.

With the production overlay, also check the network segmentation and Redis:

```bash
python3 scripts/check_network_segmentation.py config
python3 scripts/check_network_segmentation.py runtime
python3 scripts/check_redis_config.py runtime
```

After the upgrade to 0.11.0, also check:

- **An API key issued before the upgrade still works** (section 38). Through
  the gateway, a request with it answers 200, not 401:

  ```bash
  curl -sS -o /dev/null -w '%{http_code}\n' \
    -H "X-API-Key: <existing key>" https://<host>/api/v1/guardian/assets/assets/
  ```

- **Logging out answers 2xx** and the token is refused afterwards
  (sections 3 and 18); a 503 means identity cannot reach the gateway on
  port 8081.
- **guardian's data is visible** to the team you assigned it to
  (section 39), and `docker compose logs guardian-beat guardian-worker`
  shows the scheduled tasks running (sections 12 and 13).
- **`cspm-worker` takes scans**: cspm's `/health` reports `healthy`
  (section 27).

After the upgrade to 0.12.0, also check:

- **The gateway started with its limits**: `docker compose logs gateway`
  has a line `Per-address request limits: global 100 r/s, auth 5 r/s,
  static assets 500 r/s` (section 21 of "Upgrading to 0.12.0").
- **guardian applied its migrations and deleted the stored credentials**:
  `docker compose exec guardian python manage.py showmigrations --plan`
  lists none unapplied, and `docker compose logs guardian | grep "guardian
  stored"` says how many records held one (sections 5 and 6).
- **A scan of your own network answers as you set it**: `400` naming
  `GUARDIAN_ALLOWED_INTERNAL_TARGETS` for a range you did not list, a
  `task_id` for one you did (section 20).
- **The data service has a source it can collect**:
  `docker compose exec data python manage.py sources list` shows "Feodo
  Tracker" enabled, and the others disabled with the reason (section 22).
- **The responder's log holds no Redis URL**:
  `docker compose logs responder | grep -c 'Redis URL'` prints `0`
  (section 23).
