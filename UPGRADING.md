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
gateway's port 8081. A failed purge is logged by identity; the revoked token
then stays accepted from the gateway's cache for up to `AUTH_CACHE_TTL`
(300 seconds).

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

No `celery beat` is added: guardian defines no periodic schedule.

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
