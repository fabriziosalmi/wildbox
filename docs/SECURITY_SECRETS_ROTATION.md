# Secrets Rotation

How to replace the secrets a Wildbox deployment keeps in `.env`, with the
tool the repository provides, `scripts/rotate_secrets.sh`, and what each
rotation costs. Every command below works on your own `.env`; none of them
prints a secret, and neither should anything you add to this procedure.

## Where the secrets live

`make generate-secrets` (`scripts/generate_secrets.py`) writes `.env` with
random values and owner-only permissions (`0600`). `docker-compose.yml` reads
them from there and passes each one to the containers that need it.
`make validate-secrets` checks the file.

## The rotation tool

List the secrets the tool can rotate, with the cost of rotating each one:

```bash
make rotate-secrets          # runs ./scripts/rotate_secrets.sh --list
```

Rotate one secret:

```bash
./scripts/rotate_secrets.sh --secret GATEWAY_INTERNAL_SECRET
```

What the script does:

1. Accepts only these names: `GATEWAY_INTERNAL_SECRET`, `JWT_SECRET_KEY`,
   `API_KEY_HASH_SECRET`, `API_KEY`, `CSPM_CREDENTIAL_KEY`, `REDIS_PASSWORD`,
   `POSTGRES_PASSWORD`, `NEXTAUTH_SECRET`. Any other name exits with an error.
2. Works on `.env` in the repository root, or on the file named by the
   `ENV_FILE` environment variable, and exits if the file does not exist.
3. Refuses `JWT_SECRET_KEY` until identity receives a separate
   `API_KEY_HASH_SECRET`: `.env` sets it, `docker compose config` passes it
   to identity, and the running identity container, if any, has it (see
   [JWT_SECRET_KEY](#jwt_secret_key)). Set `COMPOSE_FILE` to the files you
   start the stack with, for example
   `COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml`.
4. Copies the file to `.env.bak.<timestamp>` with mode `0600`. The copy
   holds the **old** secret: delete it once the rotation is verified.
5. Generates the new value with Python's `secrets.token_urlsafe(48)` (64
   URL-safe characters), replaces the `NAME=` line or appends one, and sets
   `.env` back to `0600`. With `--secret API_KEY_HASH_SECRET --init` it copies
   the current `JWT_SECRET_KEY` value instead of generating one.
6. Prints the next step. It does not restart anything.

The script changes `.env` only. Running containers keep the old value until
they are recreated, which is what the script suggests:

```bash
docker compose up -d --force-recreate
make health
```

Recreate with the same compose files you start the stack with (for example
the production overlay), so the services come back with their usual
configuration.

## What each secret costs to rotate

### GATEWAY_INTERNAL_SECRET

The gateway sends it as `X-Gateway-Secret` on every proxied request, and each
backend compares it with its own environment value; identity also requires it
on `/internal/authorize`. A service still holding the old value refuses
requests from one holding the new value, so a rolling restart produces `403`
answers until every container has the same value. Recreate all services
together.

### JWT_SECRET_KEY

Identity signs session tokens with it. Rotating it ends every session: users
have to log in again.

API-key digests are keyed by `API_KEY_HASH_SECRET`, not by this key, so
rotating `JWT_SECRET_KEY` leaves API keys working. Identity falls back to
`JWT_SECRET_KEY` only when `API_KEY_HASH_SECRET` is unset, which the
production configuration does not allow (below); the script refuses
`JWT_SECRET_KEY` until it has checked that identity has a separate one.

### API_KEY_HASH_SECRET

The HMAC key for stored API-key digests. Rotating it to a new random value
makes every stored API key invalid: every user and team re-creates its keys.

It is required:

- both `docker-compose.yml` and `docker-compose.prod.yml` pass it to
  identity as `${API_KEY_HASH_SECRET:?...}`, so Compose refuses to start
  without it;
- identity refuses to start with a value shorter than 32 characters, a
  placeholder from `.env.example`, or one with fewer than 10 distinct
  characters, and, with `ENVIRONMENT=production`, without a value
  (`open-security-identity/app/config.py`).

`make generate-secrets` writes a random value for a new deployment. A
deployment that ran before this variable reached identity has its API-key
digests keyed by `JWT_SECRET_KEY`. Before upgrading it, seed the new variable
from that key once, so existing keys keep working, as
[UPGRADING.md, section 38](https://github.com/fabriziosalmi/wildbox/blob/main/UPGRADING.md#38-seed-api_key_hash_secret-from-jwt_secret_key-before-upgrading-required)
describes:

```bash
make init-api-key-hash
# same as: ./scripts/rotate_secrets.sh --secret API_KEY_HASH_SECRET --init
```

It copies `JWT_SECRET_KEY` into `API_KEY_HASH_SECRET` inside `.env`; from
then on the two can be rotated separately.

### API_KEY

A static key that the `api`, `tools-worker` and `tools-flower` containers
require at startup (`open-security-tools/app/config.py`). The tools service no
longer accepts it as a credential (#565), so rotating it affects no client.
Recreate those three containers.

### CSPM_CREDENTIAL_KEY

Encrypts cloud credentials before the CSPM service writes them to Redis for a
pending scan. Used by `cspm` and `cspm-worker`. Credentials of scans still
in flight can no longer be decrypted, so those scans fail and have to be
submitted again.

### REDIS_PASSWORD

The Redis container starts with `--requirepass ${REDIS_PASSWORD}`, and
`docker-compose.yml` builds every service's Redis and Celery URL from the
same variable. Recreate all services together. Redis keeps its data
(append-only file) across the restart.

If `.env` overrides any of those URLs (variables such as
`IDENTITY_REDIS_URL` or `AGENTS_REDIS_URL`), the password inside them is not
updated by the script: edit them by hand.

### POSTGRES_PASSWORD

PostgreSQL reads `POSTGRES_PASSWORD` only when it initializes an empty data
directory; on an existing deployment the password lives in the database. The
script changes only the `POSTGRES_PASSWORD=` line, while `DATABASE_URL`,
`DATA_DATABASE_URL` and `GUARDIAN_DATABASE_URL` embed the password and are
left as they are. A complete rotation is:

1. Run `./scripts/rotate_secrets.sh --secret POSTGRES_PASSWORD`.
2. While the old containers are still running, set the same value in the
   database. `\password` prompts for it, so it does not appear on the
   command line or in shell history (replace `postgres` with your
   `POSTGRES_USER` if you changed it):

   ```bash
   docker compose exec postgres psql -U postgres -c '\password postgres'
   ```

3. Replace the old password with the new one in the three connection strings
   above in `.env`.
4. Recreate all services.

### NEXTAUTH_SECRET

Passed to the dashboard container, but the dashboard source does not read it,
so rotating it has no visible effect.

## API keys issued to users and teams

Users and teams hold their own API keys, issued by identity. They are not in
`.env` and are rotated through the identity API, with a session token:

- user keys: `GET`, `POST /api/v1/identity/api-keys`, and
  `DELETE /api/v1/identity/api-keys/{key_prefix}`;
- team keys: the same under `/api/v1/identity/teams/{team_id}/api-keys`.

Create the replacement key, move clients to it, then delete the old one.

## If `.env` has leaked

Treat every value in it as known. Rotate `GATEWAY_INTERNAL_SECRET`,
`JWT_SECRET_KEY` (with its API-key consequence above), `REDIS_PASSWORD`,
`POSTGRES_PASSWORD` and `CSPM_CREDENTIAL_KEY`, and change the other
credentials the file holds, such as `INITIAL_ADMIN_PASSWORD` and third-party
API keys, with their providers. Then delete the `.env.bak.*` copies and
report the incident as described in [SECURITY.md](../SECURITY.md).

## After a rotation

1. `make health`.
2. Log in and call one authenticated route through the gateway.
3. Delete the `.env.bak.*` copies the script made.
