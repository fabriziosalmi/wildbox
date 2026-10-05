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
4. Refuses `POSTGRES_PASSWORD` unless the `postgres` service is running (see
   [POSTGRES_PASSWORD](#postgres_password)).
5. Copies the file to `.env.bak.<timestamp>` with mode `0600`. The copy
   holds the **old** secret: delete it once the rotation is verified.
6. Generates the new value with the generator `make generate-secrets` uses
   for that secret, so it has the shape the services and
   `make validate-secrets` expect (`API_KEY`, for example, is
   `wsk_prod.<64 hex characters>`). It replaces the `NAME=` line or appends
   one, and leaves `.env` with mode `0600`. With
   `--secret API_KEY_HASH_SECRET --init` it copies the current
   `JWT_SECRET_KEY` value instead of generating one.
7. Prints the next step: which services receive the secret, read from
   `docker compose config`, and the command that recreates them. It does not
   restart anything.

Except for `POSTGRES_PASSWORD`, the script changes `.env` only. Running
containers keep the old value until they are recreated, with the command the
script prints, for example:

```bash
docker compose up -d --no-deps api tools-worker tools-flower
make health
```

Recreate with the same compose files you start the stack with (for example
the production overlay), so the services come back with their usual
configuration. If the script cannot read the compose configuration it prints
`docker compose up -d` instead, which recreates every container whose
configuration changed.

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

This password lives in two places. PostgreSQL reads `POSTGRES_PASSWORD` only
when it initializes an empty data directory; on an existing deployment the
password is stored in the server. The services do not read the variable at
all: they connect with `DATABASE_URL`, `DATA_DATABASE_URL`,
`GUARDIAN_DATABASE_URL` and `RESPONDER_DATABASE_URL`, which embed it.

The script changes both places or neither, and needs the stack running:

```bash
./scripts/rotate_secrets.sh --secret POSTGRES_PASSWORD
```

1. It refuses, changing nothing, if Docker is missing, if the `postgres`
   service is not running in the Compose project (`COMPOSE_FILE`,
   `COMPOSE_PROJECT_NAME`), or if the role named by `POSTGRES_USER` does not
   exist in the server.
2. It rewrites `POSTGRES_PASSWORD` and the password inside every PostgreSQL
   connection string in `.env` that points at the stack's `postgres` service
   (host `postgres` or `wildbox-postgres`) with that user. Nothing else in
   the connection strings changes. Connection strings for another host or
   user are left alone and listed, so you can update them by hand.
3. It sets the new password in the running server. The statement carries a
   SCRAM-SHA-256 verifier computed by the script and is sent to `psql` over
   standard input, so the password is in no command line and in no statement
   the server could log.
4. It asks the server, over TCP, whether it accepts the new password.
5. If step 3 or 4 fails, it restores `.env` from the backup and puts the
   server's previous password back, and says so. If the server cannot be
   reached to do that, it says `INCONSISTENT`, exits with status 3, and
   prints the command that sets the password by hand.

Then recreate the services it names, for example:

```bash
docker compose up -d --no-deps identity data data-scheduler guardian guardian-worker guardian-beat responder
```

Until then they keep the connections they already have and fail to open new
ones. The `postgres` container itself keeps running. If you run the `backup`
profile, recreate that container too.

### NEXTAUTH_SECRET

Passed to the dashboard container, but the dashboard source does not read it,
so rotating it has no visible effect, and the script says so.

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
