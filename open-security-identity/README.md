# Open Security Identity

The identity service owns users, teams, sessions and API keys for Wildbox. It
is a FastAPI application built on [fastapi-users](https://fastapi-users.github.io/fastapi-users/)
with PostgreSQL (SQLAlchemy, Alembic) and Redis.

It does three jobs:

- Accounts and sessions: registration, password login that issues a JWT,
  logout that revokes it, password changes and resets.
- Teams and API keys: every account belongs to at least one team; API keys
  belong to a user in a team and can be limited to scopes.
- Authorization for the gateway: `POST /internal/authorize` turns a Bearer
  token or an API key into the user, team and role the gateway forwards to
  the other services.

There are no plans, subscriptions or billing: every team has the same
features.

## Running

Identity runs as the `identity` service of the root `docker-compose.yml`
(container `open-security-identity`, port 8001, published on `127.0.0.1`
only). Clients reach it through the gateway; see
[the gateway README](../open-security-gateway/README.md).

```bash
# From the repository root
docker compose up -d --wait
```

The container entrypoint, `scripts/init.sh`:

1. Waits until PostgreSQL at `DATABASE_URL` accepts connections.
2. Runs `alembic upgrade head`.
3. If `CREATE_INITIAL_ADMIN` is `true` (the root Compose default), creates the
   account `INITIAL_ADMIN_EMAIL` with `INITIAL_ADMIN_PASSWORD` as a verified
   superuser, plus a team named `Default` that it owns. If the account
   exists, it only makes sure the account has a team. The script exits if
   the password is unset or does not meet the password policy, and it never
   prints the password.
4. Starts `uvicorn app.main:app` on port 8001, with `--reload` only when
   `ENVIRONMENT` is `development` (the root Compose default); any other
   value, or none, runs a single server process without the file watcher.

The `docker-compose.yml` and `Makefile` in this directory start a standalone
identity with its own PostgreSQL and Redis. They are not what the root stack
or CI runs.

## Endpoints

Paths are the service's own. The gateway column gives the path a client uses
on `https://<gateway>/`. Every `/api/v1/<x>` route is also reachable as
`/api/v1/identity/<x>`, which the gateway passes through with the
`Authorization` header; identity authenticates those requests itself.

### Authentication

| Method and path | Gateway path | Notes |
| --- | --- | --- |
| `POST /api/v1/auth/jwt/login` | `/auth/jwt/login` | Form fields `username` (email) and `password`; returns `{"access_token": "...", "token_type": "bearer"}` |
| `POST /api/v1/auth/jwt/logout` | `/auth/jwt/logout` | Revokes the presented token |
| `POST /api/v1/auth/logout` | `POST /auth/logout` | Revokes the presented Bearer token; idempotent |
| `POST /api/v1/auth/register` | `/auth/register` | Creates an account and a team it owns |
| `POST /api/v1/auth/forgot-password` | `/auth/forgot-password` | fastapi-users reset flow |
| `POST /api/v1/auth/reset-password` | `/auth/reset-password` | fastapi-users reset flow |
| `POST /api/v1/auth/request-verify-token`, `POST /api/v1/auth/verify` | `/api/v1/identity/auth/...` | fastapi-users verification flow |

Identity sends no email: the forgot-password and verification routes create
tokens, but nothing delivers them.

Login is limited per account: after `MAX_FAILED_LOGIN_ATTEMPTS` failures (5)
the account is locked for `ACCOUNT_LOCKOUT_MINUTES` (15) and login answers
`429` with `Retry-After`, even for the correct password. The counter is kept in
Redis.

Tokens are HS256 JWTs with `sub`, `aud` (`fastapi-users:auth`), `exp`, a random
`jti` and a fractional `iat`, valid for `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` (30).
Logout adds the `jti` to a Redis blacklist and tells the gateway, so the token
stops working at the gateway too.

### Users

| Method and path | Gateway path | Notes |
| --- | --- | --- |
| `GET /api/v1/users/me` | `/api/v1/identity/users/me` or `/auth/users/me` | The current account |
| `PATCH /api/v1/users/me` | as above | fastapi-users self update |
| `GET`, `PATCH`, `DELETE /api/v1/users/{id}` | as above | Superusers only |
| `POST /api/v1/admin/me/change-password` | `/api/v1/identity/admin/me/change-password` | Body `current_password`, `new_password`; returns a new `access_token` |
| `PUT /api/v1/admin/me/password` | `/api/v1/identity/admin/me/password` | Same as above |

The `/api/v1/admin/` router also holds user administration for superusers
(`/admin/users`, `/admin/users/{id}`, status, role and superuser changes),
the caller's own profile, activity and account deletion (`/admin/me/...`), and
team routes (below). `/api/v1/analytics/admin/*` serves usage statistics.

A password change ends every other session of the account: tokens issued
before it are refused by identity and by the gateway. API keys are not
affected.

### Teams

| Method and path | Who | Notes |
| --- | --- | --- |
| `GET /api/v1/admin/teams/{team_id}/members` | Team members, superusers | Lists members |
| `POST /api/v1/admin/teams/{team_id}/members` | Team owners and admins, superusers | Creates a new account in the team |
| `PUT /api/v1/admin/teams/{team_id}` | Team owners and admins, superusers | Renames the team |
| `DELETE /api/v1/admin/teams/{team_id}/members/{user_id}` | Team owners and admins, superusers | Removes a member; their API keys and sessions in that team stop working |

`POST /api/v1/admin/teams/{team_id}/members` takes `email`, `password` and
`role`. The role must rank below the caller's (an owner creates admins and
members, an admin creates members, nobody creates an owner). The new account's
only membership is this team. An email that is already registered answers
`409`; an existing account cannot be added this way, and no email is sent.

The new account carries `must_change_password`. Until its user changes the
password, its sessions may only call `GET /api/v1/users/me`,
`POST /api/v1/admin/me/change-password`, `PUT /api/v1/admin/me/password` and
the logout routes. Identity answers `403` with detail `PASSWORD_CHANGE_REQUIRED`
to every other authenticated route, and the gateway does the same for every
other service, because `/internal/authorize` reports
`password_change_required: true`.

### API keys

| Method and path | Who |
| --- | --- |
| `POST /api/v1/api-keys` | Any member |
| `GET /api/v1/api-keys`, `GET /api/v1/api-keys/{prefix}` | Any member, for their own keys |
| `DELETE /api/v1/api-keys/{prefix}` | Any member, for their own keys |
| `POST /api/v1/teams/{team_id}/api-keys` | Team owners and admins |
| `GET /api/v1/teams/{team_id}/api-keys`, `GET .../{prefix}` | Team members |
| `DELETE /api/v1/teams/{team_id}/api-keys/{prefix}` | Team owners and admins |

The `/api/v1/api-keys` routes act on the caller's primary team (the first team
they own, otherwise their first membership) and on the caller's own keys only:
another member's key answers `404`, as a key that does not exist does. Team
owners and admins list a team's keys with `GET /api/v1/teams/{team_id}/api-keys`
and revoke another member's key with
`DELETE /api/v1/teams/{team_id}/api-keys/{prefix}`. Through the gateway these
routes are under `/api/v1/identity/`, for example `/api/v1/identity/api-keys`.

A key looks like `wsk_<4 hex>.<64 hex>`. The full key is returned once, at
creation. Identity stores only an HMAC-SHA256 digest of it, keyed with
`API_KEY_HASH_SECRET` (see [Configuration](#configuration)). A key can
have an expiry (`expires_at`) and a list of `scopes` from this set: `read`,
`write`, `admin`, `tools:read`, `tools:execute`, `tools:admin`, `data:read`,
`data:write`, `data:delete`, `data:ingest`, `reports:read`, `reports:write`, `team:read`,
`team:manage`. A key created without scopes is stored as `["*"]`
(unrestricted). The gateway enforces the scopes.

Revoking a key, deactivating or deleting a user, and removing a member from a
team are sent to the gateway before they are committed. If the gateway does
not confirm, identity answers `503` and changes nothing.

Removing a member from a team and deleting an account are also sent to
guardian, after they are committed, so that guardian stops treating the user
as one of the team's users (`app/guardian_memberships.py`). This one does not
block: if guardian does not confirm, the change stands, identity logs an
error, and guardian drops the user by itself when their membership there
ages out. Deactivating an account sends guardian nothing.

### Internal

`POST /internal/authorize` is called by the gateway only. It requires the
`X-Gateway-Secret` header to match `GATEWAY_INTERNAL_SECRET` (`403` otherwise,
`503` if the secret is not configured). The gateway does not route `/internal/`
to identity.

`POST /internal/team-contacts` is called by guardian's worker only, when it
is about to e-mail somebody about a team's data: guardian mirrors identity's
users by id and keeps no address. It requires the
`X-Guardian-Contacts-Secret` header to match `GUARDIAN_CONTACTS_SECRET`
(`403` otherwise, `503` if the secret is not configured), a secret of its
own: `X-Gateway-Secret` does not open it, and identity does not start when
the two secrets have the same value. The body names one team and either the
users or the roles wanted, never both and never neither; a field it does not
know is refused (`422`):

```json
{"team_id": "<team UUID>", "roles": ["owner", "admin"]}
```

```json
{"team_id": "<team UUID>", "user_ids": ["<user UUID>"]}
```

It answers the members of that team, with an active account and an address,
that the request selects. A team that does not exist, a user who is not in
it and a deactivated account are an empty answer:

```json
{"team_id": "<team UUID>", "contacts": [{"user_id": "<user UUID>", "email": "owner@example.com", "role": "owner"}]}
```

An address is returned as identity holds it; identity does not verify
addresses. No address is written to identity's log.

Request body:

```json
{"token": "<JWT or API key>", "token_type": "bearer"}
```

`token_type` is `bearer` or `api_key`. The gateway also sends `request_path`,
`request_method`, `client_ip`, `user_agent` and `timestamp`; identity does not
use them.

Response (`AuthorizationResponse` in `app/schemas.py`):

| Field | Meaning |
| --- | --- |
| `is_authenticated` | `true` on success (failures are `401`) |
| `user_id`, `team_id` | The account and the team the request runs in |
| `role` | The account's role in that team: `owner`, `admin` or `member` |
| `permissions` | `tool:basic`, `tool:advanced`, `feed`, `cspm`; owners and admins also get `team:manage`, `keys:manage` |
| `scopes` | The API key's scopes; `null` for a session token |
| `password_change_required` | The account must change its initial password |
| `api_key_id` | The API key's id (API keys only), used by the gateway to revoke it |
| `credential_expires_at` | Epoch seconds when the token or key expires, or `null` |

For a session token, the team is the one named in the token's `team_id` claim
if present, otherwise the account's oldest membership. Revoked tokens, tokens
issued before the last password change, inactive users and expired or inactive
keys are refused with `401`.

### Health and metrics

| Path | Gateway path | Notes |
| --- | --- | --- |
| `GET /health` | `/api/v1/identity/health` (gateway auth) | Checks PostgreSQL and Redis |
| `GET /` | | Service name and version |
| `GET /metrics` | | Prometheus exposition, scraped by `monitoring/prometheus.yml` |
| `GET /api/v1/admin/metrics` | `/api/v1/identity/admin/metrics` | User, team and active-key counts; superusers only, authenticated by identity from the bearer token |

`/health` returns `status` (`healthy`, `degraded` or `unhealthy`), `service`,
`timestamp` and `checks` for `database` and `redis`. Redis being down makes the
service `degraded`: login keeps working, but revocation and lockout stop
working until it is back.

`/docs`, `/redoc` and `/openapi.json` are served only when `ENVIRONMENT` is
`development`.

## Security details

- Passwords are hashed with Argon2id (the fastapi-users `PasswordHelper`,
  backed by pwdlib). Existing bcrypt hashes still verify.
- Password policy (`app/password_policy.py`): 12 to 128 characters, must not
  contain the account's email or its local part, and must not be a common
  password (`app/data/common_passwords.txt`). It applies to registration,
  password changes, resets, team member creation and the initial admin.
- API keys are stored as HMAC-SHA256 digests, never in clear.
- Every logout, password change, key revocation and membership removal is
  pushed to the gateway's `/internal/gateway/purge-auth-cache` on its
  internal listener (`GATEWAY_INTERNAL_URL`), so cached decisions do not
  outlive it.

## Configuration

Settings come from `app/config.py` (`Settings`, read from the environment,
case-insensitive), plus a few variables read directly.

| Variable | Default | Notes |
| --- | --- | --- |
| `DATABASE_URL` | none, required | `postgresql+asyncpg://...` |
| `JWT_SECRET_KEY` | none, required | At least 32 characters; signs tokens and reset/verify tokens |
| `API_KEY_HASH_SECRET` | none; required in production | Keys the API-key HMAC, separately from `JWT_SECRET_KEY`. At least 32 characters and 10 distinct ones, and not an `.env.example` placeholder |
| `JWT_ALGORITHM` | `HS256` | |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Token lifetime |
| `REDIS_URL` | `redis://localhost:6379/0` | Token blacklist and login lockout |
| `MAX_FAILED_LOGIN_ATTEMPTS` | `5` | Login lockout threshold |
| `ACCOUNT_LOCKOUT_MINUTES` | `15` | Lockout duration |
| `GATEWAY_INTERNAL_SECRET` | unset | Required for `/internal/authorize` and for purges sent to the gateway |
| `GATEWAY_INTERNAL_URL` | `http://open-security-gateway:8081/internal/gateway/purge-auth-cache` | Gateway purge endpoint |
| `GUARDIAN_INTERNAL_URL` | `http://open-security-guardian:8013/internal/team-memberships/revoke/` | Where guardian is told that a membership ended. Empty: no guardian, nothing is sent |
| `GUARDIAN_CONTACTS_SECRET` | unset | What guardian's worker presents to `/internal/team-contacts`. At least 32 characters, and not the value of `GATEWAY_INTERNAL_SECRET`, `JWT_SECRET_KEY` or `API_KEY_HASH_SECRET`: identity does not start otherwise. Unset, the route answers `503` |
| `CORS_ORIGINS` | `http://localhost:3000`, `https://wildbox.local`, `https://dashboard.wildbox.local` | Comma-separated or JSON list |
| `CORS_ALLOW_CREDENTIALS`, `CORS_ALLOW_METHODS`, `CORS_ALLOW_HEADERS` | see `app/config.py` | |
| `ENVIRONMENT` | `development` | `production` disables the API docs |
| `DEBUG` | `false` | Used only by `python -m app.main` |
| `CREATE_INITIAL_ADMIN` | `false` in `init.sh`, `true` in the root Compose file | Create the initial admin at startup |
| `INITIAL_ADMIN_EMAIL` | `admin@wildbox.security` in `init.sh` | Initial admin account |
| `INITIAL_ADMIN_PASSWORD` | none | Must meet the password policy |

The root `docker-compose.yml` passes `ENVIRONMENT`, `DATABASE_URL`,
`REDIS_URL`, `JWT_SECRET_KEY`, `API_KEY_HASH_SECRET`,
`GATEWAY_INTERNAL_SECRET`, `GUARDIAN_INTERNAL_URL`,
`GUARDIAN_CONTACTS_SECRET`, `CREATE_INITIAL_ADMIN`, `INITIAL_ADMIN_EMAIL` and
`INITIAL_ADMIN_PASSWORD`.

`API_KEY_HASH_SECRET` keys API-key digests, so rotating `JWT_SECRET_KEY`
leaves API keys valid (#648):

- The root `docker-compose.yml` and `docker-compose.prod.yml` require it
  (`${API_KEY_HASH_SECRET:?}`); compose does not start without it.
- With `ENVIRONMENT=production`, identity refuses to start without it. In any
  environment it refuses a value that is too short, has too few distinct
  characters or is a placeholder from `.env.example` (`app/config.py`); an
  empty value counts as unset.
- Outside production an unset value falls back to `JWT_SECRET_KEY`, and
  identity logs a warning at startup.
- An existing deployment must seed it once from its current
  `JWT_SECRET_KEY`, so the digests stored so far keep matching, with
  `make init-api-key-hash` before upgrading; see
  [UPGRADING.md](../UPGRADING.md). A fresh install gets it from
  `make generate-secrets`.

## Database migrations

Alembic migrations are in `alembic/versions/` and run at every container start.
They create the schema (users, teams, memberships, API keys), add
`is_verified`, API-key scopes (with existing keys set to `["*"]`),
`tokens_valid_after` and `must_change_password`, and remove the former Stripe
columns and subscriptions table.

```bash
docker compose exec identity alembic upgrade head
docker compose exec identity alembic revision --autogenerate -m "describe the change"
```

## Tests

Unit tests are in `tests/unit/`. CI runs them as:

```bash
cd open-security-identity
pip install ../open-security-shared -r requirements.txt pytest pytest-asyncio
pytest tests/unit/
```

## License

MIT, as the rest of the repository. See the root `LICENSE` file.
