# Troubleshooting

Problems you are likely to meet when running Wildbox with Docker Compose, and
how to tell what is wrong. Commands use the Compose plugin (`docker compose`)
and the service names in `docker-compose.yml`; the
[Service ports](https://www.wildbox.io/guides/ports/) page lists them all.

## Table of Contents

- [First Checks](#first-checks)
- [The Stack Does Not Start](#the-stack-does-not-start)
- [Logging In and Authentication](#logging-in-and-authentication)
- [Gateway Responses](#gateway-responses)
- [Datastores](#datastores)
- [After an Upgrade](#after-an-upgrade)
- [Getting Help](#getting-help)

---

## First Checks

```bash
docker compose ps                       # which services are unhealthy or restarting
docker compose logs --tail=100 <service>
curl -s http://localhost/health         # the gateway
make health                             # every health URL; non-zero exit when one is unhealthy
```

Each backend answers its health URL on its own port, bound to `127.0.0.1`:
`/health`, except guardian, whose route is `/health/` (`/health` answers a
redirect, which is not healthy). `make health` checks all of them, and the
[Service ports](https://www.wildbox.io/guides/ports/#checking-the-stack)
page lists them.

---

## The Stack Does Not Start

### Compose stops with "... is required" or "set it in .env to production ..."

A required variable is missing from `.env`: a secret (`... is required`), or
`ENVIRONMENT` (`set it in .env to production, or to development for a
development stack`), which Compose requires of every stack. Generate the
file, or check it:

```bash
make generate-secrets    # writes .env; asks before replacing one
make validate-secrets    # names any placeholder or missing value
```

Never write secrets by hand: some services reject values that contain weak
patterns (the tools API refuses an `API_KEY` containing, for example, `abc`
or `123`, with "API key contains weak pattern"). The generator avoids them.

### `make start` returns before the services are healthy

`make start` and `make start-prod` run `docker compose ... up -d` and then
pause 15 seconds; they do not wait for the health checks. To wait for them,
run the command with `--wait`:

```bash
# what make start runs, plus --wait for the health checks
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --wait
```

### `make start-prod` rejects `docker-compose.prod.yml`

The production overlay uses the `!override` tag, which needs Docker Compose
2.24.4 or later (`docker compose version`). Update the Compose plugin; older
versions refuse the file rather than start an unsegmented stack.

### A service keeps restarting

Its log says why; the first error is usually the cause:

```bash
docker compose logs --tail=200 <service>
```

Common causes:

- **A secret is missing or invalid**: the service names the variable.
- **responder exits with "Failed to load N playbooks"**: a playbook in
  `open-security-responder/playbooks/` has a key the engine does not read.
  Unknown keys are rejected, not ignored; the message names the file and the
  key. `retry_count` and a top-level `output:` block are no longer accepted;
  step arguments go under `input`, not `params`.
- **A migration failed**: identity and data run alembic, guardian runs Django
  migrations when it starts. The log names the migration and, for the CHECK
  constraints added in 0.10.0, the offending values; see
  [UPGRADING.md](UPGRADING.md).

### A port is already in use

The gateway publishes 80, 443 and 8080 on all interfaces; the backends use
`127.0.0.1` ports listed on the
[Service ports](https://www.wildbox.io/guides/ports/) page. Find what holds the
port (`sudo lsof -i :443`) and stop it. Do not move the backend bindings off
`127.0.0.1`.

---

## Logging In and Authentication

How login, tokens and logout work is described in
[Authentication and sessions](https://www.wildbox.io/guides/authentication/).

| Symptom | Cause | What to do |
| --- | --- | --- |
| Login returns 400 | Wrong email or password | The first administrator is `INITIAL_ADMIN_EMAIL` / `INITIAL_ADMIN_PASSWORD` from the `.env` in use when identity **first** started; editing `.env` later does not change the account |
| Login returns 429 with `Retry-After: 900` | 5 failed logins locked the email for 15 minutes, even for the right password | Wait, or delete the lock from Redis as shown in [Failed-login lockout](https://www.wildbox.io/guides/authentication/#failed-login-lockout) |
| 403 `PASSWORD_CHANGE_REQUIRED` on every call after a successful login | A team owner or admin created the account with an initial password, which must be changed first | Change it in the dashboard, or with `POST /api/v1/identity/admin/me/change-password` (`current_password`, `new_password`), then use the token that call returns; see [Accounts that must change their password](https://www.wildbox.io/guides/authentication/#accounts-that-must-change-their-password) |
| Login returns 429 without `Retry-After` | The gateway's rate limit on `/auth/jwt/` (5 requests per second per address unless `GATEWAY_AUTH_RATE_LIMIT_PER_SECOND` says otherwise) | Slow down the client |
| 401 on every call after 30 minutes | The token expired; there is no refresh | Log in again |
| 401 right after logging out | The token was revoked, as intended | Log in again |
| Logout returns 400, "Token carries no jti" | The token was issued before the release that added `jti` | Nothing: it expires within 30 minutes |
| 503 from the gateway on authenticated calls | The gateway cannot reach identity (5-second timeout; after 10 failures it stops trying for 60 seconds) | `docker compose ps identity` and `docker compose logs identity` |
| identity logs "Authentication required" from Redis | identity's Redis URL has no password | Unset `IDENTITY_REDIS_URL`, or include `REDIS_PASSWORD` in it; see [UPGRADING.md](UPGRADING.md) |
| `curl` fails with a certificate error | The development certificate is self-signed | Pass `--cacert open-security-gateway/ssl/wildbox.crt` and use `localhost`; do not turn verification off |
| `http://localhost:8001/docs` returns 404 | identity, like every other service, serves its API docs and schema only when `ENVIRONMENT` is `development`, and the generated `.env` sets `production` | Expected; use the [identity API reference](https://www.wildbox.io/api/identity/endpoints/) |

---

## Gateway Responses

- **301 on port 80 or 8080**: expected. Only `/health` is served over HTTP;
  use `https://`.
- **404 under `/api/`**: the path is not one the gateway routes; see the
  [gateway routes](https://www.wildbox.io/docs.html#gateway-routes).
- **404 on `/api/v1/automations/`**: expected. The gateway does not route
  to n8n; its editor is on `http://127.0.0.1:5678` of the host, with the
  `automations` profile started. See
  [the automations README](open-security-automations/README.md).
- **502 elsewhere**: the backend behind the route is down; check it with
  `docker compose ps` and its log.

---

## Datastores

PostgreSQL and Redis publish no port; reach them through Compose:

```bash
docker compose exec postgres pg_isready -U postgres
docker compose exec postgres psql -U postgres -c 'SELECT 1'

REDISCLI_AUTH="$(sed -n 's/^REDIS_PASSWORD=//p' .env)" \
  docker compose exec -e REDISCLI_AUTH wildbox-redis redis-cli ping
```

`-e REDISCLI_AUTH` names the variable and takes its value from the
environment of the command. Do not write the password after the name, and
do not pass it to `redis-cli -a`: an argument is visible to every user of the
host in the process list.

**Do not flush Redis** (`FLUSHALL`) to "clear a cache". It holds the only copy
of CSPM scan state, responder run state and agents task ownership, as well as
the token blacklist and the login lockout counters.

`docker compose down -v` deletes every volume of the stack, databases
included. Use it only to start from nothing. `make clean` removes Python
caches from the checkout and touches no container, image or volume.

---

## After an Upgrade

- **Services still run the old code**: the images are built from the
  repository and `up -d` does not rebuild an existing image. Run
  `docker compose build` (with the same `-f` files you start with), then start
  the stack again.
- **Something else changed**: [UPGRADING.md](UPGRADING.md) lists what each
  release requires of an existing deployment.

---

## Getting Help

- Search or open an issue on
  [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues), with the
  output of `docker compose ps`, the relevant `docker compose logs`, your OS
  and Docker version. Remove secrets from logs before posting them.
- Questions: [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions).
- Security problems: follow [SECURITY.md](SECURITY.md), not a public issue.
