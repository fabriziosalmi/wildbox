# Wildbox Quick Start Guide

Run the whole Wildbox stack on one machine with Docker Compose, log in, and
make an authenticated API call.

How long this takes depends mostly on building the images the first time,
which can take a while on a slow machine or connection.

> **Early evaluation phase**: Wildbox is actively seeking feedback.
> [Report issues](https://github.com/fabriziosalmi/wildbox/issues) and
> [share feedback](https://github.com/fabriziosalmi/wildbox/discussions).

---

## Prerequisites

- **Docker** Engine 23.0 or later with the Compose plugin 2.24.4 or later
  (`docker compose`): [Install Docker](https://docs.docker.com/get-docker/).
  The [deployment guide](deployment.md#1-server-requirements) explains both
  minimums
- **Git**, **Python 3** (to generate secrets), **curl** and **jq**
- **Resources**: 8 GB RAM minimum (16 GB recommended), 20 GB of free disk

```bash
docker --version
docker compose version
python3 --version
```

---

## 1. Clone the Repository

```bash
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox
```

---

## 2. Generate `.env`

Do not write secrets by hand. `scripts/generate_secrets.py` reads
`.env.template`, fills every secret the stack needs with a random value and
writes `.env` with mode 0600; `scripts/validate_secrets.py` refuses a `.env`
that still contains a placeholder.

```bash
make generate-secrets    # python3 scripts/generate_secrets.py
# edit .env: set INITIAL_ADMIN_EMAIL
make validate-secrets    # python3 scripts/validate_secrets.py
```

`generate_secrets.py` asks before replacing an existing `.env` (it keeps a
backup). Before validating, open `.env` and set `INITIAL_ADMIN_EMAIL` to the
address you want for the first administrator. `INITIAL_ADMIN_PASSWORD` has
already been generated; leave it as it is. See the
[Credentials guide](credentials.md) for what each value is for.

Optional: set `ANTHROPIC_API_KEY` in `.env` to enable AI analysis in the
agents service. Everything else works without it.

---

## 3. Start the Stack

```bash
docker compose up -d --wait --wait-timeout 600
docker compose ps
```

`--wait` returns once every service reports healthy, which is how CI starts
the stack. `make start` adds the development overlay
(`docker-compose.dev.yml`) and `make start-prod` the production one
(`docker-compose.prod.yml`); neither waits for the health checks (they pause
15 seconds), so follow them with `docker compose ps`. The production
overlay needs Compose 2.24.4 or later.

There is no smaller stack behind the gateway. Compose starts a service's
dependencies with it, and the gateway depends on every service it routes
to: it refuses to start while one of their names does not resolve. So
`docker compose up gateway` starts identity, tools, data, guardian,
responder, agents, cspm and the dashboard as well. It leaves out only the
workers (`tools-worker`, `guardian-worker`, `guardian-beat`, `cspm-worker`,
`data-scheduler`), Flower and the sensor, and without the workers
asynchronous tool runs, scheduled guardian tasks, cloud scans and feed
collection do not run. To work on a single backend without the gateway,
start it alone, for example `docker compose up -d --wait identity`, which
also starts PostgreSQL and Redis.

The service names are the ones in `docker-compose.yml`; the
[Service ports](ports.md) page lists all of them with their ports.

---

## 4. Verify

The gateway is the public entry point. Port 80 answers `/health` and redirects
everything else to HTTPS:

```bash
curl -s http://localhost/health
```

Each backend also answers `/health` on its own port, bound to `127.0.0.1`
only; the loop on the [Service ports](ports.md#checking-the-stack) page checks
all of them.

---

## 5. Log In and Call the API

The gateway serves the API over HTTPS. On first start it generates a
self-signed development certificate in `open-security-gateway/ssl/`; pass it
to curl with `--cacert` rather than turning verification off.

This is the same sequence the integration tests use: a form-encoded login
(fields `username` and `password`) that returns `access_token`, then a bearer
token on every call.

```bash
# Read the admin credentials out of .env without sourcing it
# (a generated secret is not necessarily valid shell).
env_value() { sed -n "s/^$1=//p" .env | head -1; }
ADMIN_EMAIL="$(env_value INITIAL_ADMIN_EMAIL)"
ADMIN_PASSWORD="$(env_value INITIAL_ADMIN_PASSWORD)"
CA=open-security-gateway/ssl/wildbox.crt

TOKEN=$(curl -s --cacert "$CA" -X POST https://localhost/auth/jwt/login \
  --data-urlencode "username=$ADMIN_EMAIL" \
  --data-urlencode "password=$ADMIN_PASSWORD" | jq -r .access_token)

# Who am I?
curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  https://localhost/api/v1/identity/users/me | jq .

# List the security tools
curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  https://localhost/api/v1/tools | jq .
```

The other APIs follow the same pattern under `/api/v1/data/`,
`/api/v1/guardian/`, `/api/v1/responder/`, `/api/v1/agents/` and
`/api/v1/cspm/`; see the
[gateway routes table](https://www.wildbox.io/docs.html#gateway-routes) and
the [API documentation](../api/README.md).

### Dashboard

Open `https://localhost/` (through the gateway) and log in with the same
`INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD`. Change the password after
the first login.

---

## 6. Common Tasks

```bash
# Logs
docker compose logs -f identity
docker compose logs --tail=100 gateway

# Shell inside a service
docker compose exec identity bash

# Stop, keeping data
docker compose down

# Stop and DELETE all data volumes
docker compose down -v
```

Optional services stay down until you ask for them:

```bash
docker compose --profile automations up -d   # n8n workflows
docker compose --profile monitoring up -d    # Prometheus
```

---

## 7. Troubleshooting

- **A service is unhealthy**: `docker compose ps` shows which;
  `docker compose logs <service>` shows why.
- **The stack refuses to start with "... is required"**: a secret is missing
  from `.env`. Run `make validate-secrets`.
- **Login returns 400**: wrong credentials. Check `INITIAL_ADMIN_EMAIL` and
  `INITIAL_ADMIN_PASSWORD` in `.env`; the admin account is created from them
  on the identity service's first start.
- **Login returns 429**: after 5 failed logins the account is locked for 15
  minutes, even for the right password. Wait, or see
  [Failed-login lockout](authentication.md#failed-login-lockout).
- **curl fails with a certificate error**: pass
  `--cacert open-security-gateway/ssl/wildbox.crt` and use `localhost`, a name
  the development certificate covers.
- **A request on port 80 returns 301**: expected. Only `/health` is served
  over HTTP; use `https://localhost`.
- See [TROUBLESHOOTING.md](https://github.com/fabriziosalmi/wildbox/blob/main/TROUBLESHOOTING.md)
  for more.

---

## Next Steps

1. [Deployment guide](deployment.md) for a production setup
2. [Credentials](credentials.md) and [Authentication and sessions](authentication.md)
3. [Security status](../security/status.md) and [Security policy](../security/policy.md)
4. [API documentation](../api/README.md)
