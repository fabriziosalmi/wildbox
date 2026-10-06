# Wildbox Security Tools

The tools service is a FastAPI application that discovers security tool
plugins under `app/tools/`, exposes each one as an HTTP endpoint, and runs them
either inline or asynchronously on a Celery worker backed by Redis.

It runs behind the Wildbox gateway as part of the root `docker-compose.yml`
stack. It does not authenticate clients itself and accepts no direct API keys:
every tool and task route requires the identity headers and the shared secret
that only the gateway adds (see [Authentication](#authentication)).

## Components

In the root `docker-compose.yml` the service runs as three containers built
from this directory's `Dockerfile` (Python 3.11):

| Compose service | Role                                                                  |
| --------------- | --------------------------------------------------------------------- |
| `api`           | `uvicorn app.main:app` on port 8000, published on `127.0.0.1:8000`     |
| `tools-worker`  | Celery worker (`celery -A app.celery_app worker`) for asynchronous runs |
| `tools-flower`  | Flower monitoring UI on `127.0.0.1:5555`, behind HTTP basic auth       |

All three use Redis database 2 on `wildbox-redis` as Celery broker and result
backend. The gateway reaches the API at `open-security-tools:8000`.

## Running it

Start the whole platform from the repository root as described in the
[root README](../README.md); the tools service needs the gateway and identity
service to be reachable at all. To rebuild only this service:

```bash
docker compose up -d --build api tools-worker
```

### Standalone compose files

`docker-compose.yml` and `docker-compose.dev.yml` in this directory start the
API and Redis without the gateway, identity service or Celery worker. Without
the gateway, every tool and task route answers `401`, so these files are only
useful to check that the service starts and to read its health and schema
endpoints (see [Unauthenticated endpoints](#unauthenticated-endpoints)). Both
require `API_KEY` (see [Configuration](#configuration)) and say so when it is
not set:

```bash
API_KEY="$(openssl rand -hex 32)" docker compose up --build
```

## Authentication

Clients authenticate to the gateway, never to this service:

- `Authorization: Bearer <JWT>` from the identity service login, or
- `X-API-Key: <key>` for an identity API key. Reading tools and tasks needs
  the `tools:read` scope; running a tool or cancelling a task needs
  `tools:execute`.

The gateway validates the credential with the identity service and forwards
the request with `X-Wildbox-User-ID`, `X-Wildbox-Team-ID`, `X-Wildbox-Role`
and `X-Gateway-Secret`. The service (`app/auth.py`, using
`open_security_shared.gateway_auth`) answers:

- `401` when the identity headers are missing,
- `403` when `X-Gateway-Secret` does not match `GATEWAY_INTERNAL_SECRET`,
- `503` when `GATEWAY_INTERNAL_SECRET` is not set in the service environment.

The gateway also forwards the credential's type and an API key's scopes
(`X-Wildbox-Auth-Type`, `X-Wildbox-Scopes`), and the routes that run a tool
or cancel a task (`POST /api/tools/{tool}`, `POST /api/tools/{tool}/async`,
`DELETE /api/tasks/{task_id}`) check `tools:execute` again on them
(`require_tools_execute` in `app/auth.py`): `403` `INSUFFICIENT_SCOPE` for a
key without it, and `403` `GATEWAY_AUTH_TYPE_REQUIRED` for a request that
does not state its auth type, which a gateway older than this service does
not. Reading tools and tasks is checked by the gateway alone (#637).

See [docs/GATEWAY_AUTHENTICATION_GUIDE.md](../docs/GATEWAY_AUTHENTICATION_GUIDE.md)
for the gateway side.

## API

The gateway maps `/api/v1/tools/*` to `/api/tools/*` and `/api/v1/tasks/*` to
`/api/tasks/*` on this service. The examples below run from the repository
root and trust the gateway's self-signed development certificate, as the root
README does:

```bash
CA=open-security-gateway/ssl/wildbox.crt
ADMIN_EMAIL=$(sed -n 's/^INITIAL_ADMIN_EMAIL=//p' .env)
ADMIN_PASSWORD=$(sed -n 's/^INITIAL_ADMIN_PASSWORD=//p' .env)
TOKEN=$(curl -s --cacert "$CA" \
  --data-urlencode "username=$ADMIN_EMAIL" \
  --data-urlencode "password=$ADMIN_PASSWORD" \
  https://localhost/auth/jwt/login | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
```

| Method   | Gateway path                       | Purpose                                        |
| -------- | ---------------------------------- | ---------------------------------------------- |
| `GET`    | `/api/v1/tools`                    | List loaded tools and their metadata           |
| `GET`    | `/api/v1/tools/{tool_name}/info`   | Tool metadata plus input and output JSON Schema |
| `POST`   | `/api/v1/tools/{tool_name}`        | Run a tool and wait for the result             |
| `POST`   | `/api/v1/tools/{tool_name}/async`  | Queue a tool run on the Celery worker (`202`)  |
| `GET`    | `/api/v1/tasks`                    | List the caller's tasks (`limit`, 1 to 100)    |
| `GET`    | `/api/v1/tasks/{task_id}`          | Status and result of one of the caller's tasks |
| `DELETE` | `/api/v1/tasks/{task_id}`          | Cancel a pending or running task               |

List the tools and inspect one:

```bash
curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  https://localhost/api/v1/tools

curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  https://localhost/api/v1/tools/base64_tool/info
```

Run a tool synchronously. The request body is the tool's input model; an
invalid body returns `422` with the failing fields (the submitted values are
not echoed back):

```bash
curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation": "encode", "data": "hello"}' \
  https://localhost/api/v1/tools/base64_tool
```

Run it asynchronously and poll the task. The submit response carries
`task_id` and `status_url` (`/api/v1/tasks/{task_id}`). The task's `status`
is `pending`, `running` or `retrying` while it is not finished, and
`completed`, `failed`, `timeout`, `refused` or `cancelled` once it is
(`unknown` when its stored state cannot be read):

```bash
TASK=$(curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation": "encode", "data": "hello"}' \
  https://localhost/api/v1/tools/base64_tool/async \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["task_id"])')

curl -s --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/v1/tasks/$TASK"
```

Task ownership is recorded in Redis before the task is queued. A caller can
read, cancel and list only the tasks they submitted; any other task id
returns `404`. Task listings cover roughly the last day.

### Unauthenticated endpoints

These four routes have no authentication dependency; every other route
answers `401` without the gateway's identity. The gateway does not route
them, so they are reachable only from the Docker network or, in the root
stack, from the host on `127.0.0.1:8000`:

| Path            | Content                                                         |
| --------------- | --------------------------------------------------------------- |
| `/health`       | Status, service, version, number of loaded tools, active executions |
| `/metrics`      | Prometheus exposition format; `monitoring/prometheus.yml` scrapes it |
| `/openapi.json` | OpenAPI schema, only when `ENVIRONMENT` is `development` (there is no Swagger UI or ReDoc page) |
| `/api`          | Service name, version and the path of the tool list             |

```bash
curl -s http://127.0.0.1:8000/health
```

`/health` is the route the image's and the compose file's health checks
probe. It and `/api` answer anyone who reaches the service port, so they
say how the service is and which version answered, and nothing about the
deployment: not the environment, not its settings, not the names of the
loaded tools (`GET /api/v1/tools`, through the gateway, lists those). The
version is the one in `app/__init__.py`, which the OpenAPI schema and the
`X-API-Version` response header carry too. `/metrics` carries the request counters,
`wildbox_tool_executions_total` (the synchronous executions by tool and
outcome) and the asynchronous ones. Those execute in the worker, which
Prometheus cannot scrape: the worker counts in Redis how each task ended,
a task killed at the hard time limit or canceled included, and this
service exports the counts as `wildbox_tool_async_executions_total`, with
the length of the task queue (`wildbox_tool_async_queue_length`) and the
number of tasks the worker has taken
(`wildbox_tool_async_tasks_consumed_total`). See
[the endpoint reference](https://www.wildbox.io/api/tools/endpoints/#asynchronous-run-metrics).

There are no `/api/system/` routes: `info`, `metrics`, `operational-metrics`
and `health-aggregate` answered without authentication and were removed
(#646). For the health of the other services, use their own health checks
(`docker compose ps`) or Prometheus.

The active-execution count and the counters behind these endpoints live in
the `api` process memory, so run a single `api` replica (see the comment on
the `api` service in the root `docker-compose.yml`).

## Tools

`app/tools/` contains 52 tool packages. The `/health` response gives the
number that loaded in the running process (`tools_count`), and
`GET /api/v1/tools`, through the gateway, lists them; a tool that fails to
import is logged and skipped.

`api_security_analyzer`, `api_security_tester`, `base64_tool`,
`blockchain_security_analyzer`, `ca_analyzer`, `cloud_security_analyzer`,
`container_security_scanner`, `cookie_scanner`, `crypto_strength_analyzer`,
`ct_log_scanner`, `database_security_analyzer`, `digital_footprint_analyzer`,
`directory_bruteforcer`, `dns_enumerator`, `dns_security_checker`,
`email_harvester`, `email_security_analyzer`, `entra_id_security_analyzer`,
`file_upload_scanner`, `hash_cracker`, `hash_generator`, `header_analyzer`,
`http_security_scanner`, `iot_security_scanner`, `ip_geolocation`,
`jwt_analyzer`, `jwt_decoder`, `malware_hash_checker`, `metadata_extractor`,
`mobile_security_analyzer`, `network_port_scanner`, `network_scanner`,
`network_vulnerability_scanner`, `password_generator`,
`password_strength_analyzer`, `pki_certificate_manager`, `port_scanner`,
`saml_analyzer`, `security_automation_orchestrator`,
`social_engineering_toolkit`, `sql_injection_scanner`, `ssl_analyzer`,
`static_malware_analyzer`, `subdomain_scanner`,
`threat_intelligence_aggregator`, `url_analyzer`, `url_security_scanner`,
`vulnerability_db_scanner`, `web_application_firewall_bypass`,
`web_vuln_scanner`, `whois_lookup`, `xss_scanner`.

The dashboard's `/toolbox` page lists the same tools and builds a form for
each from its `/info` schema.

### Tool contract

`app/tool_loader.py` is the single loader for the API and the worker. A tool
is a Python package `app/tools/<name>/` (names starting with `_` and the
`wordlists` support package are skipped):

```text
app/tools/<name>/
  __init__.py
  main.py      # execute_tool (required), TOOL_INFO (optional)
  schemas.py   # Pydantic input and output models
```

- `main.py` must define `execute_tool`; a package without it is not loaded.
  It can be `async def` or a plain `def` (plain functions run in a thread
  pool on the API and directly on the worker). It receives the validated
  input model as its first argument.
- `schemas.py` must define one Pydantic model whose class name contains
  `Input` or `Request` and one whose name contains `Output` or `Response`
  (case-insensitive; `BaseToolInput` and `BaseToolOutput` themselves are
  ignored). Without both, the tool loads but gets no HTTP endpoint. The input
  model validates the request body and is published by `/info`; the output
  model is the endpoint's response model. Most tools subclass
  `BaseToolInput` and `BaseToolOutput` from `app/standardized_schemas.py`,
  which add common optional fields (`target`, `timeout`, `verify_ssl`, ...) and
  result fields (`success`, `tool_name`, `execution_time`, `error_message`,
  ...).
- `TOOL_INFO` is a dict with `display_name`, `description`, `version`,
  `author` and `category`; when missing, the loader fills in defaults and
  logs a warning.
- A tool whose `execute_tool` declares a `user_id` parameter acts on behalf
  of the caller: it runs only for an authenticated caller allowed by the
  authorization manager (`app/execution_manager.py`, `authorize_tool_call`),
  and receives that caller's id; see
  [Tools that act for a caller](#tools-that-act-for-a-caller).

Tools are copied into the image, so rebuild and restart `api` and
`tools-worker` after adding one.

## What the service logs, and what Redis holds

A tool's input is whatever the tool takes: a password to grade, a token to
decode, a key to test, a URL with a credential in it. Nothing a caller
submits is written to the log by value
([#755](https://github.com/fabriziosalmi/wildbox/issues/755)).

- A run is logged with the tool, the caller's user and team ids, the request
  id and the names of the fields the caller set (`input_fields`), for the
  synchronous route and for a submission alike.
- A record's fields reach the log only when they are named in
  `LOGGED_FIELDS` (`app/logging_config.py`), so what a line can carry is
  decided in one place. The list has no field for an input, a body, a
  header, a URL or the text of an error.
- A request is logged by its path, without its query string.
- An error a tool raises while it works on its input is logged by its class
  and the line that raised it (`ValueError at main.py:42 in scan`). A
  refused target is logged as a refusal, without the target; the caller
  reads which target in the answer.
- A tool names its target in a log line by its host only
  (`app/log_safety.py`, `host_of`): no user, password, path or query.
- The HTTP client libraries do not log the URLs the tools call.
- The traceback of an unexpected failure (a 500) is logged with the text of
  the exception: it is a fault of the service, and its cause is the
  operator's to read.

An asynchronous run needs its input to run, so the input is stored: it is
the body of the task's message in Redis, in the queue until a worker takes
the task and in the transport's `unacked` hash until the task ends, and it
is deleted when the task is acknowledged. A retry sends it again. A task no
worker ever takes stays queued, with its input, until the queue is purged:
the message has no expiry of its own. The result, which Redis keeps for an
hour, does not hold the input (`result_extended` is off), and the text of
the arguments that Celery sends along for worker logs, `celery inspect` and
Flower says how many fields the input has and nothing else.

## Caller and target policy

The two sections below are maintained with the policy code
(`app/execution_manager.py`, `app/security/authorization.py`,
`app/target_policy.py`).

### Tools that act for a caller

A tool whose `execute_tool` declares a `user_id` parameter acts on behalf of
the caller. Today that is `sql_injection_scanner` only. For such a tool the
execution path (`authorize_tool_call` in `app/execution_manager.py`, used by
both `POST /api/tools/<name>` and `POST /api/tools/<name>/async`):

1. refuses to run it without an authenticated caller;
2. asks the authorization manager (`app/security/authorization.py`) whether
   that caller may perform the tool's operation type (`destructive_test` for
   the scanner) against the tool's `target_url`;
3. passes the caller to the tool as `user_id`.

A refusal answers `403` with the reason. The caller is the user ID that the
gateway forwards in `X-Wildbox-User-ID`.

The policy is read at start-up from two files, and **with neither present,
nobody may run the scanner**. That is the default in `docker-compose.yml`:

- `USER_PERMISSIONS_FILE` (default `/etc/security/user_permissions.json`):
  user IDs mapped to the operations they may perform, for example
  `{"<user uuid>": ["destructive_test"]}`. Keys whose value is not a list,
  such as `description`, are ignored.
- `AUTHORIZED_TARGETS_FILE` (default `/etc/security/authorized_targets.json`):
  `{"targets": [...]}` with URLs (`https://shop.example.com/app` covers that
  path and everything below it, on the same scheme, host and port), host names,
  wildcard domains (`.example.com` covers the domain and its subdomains), IP
  addresses and CIDR ranges.

See `config/*.json.example`. To grant access, mount the files into both the
`api` and `tools-worker` containers of the root `docker-compose.yml`.
Destructive tests are limited to one per caller in any hour. The count is
kept in the service's Redis (`REDIS_URL`), one key per caller and operation
(`wildbox:tools:operation-limit:<user>:<operation>`), so the API process and
every worker process share it and a restart does not reset it. When Redis
cannot be reached the tool is not run: the API answers 503
(`Rate limiting temporarily unavailable`) and an asynchronous task fails
after its retries. A deployment without `REDIS_URL` cannot run these tools.

### Network targets

The tools that scan a host, an address or a range refuse internal targets
before they run (#614), on `POST /api/v1/tools/<name>`, in the
asynchronous task and in each step of `security_automation_orchestrator`.
The check is `enforce_target_policy` in `app/target_policy.py`, which also
runs the URL guard for tools that fetch a URL. What is internal, what the
allowlist covers and how a host is parsed are decided by
`open_security_shared.target_policy`, the implementation Guardian's asset
discovery and port scans use too (#748): `app/target_policy.py` holds which
fields of which tool are targets, this service's setting and the wording of
a refusal. Guardian has a list of its own,
`GUARDIAN_ALLOWED_INTERNAL_TARGETS`, and does not read this service's.

Refused, unless allowed below:

- private, loopback, link-local, unspecified, multicast, reserved and
  shared (`100.64.0.0/10`) addresses, and IPv4 addresses embedded in IPv6
  ones (IPv4-mapped, 6to4, NAT64);
- a CIDR or address range with any such address in it, and any range of
  more than 1024 addresses (an IPv4 `/22`, an IPv6 `/118`);
- a host name that resolves to such an address (every answer is checked)
  or does not resolve;
- the deployment's own names: every name without a dot (`wildbox-redis`,
  `postgres`, `gateway`), `localhost`, names under `.localhost`, `.local`,
  `.internal`, `.localdomain` and `.home.arpa`, and the cloud metadata
  names;
- spellings that are not canonical (`127.1`, `0x7f000001`), non-ASCII host
  names (write them in their `xn--` form) and values with whitespace.

The inputs checked, declared per tool in `NETWORK_TARGET_FIELDS`:

| Tool | Field | Holds |
| ------ | ------- | ------- |
| `ssl_analyzer`, `ca_analyzer`, `port_scanner`, `network_port_scanner`, `network_vulnerability_scanner` | `target` | a host name or IP address |
| `pki_certificate_manager` | `domain` | a host, `host:port` or a URL |
| `iot_security_scanner` | `target_ip`, `ip_range` | a host; an address or CIDR range |
| `network_scanner` | `network` | an address, a CIDR range or `a.b.c.d-e` |
| `database_security_analyzer` | `host` | a host name or IP address |
| `dns_enumerator` | `dns_servers` | IP addresses only |
| `container_security_scanner` | `image_name` | an image reference; its registry host is checked |

dns_enumerator also checks the name servers it attempts a zone transfer
from, which come from the domain's NS records, and connects to the
address it checked. `tests/unit/test_target_policy.py` fails when a tool
has a host-like input field that is neither declared nor listed in
`REVIEWED_NON_TARGET_FIELDS` with the reason it is not a target.

**Allowing a lab.** `TOOLS_ALLOWED_INTERNAL_TARGETS` takes comma-separated
CIDR ranges, IP addresses and host names, and is empty by default:

```bash
TOOLS_ALLOWED_INTERNAL_TARGETS=10.20.0.0/16,192.168.50.0/24,lab-dc01
```

An address inside a listed range is accepted, a range only if all its
internal addresses are inside listed ranges, and a host name if it is
listed (exactly, not its subdomains) or if all its internal addresses are
inside listed ranges. The range limit still applies. A range must have its
host bits zero (`10.20.0.0/16`); a bad entry stops the service and the
worker at start-up. Give the same value to the `api` and `tools-worker`
containers (the root `docker-compose.yml` does). Do not list the stack's
own Docker networks: a listed range is open to every caller of every
network tool.

This list is separate from `AUTHORIZED_TARGETS_FILE` (above). That one
names the targets a caller may attack through a tool that acts for the
caller, among public ones, and never lifts the SSRF guard; this one opens
internal targets to every caller.

**What remains.** The check resolves a host name, and most tools resolve
it again when they connect, so a name whose DNS answer changes in between
(DNS rebinding) can still reach an internal address in that window.
`container_security_scanner` hands the image to trivy, which follows the
registry's redirects and token endpoints by itself.

## Configuration

Settings are read from the environment (and a `.env` file in the working
directory) by `app/config.py`. `.env.example` lists the common ones. In the
root stack, `docker-compose.yml` sets them for each container.
`GATEWAY_INTERNAL_SECRET`, `USER_PERMISSIONS_FILE` and
`AUTHORIZED_TARGETS_FILE` are not fields of `app/config.py`: they are read
from the process environment only (`open_security_shared.gateway_auth`,
`app/security/authorization.py`), not from that `.env` file.

| Variable                  | Default                 | Notes                                                        |
| ------------------------- | ----------------------- | ------------------------------------------------------------ |
| `API_KEY`                 | none (required)         | See below                                                    |
| `GATEWAY_INTERNAL_SECRET` | none                    | Must match the gateway's; without it every tool and task request the gateway forwards answers `503` |
| `REDIS_URL`               | none                    | Celery broker and backend, task ownership records            |
| `ENVIRONMENT`             | none                    | `development`, `staging` or `production`; `/openapi.json` is served only in `development`, and not when the variable is unset |
| `DEBUG`                   | `false`                 |                                                              |
| `LOG_LEVEL`               | `INFO`                  |                                                              |
| `CORS_ORIGINS`            | `http://localhost:3000` | Comma-separated                                              |
| `TOOL_TIMEOUT`            | `300`                   | Default synchronous execution timeout, seconds               |
| `MAX_CONCURRENT_TOOLS`    | `10`                    | Concurrent synchronous executions in the `api` process        |
| `TOOLS_ALLOWED_INTERNAL_TARGETS` | empty | Internal ranges, addresses and host names the network tools may scan; see [Network targets](#network-targets) |
| `USER_PERMISSIONS_FILE`, `AUTHORIZED_TARGETS_FILE` | `/etc/security/...json` | Policy for tools that act for a caller; see [Tools that act for a caller](#tools-that-act-for-a-caller) |
| `HOST`, `PORT`            | `127.0.0.1`, `8000`     | Used only by `python -m app.main`; the image runs `uvicorn` on `0.0.0.0:8000` |

`API_KEY` is a required setting: the process fails at startup without it.
`app/config.py` rejects a value shorter than 32 characters, with fewer than 16
distinct characters, or containing a weak pattern (`key`, `secret`, `test`,
`123`, `abc`, `wildbox` and others). Clients never send it; tool and task
routes accept only gateway-forwarded requests. In the root stack,
`make generate-secrets` writes it to `.env`.

There is no rate-limit setting. Requests are limited per team by the
gateway (`RATE_LIMIT_PER_HOUR` in the root `.env`), which every request
passes through; the service bounds the cost of a call with
`MAX_CONCURRENT_TOOLS`, `TOOL_TIMEOUT` and the hourly limits of the
[tools that act for a caller](#tools-that-act-for-a-caller).
`RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW` were read and never enforced,
and were removed (#646). An environment variable the service does not
declare is ignored, but a key it does not declare in a `.env` file in the
working directory stops it at start-up (`Extra inputs are not permitted`):
delete those two lines from a `.env` copied from an older `.env.example`.

The Celery limits are fixed in `app/celery_app.py` (10-minute hard limit,
9-minute soft limit, results kept for one hour) and the worker command line in
`docker-compose.yml` (concurrency 4); they are not environment variables.

Two tools call third-party services with keys read from the process
environment: `threat_intelligence_aggregator` (`VIRUSTOTAL_API_KEY`,
`SHODAN_API_KEY` and an AlienVault key) and `malware_hash_checker`
(`VIRUSTOTAL_API_KEY`, `HYBRID_ANALYSIS_API_KEY`). The root
`docker-compose.yml` does not pass them to the `api` and `tools-worker`
containers; add them there (for example in a compose override file) to use
those integrations.

## Project structure

```text
open-security-tools/
  app/
    main.py                  # FastAPI app, tool registration, system endpoints
    config.py                # Settings
    auth.py                  # Gateway-only authentication dependency
    tool_loader.py           # Tool discovery and schema lookup
    execution_manager.py     # Synchronous execution, timeouts, authorization
    celery_app.py, tasks.py  # Celery app and the async execution task
    task_ownership.py        # Redis records of who submitted which task
    standardized_schemas.py  # BaseToolInput, BaseToolOutput and shared models
    api/                     # router.py (tools), async_router.py (tasks)
    security/                # Authorization manager and input validators
    tools/                   # One package per tool, plus wordlists/
    utils/                   # Shared helpers for tools
  config/                    # Examples of the two authorization files
  tests/unit/                # Unit tests
  Dockerfile                 # Production image (Python 3.11)
  Dockerfile.dev             # Development image with --reload
  docker-compose.yml         # Standalone stack (no gateway; see above)
  docker-compose.dev.yml     # Standalone development stack (no gateway)
  requirements.in            # Direct dependencies
  requirements.txt           # Locked dependencies
```

## Development

The service imports the shared package from `../open-security-shared`.
Install both, then run the unit tests from this directory as CI does:

```bash
cd open-security-tools
pip install ../open-security-shared
pip install -r requirements.txt
pip install pytest pytest-cov pytest-asyncio
pytest tests/unit/ -v
```

CI also starts a Redis server for this suite and sets
`TOOLS_TEST_REDIS_URL` (`.github/workflows/test.yml`). Without that variable
the tests that need Redis (the hourly limit, the asynchronous run counters)
start a `redis-server` found on `PATH`, and are skipped when there is none.

`requirements.txt` is generated from `requirements.in`; change the latter and
regenerate the lock instead of editing `requirements.txt` by hand.

## License

See [LICENSE](../LICENSE) at the repository root.
