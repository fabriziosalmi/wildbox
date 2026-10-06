# Wildbox Security Gateway

The gateway is the single entry point of the Wildbox stack. It is an
OpenResty (nginx with LuaJIT) reverse proxy that terminates TLS, routes
requests to the backend services, and authenticates API requests by asking
the identity service. Backend services trust only requests that carry the
gateway's identity headers and the shared `GATEWAY_INTERNAL_SECRET`.

The configuration lives in:

| File | Contents |
| --- | --- |
| `nginx/nginx.conf` | Global settings, `limit_req` zones, Lua shared dictionaries, exported environment variables |
| `nginx/conf.d/wildbox_gateway.conf` | Upstreams, listeners and every `location` block |
| `nginx/includes/` | Shared proxy settings, the request-method and CORS rules (`cors.conf`), dashboard header settings, and the auth-cache purge endpoint |
| `nginx/lua/auth_handler.lua` | Authentication, decision cache, revocation, API-key scopes, per-team rate limit |
| `nginx/lua/utils.lua` | Token extraction, header cleanup, HTTP client helper |
| `nginx/lua/cors.lua` | The CORS allowlist (`CORS_ORIGINS`), the preflight answer, and the labels on the API's responses |
| `scripts/docker-entrypoint.sh` | Generates a self-signed certificate if none is mounted, then starts OpenResty with `nginx/nginx.conf` |

## Running

The gateway runs as the `gateway` service of the root `docker-compose.yml`
(container `open-security-gateway`), on the `wildbox` network defined there.
Docker prefixes the network with the Compose project name, so with the default
project name it appears as `wildbox_wildbox` in `docker network ls`.

```bash
# From the repository root
docker compose up -d --wait
```

Published ports:

| Port | Purpose |
| --- | --- |
| 443 | HTTPS: the dashboard and every API route |
| 80 | `/health`; everything else answers `301` to HTTPS |
| 8080 | `/health`; everything else answers `301` to HTTPS |

The redirect target uses the first `server_name`, so `http://localhost/x` is
redirected to `https://api.wildbox.local/x`. Use HTTPS directly.

A fourth listener on port 8081 is not published. Only containers on the
Compose network reach it; identity calls the auth-cache purge endpoint there.

At first start the entrypoint writes a self-signed certificate to
`open-security-gateway/ssl/` (mounted at `/etc/ssl/wildbox`), valid for
`api.wildbox.local`, `wildbox.local`, `*.wildbox.local`, `localhost`,
`gateway`, `open-security-gateway` and `127.0.0.1`. Trust it explicitly
instead of disabling verification:

```bash
curl --cacert open-security-gateway/ssl/wildbox.crt https://localhost/health
```

In production, mount a real certificate and key at
`/etc/ssl/wildbox/wildbox.crt` and `/etc/ssl/wildbox/wildbox.key`.

## Health check

`/health` needs no authentication. On port 443 and on port 80 it returns:

```json
{"status":"healthy","service":"wildbox-gateway","timestamp":"<nginx $time_iso8601>"}
```

On port 8080 it returns
`{"status":"healthy","service":"wildbox-gateway","port":"8080-redirect-only"}`.
The response is static: it does not check any backend service.

## Authentication

Routes that authenticate at the gateway call `auth_handler.authenticate()`.
It accepts exactly two credentials:

- `Authorization: Bearer <JWT>`, a session token from the login endpoint
- `X-API-Key: <key>`, an API key created in identity (`wsk_...`)

There is no query-parameter token and no cookie authentication: a cookie alone
is not a credential (`nginx/lua/utils.lua`, `extract_auth_token`).

For each request without a cached decision, the gateway sends the token to
identity's `POST /internal/authorize` with the `X-Gateway-Secret` header, and
then:

1. Caches the decision in the `auth_cache` shared dictionary for
   `AUTH_CACHE_TTL` seconds (300 by default), never past the credential's own
   expiry.
2. Refuses the request if the token was revoked: logout, a password change, a
   revoked API key, or the user's removal from the team. Identity sends these
   revocations to the purge endpoint before it commits them, so a cached
   decision does not outlive them.
3. Answers `403 PASSWORD_CHANGE_REQUIRED` if the account must change its
   initial password.
4. Enforces API-key scopes (see below).
5. Applies the per-team rate limit.
6. Strips `Authorization`, `X-API-Key` and any client-supplied `X-Wildbox-*`
   headers, then forwards `X-Wildbox-User-ID`, `X-Wildbox-Team-ID`,
   `X-Wildbox-Role`, `X-Gateway-Secret` and `X-Request-ID` to the service,
   with what the credential is: `X-Wildbox-Auth-Type` and, for an API key,
   `X-Wildbox-Scopes` (see [What the service is told](#what-the-service-is-told)).

If identity cannot be reached, the gateway answers `503` with a JSON body and
`Retry-After`. After 10 failed calls a circuit breaker stops calling identity
for 60 seconds.

### API-key scopes

A key whose `scopes` is a list is checked against the scope each request
needs (`ROUTE_SCOPES` in `auth_handler.lua`). A row covers its path and
everything under it, so `/api/v1/tools` and `/api/v1/tools/whois` need the
same scope:

| Path | Read (`GET`, `HEAD`) | Other methods |
| --- | --- | --- |
| `/api/v1/tools`, `/api/v1/agents`, `/api/v1/tasks` | `tools:read` | `tools:execute` |
| `/api/v1/guardian` | `data:read` | `data:write`, or `data:delete` for `DELETE` |
| `/api/v1/data/ingest` (this path only) | `read` | `data:ingest`, also satisfied by `data:write` or `write` |
| `/api/v1/data`, `/api/v1/cspm`, `/api/v1/responder`, `/api/v1/identity/health` | `read` | `write` |
| An authenticated path with no row | `admin` | `admin` |

`admin` and `*` satisfy every scope. Session tokens are not scope-limited.

A generic scope also satisfies the resource scopes of its level: `read`
satisfies `tools:read` and `data:read`, and `write` satisfies those and
`tools:execute`, `data:write` and `data:ingest`. `tools:admin` and
`data:delete` are satisfied only by themselves, by the resource's `admin`
scope, and by `admin` and `*`. No route requires `tools:admin` since the
automations route was removed; a key that holds it has what `tools:read`
and `tools:execute` give.

The request is mapped by the path nginx chose its location for, before any
rewrite in that location: the server block copies `$uri` into
`$wildbox_route_uri`, and `scripts/check_gateway_config.py` fails for a
configuration that authenticates without it.

A location added to `wildbox_gateway.conf` needs a row in `ROUTE_SCOPES`
and a pin in `test/route_scope_tests.sh`. Without the row it requires
`admin` of every scope-limited key; without the pin the harness fails.

### What the service is told

The gateway forwards the credential it decided on, so that a service can
check a scope itself (`credential_headers` in `auth_handler.lua`):

| Credential | `X-Wildbox-Auth-Type` | `X-Wildbox-Scopes` |
| --- | --- | --- |
| Session (JWT) | `session` | not sent |
| API key with scopes | `api_key` | the scopes, separated by single spaces, in identity's order |
| API key that is not limited | `api_key` | `*` |

Both are set by `authenticate()` and sent by `proxy_params.conf` from
`$wildbox_auth_type` and `$wildbox_scopes`; a client's own are removed, and
a location that does not authenticate forwards neither. The auth type
follows identity's answer: a decision that names an API key is `api_key`.
A value that is not a scope name is not forwarded.

The data service, guardian and the tools routes that run a tool require the
scope again on these headers, and refuse a request that carries the
gateway's secret without `X-Wildbox-Auth-Type`. The
[Gateway authentication guide](../docs/GATEWAY_AUTHENTICATION_GUIDE.md#credential-headers)
describes how a service reads them. `test/scope_vectors.txt` is the scope
hierarchy written out; `test/scope_vector_tests.sh` checks `scopes_satisfy`
against it and the shared package's tests check the services' copy.

### What each upstream receives

`X-Gateway-Secret` and the `X-Wildbox-*` headers are what a Wildbox service
trusts, so they go to Wildbox services and to nothing else, and a caller's
own credentials go only where they are validated:

| Upstream | Receives | Does not receive |
| --- | --- | --- |
| A Wildbox service behind `authenticate()` | `X-Gateway-Secret`, the caller's user, team and role, the credential's type and scopes | the caller's `Authorization`, `X-API-Key` and `auth_token` cookie |
| identity's own routes (`/api/v1/identity/`, `/auth/users/`, `/auth/jwt/`, ...) | the caller's `Authorization`, which identity validates | `X-Gateway-Secret`, any `X-Wildbox-*`, `X-API-Key` |
| The dashboard | its cookies | `X-Gateway-Secret`, any `X-Wildbox-*`, `Authorization`, `X-API-Key` |

The `auth_token` cookie is where the dashboard keeps the session JWT. A
browser sends it with every request to the gateway's origin, so
`clean_request_headers()` removes it, and only it, on every route
`authenticate()` guards.

The gateway proxies to nothing else. `/api/v1/automations/` used to reach
n8n, the optional automations service, which is not a Wildbox service; the
location is removed and the path answers 404
(see [Automations](#automations-n8n)). `authenticate()` must not guard a
location whose upstream is anything but a Wildbox service: it would send
that upstream the secret.

The harness enforces the table: `test/upstream_header_tests.sh` reads every
location with a `proxy_pass` from `wildbox_gateway.conf`, fails for one it
has no classification for, and checks on the wire what each one's upstream
receives of a request that carries a session token, an API key, the
session cookie and forged copies of the gateway's own headers.
`tests/scripts/test_gateway_authenticated_locations.py` fails for a
location that proxies to anything but a Wildbox service or the dashboard.

### Automations (n8n)

The gateway does not route to n8n. `/api/v1/automations/` proxied to its
whole surface, the editor, the REST API and the webhooks, for every
registered session of every team; n8n is a single-tenant tool with accounts
of its own, and an instance whose owner account does not exist yet lets the
first caller create it. The path now falls to the catch-all and answers 404
with or without a credential.

n8n's editor is on `127.0.0.1:5678` of the host, with the `automations`
Compose profile started; `open-security-automations/README.md` has the
setup. The workflows shipped there call the API outbound, through the
gateway, with an API key. A workflow that needs an inbound webhook needs a
location of its own for n8n's `/webhook/` prefix only, without
`authenticate()` and without `proxy_params.conf`, relying on the webhook's
own authentication in n8n.

## Routing

All routes below are on the HTTPS listener (port 443). "Gateway auth" means
the location runs `auth_handler.authenticate()`; "identity" means the request
is passed to identity with its `Authorization` header, and identity
authenticates it.

### Identity

| Gateway path | Upstream | Auth |
| --- | --- | --- |
| `/auth/jwt/*` | `open-security-identity:8001` `/api/v1/auth/jwt/*` | identity (login is public) |
| `/auth/register` | `open-security-identity:8001` `/api/v1/auth/register` | none |
| `/auth/forgot-password` | `open-security-identity:8001` `/api/v1/auth/forgot-password` | none |
| `/auth/reset-password` | `open-security-identity:8001` `/api/v1/auth/reset-password` | none |
| `POST /auth/logout` | `open-security-identity:8001` `/api/v1/auth/logout` | identity |
| `/auth/users/*` | `open-security-identity:8001` `/api/v1/users/*` | identity |
| `/api/v1/identity/auth/*` | `open-security-identity:8001` `/api/v1/auth/*` | identity |
| `/api/v1/identity/health` | `open-security-identity:8001` `/health` | gateway |
| `/api/v1/identity/*` | `open-security-identity:8001` `/api/v1/*` | identity |

`/auth/jwt/*` is limited to 5 requests per second per client IP (burst 3);
`/auth/register` and `/auth/forgot-password` use the same zone with burst 2.
Identity routes do not pass through `auth_handler`, so the per-team rate
limit and API-key scopes do not apply to them; identity enforces the
password-change requirement on them itself. Since the gateway authenticated
nobody on these routes, it forwards no `X-Gateway-Secret` to identity
(`$wildbox_gateway_secret` stays empty; `authenticate()` sets it only for the
caller it verified, #664).

### Other services

| Gateway path | Upstream | Auth |
| --- | --- | --- |
| `/api/v1/data/health` | `open-security-data:8002` `/health` | gateway |
| `/api/v1/data/*` | `open-security-data:8002` `/api/v1/*` | gateway |
| `/api/v1/cspm/*` | `open-security-cspm:8019` `/api/v1/*` | gateway |
| `/api/v1/responder/*` | `open-security-responder:8018` `/v1/*` | gateway |
| `/api/v1/guardian/*` | `open-security-guardian:8013` `/api/v1/*` | gateway |
| `/api/v1/agents/stats` | `open-security-agents:8006` `/stats` | gateway |
| `/api/v1/agents/*` | `open-security-agents:8006` `/v1/*` | gateway |
| `/api/v1/tools` | `open-security-tools:8000` `/api/tools` | gateway |
| `/api/v1/tools/*` | `open-security-tools:8000` `/api/tools/*` | gateway |
| `/api/v1/tasks` | `open-security-tools:8000` `/api/tasks` | gateway |
| `/api/v1/tasks/*` | `open-security-tools:8000` `/api/tasks/*` | gateway |

Notes:

- `/api/v1/guardian/*` presents `Host: open-security-guardian` to the Django
  service and forwards the caller's host as `X-Forwarded-Host`; redirects are
  rewritten back to `/api/v1/guardian/`. It also sends
  `X-Forwarded-Prefix: /api/v1/guardian`, a literal that replaces any value
  the client sent: guardian writes its pagination links under that path, as
  relative references without a host (#643).
- `/api/v1/automations/*` is not a route: it answers 404. See
  [Automations](#automations-n8n).

### Dashboard and other locations

| Gateway path | Upstream or response | Auth |
| --- | --- | --- |
| `/` | `open-security-dashboard:3000` | none (the dashboard enforces its own login) |
| `= /auth/login`, `= /auth/signup`, `GET /auth/logout` | dashboard pages | none |
| `/login/`, `/register/`, `/signup/` | dashboard | none |
| `/_next/hmr` | dashboard, WebSocket upgrade (`next dev` hot reload) | none |
| `/favicon.ico` and paths outside `/api/` ending in `.css`, `.js`, or an image or font extension | dashboard, cached for one year | none |
| `/ws/*` | dashboard, WebSocket upgrade | none at the gateway |
| `/public/*` | files under `/var/www/public/` in the container (none are shipped) | none |
| `/tools/*` | `404` JSON: the standalone tools UI was removed | none |
| `/internal/gateway/purge-auth-cache` | auth-cache purge (see below) | private source IP and `X-Gateway-Secret` |
| `/api/*` (anything not matched above) | `404` `{"error":"endpoint_not_found",...}` | none |
| `/health` | static JSON (see above) | none |

The sensor service has no gateway route: `/api/v1/sensor/*` falls through to
the `/api/` catch-all and answers `404`. The sensor is a client of the
gateway instead: it posts telemetry to `/api/v1/data/ingest` with an API key.

### Example

```bash
# ADMIN_EMAIL and ADMIN_PASSWORD as in the root README's "Verify" step
CA=open-security-gateway/ssl/wildbox.crt

TOKEN=$(curl -s --cacert "$CA" \
  --data-urlencode "username=$ADMIN_EMAIL" \
  --data-urlencode "password=$ADMIN_PASSWORD" \
  https://localhost/auth/jwt/login | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

# Identity authenticates this request itself
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  https://localhost/api/v1/identity/users/me

# The gateway authenticates this one and forwards X-Wildbox-* headers
curl --cacert "$CA" -H "Authorization: Bearer $TOKEN" \
  https://localhost/api/v1/tools
```

## Rate limiting

Two independent limits apply:

- **Per client IP** (`limit_req` in `nginx.conf`). The HTTPS server applies the
  `global` zone, 100 requests per second with burst 10, to every location that
  does not set its own. The auth endpoints use the `auth` zone (5 requests per
  second) and static assets the `static_assets` zone (500 requests per second,
  burst 200). Excess requests get `429`.
- **Per team** (`apply_rate_limiting` in `auth_handler.lua`), on routes that
  call `authenticate()`. `RATE_LIMIT_PER_HOUR` (default 10000) is enforced as a
  fixed 60-second window of `RATE_LIMIT_PER_HOUR * 60 / 3600` requests, 166 by
  default. Responses carry `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  `X-RateLimit-Reset` and `X-RateLimit-Policy`; over the limit the gateway
  answers `429` with `Retry-After` and
  `{"error":"rate_limit_exceeded",...}`.

There are no plans or tiers: every team gets the same limit.

## Auth-cache purge

`POST /internal/gateway/purge-auth-cache` lets identity revoke cached
decisions. It is reachable on the internal listener (8081) and on 443, only
from private address ranges, and only with the correct `X-Gateway-Secret`. The
JSON body selects what is revoked: `users` (password change), `memberships`
(team removal), `api_keys`, `jtis` (logout), a single `token`, or an empty body
to flush the whole cache. The answer is
`{"purged":true,"scope":"...","revoked":<n>}`.

## Configuration

The root `docker-compose.yml` passes these variables to the gateway. Lua reads
them through the `env` directives in `nginx.conf`.

| Variable | Default | Effect |
| --- | --- | --- |
| `GATEWAY_INTERNAL_SECRET` | none, required | Sent to identity's `/internal/authorize` as `X-Gateway-Secret`, and forwarded to a service only on requests the gateway authenticated. If it is empty, every authorization fails. |
| `IDENTITY_SERVICE_URL` | `http://open-security-identity:8001` | Base URL for `/internal/authorize` |
| `AUTH_CACHE_TTL` | `300` | Seconds a decision is cached |
| `RATE_LIMIT_PER_HOUR` | `10000` | Per-team request budget, see above. Must be a whole number from 1 to 1,000,000,000; any other value stops the gateway at startup |
| `CORS_ORIGINS` | `http://localhost:3000` in `docker-compose.yml`, empty under the production overlay | The origins whose pages may call the API from a browser, see [CORS](#cors). An entry that is not an origin stops the gateway at startup |

The Compose file and `.env.example` also set `WILDBOX_ENV`, `GATEWAY_LOG_LEVEL`
and `GATEWAY_DEBUG`. They have no effect: no nginx or Lua code reads
`WILDBOX_ENV` or `GATEWAY_LOG_LEVEL`, and `GATEWAY_DEBUG` is stored in the
configuration but never used. The error log level is fixed at `warn` in
`nginx.conf`.

### CORS

The dashboard is normally served by the gateway, on the API's own origin,
and needs no CORS. A dashboard on another origin, and the dashboard's
development server on `http://localhost:3000`, do. `CORS_ORIGINS` lists the
origins that may call the API from a browser: exact origins (scheme, host,
optional port), comma-separated; a JSON list is read too. Nothing is
allowed that is not listed, and an entry that is not an origin (a wildcard,
a path, a bare host name) stops the gateway at startup.

The rules are in `nginx/lua/cors.lua`, applied by `includes/cors.conf`,
which the production and the test configuration both include at server
level. For the API (`/api/` and identity's routes under `/auth/`):

- A preflight from a listed origin (`OPTIONS` with `Origin` and
  `Access-Control-Request-Method`) is answered `204` by the gateway, before
  authentication and without reaching a service. Any other `OPTIONS`
  request, and any method outside `GET`, `HEAD`, `POST`, `PUT`, `PATCH` and
  `DELETE`, is answered `405`.
- A response to a request from a listed origin carries
  `Access-Control-Allow-Origin` with that origin (never `*`) and
  `Access-Control-Allow-Credentials: true`, the gateway's own `401`, `403`,
  `404` and `429` answers included.
- A response to any other origin carries no `Access-Control-*` header. What
  a service sets is removed either way: the gateway is the one authority,
  so a header is never doubled.
- Every response carries `Vary: Origin`.

The dashboard's own pages are not labelled. `test/cors_tests.sh` checks all
of this against the production image and configuration, and the same core
cases against the test configuration.

## Logs

Access logs use the `gateway` format in `nginx.conf`, which includes the
method and path of the request, the request id (`rid=`), the upstream
address and status, timings, and the team id from the `X-Wildbox-Team-ID`
response header. The path is the one the client asked for, cut at the first
`?`: the query string of a request is not logged, and neither is its
`Referer`. nginx's own error log is another matter: a line it writes while
it handles a request ends with that request's first line, query string
included, and that cannot be configured. Its `user_id` field reads a
response header the gateway never sets, so it is always empty. Logs are
written to
`open-security-gateway/logs/` on the host.

```bash
docker compose logs -f gateway
docker compose exec gateway tail -f /var/log/nginx/access.log
```

## Development

Check and reload the configuration in the running container:

```bash
docker compose exec gateway /usr/local/openresty/bin/openresty -c /etc/nginx/nginx.conf -t
docker compose exec gateway /usr/local/openresty/bin/openresty -c /etc/nginx/nginx.conf -s reload
```

To add a backend service, add an `upstream` and a `location` block to
`nginx/conf.d/wildbox_gateway.conf`, call `auth_handler.authenticate()` in an
`access_by_lua_block`, and add the service to the gateway's `depends_on` in the
root `docker-compose.yml`: nginx resolves upstream names at startup and exits
if one cannot be resolved. Give the route a row in `ROUTE_SCOPES`
(`nginx/lua/auth_handler.lua`) and a pin in `test/route_scope_tests.sh`; see
[API-key scopes](#api-key-scopes).

CI runs two checks on this directory:

- `.github/workflows/gateway-lint.yml` runs `luacheck` over `nginx/lua`.
- `.github/workflows/gateway-tests.yml` runs the harness against a mock
  identity (`test/mock_identity.py`). It builds `Dockerfile.test`, whose
  configuration is written for the tests, and runs `test/ci_auth_tests.sh`,
  `test/scope_forwarding_tests.sh`, `test/scope_vector_tests.sh`,
  `test/revocation_tests.sh` and `test/startup_config_tests.sh` against it.
  It also builds the production `Dockerfile` and runs
  `test/route_scope_tests.sh` against it: the scope each authenticated
  location of `wildbox_gateway.conf` requires, per method, with the mock
  answering for every upstream. `test/upstream_header_tests.sh`
  runs against the same image: which of Wildbox's own headers each
  proxying location sends its upstream. `test/cors_tests.sh` checks CORS against it and against the test
  configuration. `test/production_image_tests.sh` checks the
  image as built, with nothing mounted over `/etc/nginx`: only this
  project's configuration is loaded, port 80 answers `/health` and
  redirects the rest whatever the `Host`, and Docker reports the container
  healthy by the image's own `HEALTHCHECK`.

The `docker-compose.yml` and `Makefile` in this directory are for standalone
use. They use a separate `wildbox-net` network and are not what the root stack
or CI runs. There is no `docker-compose.dev.yml` any more: it mounted a mock
identity configuration that was never in the repository, so it could not
start. The mock identity the tests use is `test/mock_identity.py`, run by
`.github/workflows/gateway-tests.yml`.

## License

MIT, as the rest of the repository. See the root `LICENSE` file.
