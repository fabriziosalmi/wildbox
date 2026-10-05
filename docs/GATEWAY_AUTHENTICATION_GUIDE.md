# Gateway Authentication Pattern: Developer Guide

> **Example values are fictitious.** Keys, tokens, IDs and host names below
> are placeholders; `example.com` is reserved for documentation by RFC 2606.
> Never paste a real credential into documentation.

## Overview

The gateway (`open-security-gateway`, OpenResty) is the single entry point.
It authenticates the caller with identity, then forwards the request to the
backend service with the caller's identity in `X-Wildbox-*` headers and a
proof of origin in `X-Gateway-Secret`. The backend checks the proof of origin
and trusts the headers; it never sees the caller's credential.

```text
Client --(JWT or API key)--> Gateway --(POST /internal/authorize)--> Identity
                               |
                               +--(X-Wildbox-* + X-Gateway-Secret)--> Backend
```

## What the gateway does

On every authenticated `/api/v1/` route except identity's own, the gateway runs the
shared handler (`authenticate()` in
`open-security-gateway/nginx/lua/auth_handler.lua`):

1. It reads the credential: `Authorization: Bearer <token>` first, otherwise
   `X-API-Key: <key>`. A cookie alone is not a credential. Without either it
   answers `401` with `{"error":"authentication_required",...}`.
2. It asks identity (`POST /internal/authorize`, with `X-Gateway-Secret`) to
   validate the credential, and caches the answer. A credential identity
   refuses gets `401` (`invalid_token`); identity unreachable gets `503`.
3. It checks revocation markers, password changes, API-key revocation and
   team removal, and the API key's scopes, and applies the per-team limit of
   `RATE_LIMIT_PER_HOUR` requests per hour (10000 by default), enforced in
   60-second windows of one sixtieth of that figure (166 with the default).
   The gateway validates `RATE_LIMIT_PER_HOUR` at startup and does not start
   when it is not a whole number from 1 to 1,000,000,000.
4. It removes `Authorization`, `X-API-Key` and any client-supplied
   `X-Wildbox-User-ID`, `X-Wildbox-Team-ID`, `X-Wildbox-Role`,
   `X-Wildbox-Auth-Type` and `X-Wildbox-Scopes`
   (`utils.clean_request_headers()`), then stores the validated identity in
   the nginx variables `$wildbox_user_id`, `$wildbox_team_id` and
   `$wildbox_role`, and what the credential is in `$wildbox_auth_type` and
   `$wildbox_scopes` (see [Credential headers](#credential-headers)).

The shared proxy settings, `open-security-gateway/nginx/includes/proxy_params.conf`,
which every proxied route includes, then send:

```nginx
proxy_set_header X-Wildbox-User-ID $wildbox_user_id;
proxy_set_header X-Wildbox-Team-ID $wildbox_team_id;
proxy_set_header X-Wildbox-Role $wildbox_role;
proxy_set_header X-Wildbox-Auth-Type $wildbox_auth_type;
proxy_set_header X-Wildbox-Scopes $wildbox_scopes;
proxy_set_header X-Gateway-Secret $wildbox_gateway_secret;
proxy_set_header X-Request-ID $request_id;
proxy_set_header Authorization "";
```

The server block initializes `$wildbox_gateway_secret`, the three
`$wildbox_*` identity variables and the two credential variables to empty
strings, and nginx does not send a header whose value is empty.
`authenticate()` fills them in, the secret from the gateway's
`GATEWAY_INTERNAL_SECRET`, only for a request it let through
(`auth_handler.lua`). So the gateway sends its proof of origin, and its
description of the credential, only on routes it has authenticated; every
other location (identity's routes, the dashboard) forwards no
`X-Gateway-Secret`, `X-Wildbox-Auth-Type` or `X-Wildbox-Scopes`, and drops
the ones a client sent. `scripts/check_gateway_config.py` fails for a
configuration that calls `authenticate()` without declaring the variables.

### Routes that differ

- **Identity** (`/api/v1/identity/`, `/auth/`): identity is the
  authentication authority and validates the bearer token itself, so these
  routes do not run the shared handler and pass `Authorization` through.
- **Guardian** (`/api/v1/guardian/`): uses the shared handler, but guardian is
  a Django service with its own middleware
  (`open-security-guardian/apps/core/gateway_middleware.py`) rather than the
  FastAPI dependency below. Like the FastAPI services, it accepts gateway
  headers only and answers a direct request with `403`
  `GATEWAY_AUTH_REQUIRED`; it has no API keys of its own (#633). The
  middleware reads the credential headers with the same code as the FastAPI
  services (`open_security_shared.scopes`) and requires the scope of the
  request's method; see
  [Where a scope is checked twice](#where-a-scope-is-checked-twice).

## Identity headers

| Header | Content |
| --- | --- |
| `X-Wildbox-User-ID` | The caller's user ID (UUID) |
| `X-Wildbox-Team-ID` | The caller's team ID (UUID) |
| `X-Wildbox-Role` | The caller's role in the team: `owner`, `admin`, `member` or `viewer` |
| `X-Gateway-Secret` | The shared `GATEWAY_INTERNAL_SECRET`: the proof that the request came from the gateway |

There is no plan or subscription header.

## Credential headers

The gateway also tells the service what the credential is, so that a
service can check an API-key scope itself (#637):

| Header | Content |
| --- | --- |
| `X-Wildbox-Auth-Type` | `session` for a login session (a JWT), `api_key` for an API key. Sent on every request the gateway authenticated |
| `X-Wildbox-Scopes` | The API key's scopes, separated by single spaces, in the order identity holds them: `data:ingest`, or `tools:read data:read`. A key that is not limited carries `*`. Not sent for a session |

A session has no scopes and is not limited by them: the service gets
`X-Wildbox-Auth-Type: session` and no `X-Wildbox-Scopes`. That is how it
tells a session from a key: a key always has the header, unless its scope
list is empty, and a key without the header may do nothing that needs a
scope.

A third auth type, `service`, is never sent by the gateway. A Wildbox
service that calls another one on a user's behalf sends it with the gateway
secret; see [Calls between services](#calls-between-services).

The gateway decides the type by identity's answer: a decision that names an
API key is `api_key`, whichever header the credential came in. A scope that
is not a scope name (`*`, `name` or `name:action`, in lower case) is not
forwarded.

### How a service reads them

`open_security_shared.scopes` holds the rules, with no dependency, for the
FastAPI services and for guardian alike. They fail closed:

| What arrives | What the service does |
| --- | --- |
| No `X-Wildbox-Auth-Type` | Serves routes that need no scope; refuses a route that needs one, `403` `GATEWAY_AUTH_TYPE_REQUIRED`. A gateway older than the service does not send the header |
| An auth type other than `session`, `api_key` or `service` | `400` `INVALID_GATEWAY_HEADERS`, on every route |
| `X-Wildbox-Scopes` that is not a list of scope names separated by single spaces (empty, another separator, doubled spaces, upper case) | `400` `INVALID_GATEWAY_HEADERS`, on every route |
| `X-Wildbox-Scopes` present | The scopes decide, whatever the auth type |
| No `X-Wildbox-Scopes`, auth type `session` or `service` | Not limited by scopes |
| No `X-Wildbox-Scopes`, auth type `api_key` | The key holds no scope: every route that needs one is refused |

Whether a set of scopes satisfies a required one is decided as at the
gateway (`scopes_satisfy` in `auth_handler.lua`, `scope_satisfied` in
`open-security-shared/scopes.py`): `admin` and `*` satisfy everything,
`write` satisfies `read`, a resource's `admin` scope satisfies every action
on it, a generic scope satisfies the resource scopes of its level, and
`<resource>:delete` is satisfied only by itself and the admin scopes. The
two implementations are held together by one table of 200 pairs,
`open-security-gateway/test/scope_vectors.txt`: the shared package's tests
check theirs against every row, and the gateway's harness
(`test/scope_vector_tests.sh`) checks the Lua on the wire against the 180
rows a route of the test configuration requires.

### Where a scope is checked twice

The gateway checks every request. These services check again, on what the
gateway forwarded, so that a mistake in the gateway's scope map is not the
only thing between a key and the route:

| Service | Routes | Scope required of an API key |
| --- | --- | --- |
| data | `POST /api/v1/ingest` | `data:ingest` (also satisfied by `data:write` or `write`) |
| data | every other route under `/api/v1/` | `read` for `GET`, `write` for other methods |
| tools | `POST /api/tools/{tool}`, `POST /api/tools/{tool}/async`, `DELETE /api/tasks/{task_id}` | `tools:execute` |
| guardian | every route under `/api/` | `data:read` for `GET`, `HEAD` and `OPTIONS`; `data:delete` for `DELETE`; `data:write` for other methods |

A refusal is `403` with `code` `INSUFFICIENT_SCOPE` and the
`required_scope`.

The other routes rely on the gateway's check alone: reading tools and
tasks (`tools:read`), and everything in the agents, responder and CSPM
services. The agents and responder services use the shared dependency, so
their `GatewayUser` carries `auth_type` and `scopes` and a route can add
`require_scope`; CSPM reads the identity headers with code of its own and
does not read the credential headers.

## Using it in a FastAPI service

### Install the shared package

The shared code is the `open-security-shared` directory, installed as the
Python package `open_security_shared`. Services build with it as an extra
build context; in `docker-compose.yml`:

```yaml
build:
  context: ./open-security-myservice
  dockerfile: Dockerfile
  additional_contexts:
    shared: ./open-security-shared
```

and in the service's `Dockerfile`:

```dockerfile
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-deps /tmp/open-security-shared
```

`--no-deps` because the service's own `requirements.txt` already provides the
package's dependencies (FastAPI, Pydantic and the others listed in
`open-security-shared/pyproject.toml`).

### Authenticate a route

`open_security_shared.gateway_auth` provides `GatewayUser`,
`get_user_from_gateway_headers`, `require_role` and `require_scope`. Most
services re-export them from their own `app/auth.py`, as the agents service
does:

```python
# open-security-myservice/app/auth.py
from open_security_shared.gateway_auth import (
    GatewayUser,
    get_user_from_gateway_headers,
    require_role,
)

get_current_user = get_user_from_gateway_headers

__all__ = ["GatewayUser", "get_current_user", "require_role"]
```

```python
# open-security-myservice/app/main.py
from fastapi import Depends, FastAPI

from app.auth import GatewayUser, get_current_user, require_role

app = FastAPI()


@app.get("/api/v1/items")
async def list_items(user: GatewayUser = Depends(get_current_user)):
    # user.user_id and user.team_id are UUIDs; user.role is a string.
    return {"team_id": str(user.team_id)}


@app.delete("/api/v1/items/{item_id}")
async def delete_item(
    item_id: str,
    user: GatewayUser = Depends(get_current_user),
    _: None = Depends(require_role("owner", "admin")),
):
    return {"deleted": item_id}
```

Scope every query by `user.team_id`: the gateway authenticates the caller,
the service decides what that caller may see.

### Require an API-key scope

When the gateway requires a scope of a route (`required_scope_for_request`
in `auth_handler.lua`), the service can require it again with
`require_scope`. It returns the user, so it replaces the authentication
dependency on that route:

```python
from open_security_shared.gateway_auth import GatewayUser, require_scope


@app.post("/api/v1/ingest")
async def ingest(user: GatewayUser = Depends(require_scope("data:ingest"))):
    return {"team_id": str(user.team_id)}


# A service whose routes all follow the gateway's read/write rule, as the
# data service does: "read" for GET, HEAD and OPTIONS, "write" otherwise.
get_current_user = require_scope(read="read", write="write")
```

A session and a `service` call pass; an API key passes when its scopes
satisfy the required one; a request without `X-Wildbox-Auth-Type` is
refused. `user.auth_type`, `user.scopes` and `user.has_scope("...")` are
there for a rule of the route's own. Use the scope the gateway requires for
the route, or a key the gateway lets through is refused by the service.

### What the dependency checks

`get_user_from_gateway_headers` (`open-security-shared/gateway_auth.py`), in
this order:

| Condition | Status | `code` |
| --- | --- | --- |
| The service has no `GATEWAY_INTERNAL_SECRET` | 503 | `GATEWAY_SECRET_NOT_CONFIGURED` |
| `X-Wildbox-User-ID` or `X-Wildbox-Team-ID` missing | 403 | `GATEWAY_AUTH_REQUIRED` |
| `X-Gateway-Secret` missing or different (constant-time comparison) | 403 | `GATEWAY_SECRET_REQUIRED` |
| User or team ID not a UUID4 | 400 | `INVALID_GATEWAY_HEADERS` |
| Role not one of `owner`, `admin`, `member`, `viewer` (missing means `member`) | 400 | `INVALID_GATEWAY_HEADERS` |
| `X-Wildbox-Auth-Type` or `X-Wildbox-Scopes` present and malformed | 400 | `INVALID_GATEWAY_HEADERS` |

`require_role(...)` answers `403` with `code` `INSUFFICIENT_ROLE` when the
caller's role is not in the list.

`require_scope(...)` answers `403` with `code` `INSUFFICIENT_SCOPE` when an
API key lacks the scope, and `403` with `code` `GATEWAY_AUTH_TYPE_REQUIRED`
when the request has no `X-Wildbox-Auth-Type`. Both name the
`required_scope`.

The tools service wraps the dependency (`open-security-tools/app/auth.py`):
a request without the identity headers gets `401` there instead of `403`.

Services that install the shared error handlers
(`open_security_shared.errors.install_error_handlers`: tools, data, agents,
responder and cspm) return these errors in the canonical body. `error.code`
is the HTTP status; the `code` of the table above is at `error.details.code`,
and `error.message` is the explanation:

```json
{
  "error": {
    "code": 403,
    "message": "Direct access is not permitted; requests must traverse the gateway.",
    "type": "HTTPException",
    "request_id": "6f1c2d...",
    "details": {
      "error": "Gateway authentication required",
      "message": "Direct access is not permitted; requests must traverse the gateway.",
      "code": "GATEWAY_SECRET_REQUIRED"
    }
  }
}
```

guardian, the Django service, answers the same refusals with the dict itself
as the body, so its `code` is at the top level.

### Calls between services

A service that calls another one on behalf of a user forwards that user's
identity: the same three `X-Wildbox-*` headers and `X-Gateway-Secret`. There
is no service-wide key. The agents service does this for its tool calls
(`open-security-agents/app/tools/wildbox_client.py`, `_request_headers()`),
and the responder for its connectors
(`open-security-responder/app/caller.py`, `gateway_headers()`); both refuse
to make a call when they have no complete caller identity.

Such a call also sends `X-Wildbox-Auth-Type: service`, and no scopes: the
called service refuses a request that needs a scope and does not say what
its credential is. `service` is not limited by scopes. The caller's own
credential was checked by the gateway on the route that started the work
(`tools:execute` to start an analysis, `write` to run a playbook), and its
scopes do not travel with the call: what an analysis or a playbook does on
the caller's behalf is not checked against the scopes of the key that
started it.

## Testing

Through the gateway, which serves HTTPS with the certificate in
`open-security-gateway/ssl/`:

```bash
CA=open-security-gateway/ssl/wildbox.crt

# Valid API key: 200 with the tool's result
curl --cacert "$CA" -X POST https://<host>/api/v1/tools/whois_lookup \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Invalid API key: 401 from the gateway
curl --cacert "$CA" -X POST https://<host>/api/v1/tools/whois_lookup \
  -H "X-API-Key: invalid-key" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

Directly on a backend port (bound to `127.0.0.1` on the host), without the
gateway's headers, the request is refused:

```bash
# 401 from the tools service
curl -X POST http://127.0.0.1:8000/api/tools/whois_lookup \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Troubleshooting

**The service logs "Missing gateway authentication headers".** The request
reached the service without `X-Wildbox-User-ID` or `X-Wildbox-Team-ID`. Check
that it went through the gateway, and that the gateway route calls
`auth_handler.authenticate()` in an `access_by_lua_block`. Loading the module
with `access_by_lua_file` does not call it, and that route then runs without
authentication.

**The service answers `GATEWAY_SECRET_REQUIRED`.** The gateway and the
service hold different `GATEWAY_INTERNAL_SECRET` values, typically after a
rotation in which not every container was recreated. See
[Secrets rotation](SECURITY_SECRETS_ROTATION.md).

**The service answers `GATEWAY_AUTH_TYPE_REQUIRED`.** The request carried
the gateway's secret and no `X-Wildbox-Auth-Type`. The gateway image is
older than the service's: rebuild the gateway image and recreate its
container. A script or a test that calls a service directly with the secret
must send the header too.

**`ModuleNotFoundError: open_security_shared`.** The image was built without
the `shared` build context or without the `pip install` step above.

## Best practices

1. Never publish a backend port beyond `127.0.0.1`; the gateway is the entry
   point.
2. Do not read credentials in a backend service; use the identity headers.
3. Fail closed: a missing or invalid header is a refusal, never a default
   user.
4. Log `user.user_id` and `user.team_id` for audit trails.

The reference implementation is `open-security-shared/gateway_auth.py`.
