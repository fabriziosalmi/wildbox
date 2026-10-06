# open-security-shared

Shared utilities for Wildbox security services.

The primary export is the **gateway authentication** dependency
(`open_security_shared.gateway_auth`): backend services trust the
`X-Wildbox-*` identity headers stamped by the API gateway, verified by the
shared `GATEWAY_INTERNAL_SECRET` proof-of-origin.

```python
from open_security_shared.gateway_auth import get_user_from_gateway_headers, GatewayUser, require_role
```

The gateway also forwards what the credential is (`X-Wildbox-Auth-Type`)
and an API key's scopes (`X-Wildbox-Scopes`). `GatewayUser` carries them as
`auth_type` and `scopes`, and `require_scope` is the dependency a route
uses to check again a scope the gateway already checked:

```python
from open_security_shared.gateway_auth import require_scope

@app.post("/api/v1/ingest")
async def ingest(user: GatewayUser = Depends(require_scope("data:ingest"))):
    ...
```

`open_security_shared.scopes` holds the rules (parsing the two headers, the
scope hierarchy) and imports nothing outside the standard library, so
guardian's Django middleware uses it too. The
[Gateway authentication guide](../docs/GATEWAY_AUTHENTICATION_GUIDE.md#credential-headers)
describes the headers and what fails closed.

`open_security_shared.errors` is the error contract of the FastAPI services:
`install_error_handlers(app)` makes every error leave in one body,

```json
{"error": {"code": 403, "message": "...", "type": "HTTPException", "request_id": "..."}}
```

`error.code` is the HTTP status and `error.message` always a sentence. An
endpoint that raises `HTTPException(detail={...})` gets its dict back as JSON
under `error.details`, never as a Python dict string, and `error.message`
from its `reason`, `message` or `error` key, in that order, or the status
phrase when it has none. A list detail goes to `error.details` in the same
way. The module's docstring has the full rules.

For a validation error (422), `error.details` is the list of field errors,
each `{"type": ..., "loc": [...], "msg": ...}`. FastAPI's default list also
holds the `input` that was refused, which for a missing field is the whole
request body; `field_errors()` drops it, with `ctx` and `url`, so a secret in
a rejected request is not sent back. A validator's own message is returned
as written: do not put the value in it when the value can be a secret.

## What stays out of the log

A log is read by more people and kept for longer than the request it
describes, so no service writes what a request held into one.
`install_error_handlers(app)` also calls
`log_safety.keep_requests_out_of_the_logs()`, which does two things every
FastAPI service needs and none should have to remember:

- uvicorn's access log loses the query string of each request. The line
  keeps the method, the path and the status:
  `"GET /api/v1/indicators/search HTTP/1.1" 200`.
- the libraries that log the requests they send are held to warnings and
  errors, whatever the service's log level: `httpx` and `httpcore` (the URL
  of every request, at INFO), `urllib3` (at DEBUG), `aiohttp.client`, and
  `botocore` and `boto3` (at DEBUG, the request botocore signs, session
  token included).

A worker process makes no application, so it calls
`log_safety.quiet_http_client_loggers()` itself where it starts.

The record of an HTTP error has the status, the path and the request id,
not the `detail`: a detail is the answer to the caller and often names what
they sent. A service that wants the reason of a refusal in its log writes it
there, in words that hold no value.

`tests/scripts/test_no_request_values_in_logs.py` reads every logging call
of every service and fails when one is handed a value whose name says it is
a request, a part of one or a credential.

## Scan targets

`open_security_shared.target_policy` decides which network targets a service
may connect to for a caller. The tools service (its network tools) and
guardian (asset discovery and port scans) both run inside the stack's
networks, and both use this one implementation:

- **Refused**: private, loopback, link-local, multicast, reserved, shared
  and cloud-metadata addresses, IPv4 and IPv6, an IPv4 address embedded in an
  IPv6 one included (IPv4-mapped, 6to4, NAT64); a range with any such address
  in it, even when the rest of it is public; a range of more than 1,024
  addresses; a name that resolves to such an address or does not resolve; and
  the deployment's own names.
- **Allowlist**: `parse_allowlist(raw, setting)` reads an operator's setting.
  Each service has its own (`TOOLS_ALLOWED_INTERNAL_TARGETS`,
  `GUARDIAN_ALLOWED_INTERNAL_TARGETS`) and neither reads the other's.
- **Answer**: `TargetPolicy(allowlist)` answers with a `Refusal` (a `Reason`
  and the address, host or count it is about) or `None`. It raises nothing
  for a refused target and writes no message: each service words its own
  refusal, so no response is built from the text of an exception.

`tests/shared/target_policy_vectors.json` holds the cases the two services
and this package must agree on; each of the three runs them through its own
entry point.

## Installing it

The package has no dependency of its own. Each group of modules has an extra
that lists what those modules import, and a service installs the package with
the extras of the modules it uses:

| Extra | Modules | Requires |
| --- | --- | --- |
| none | `api_docs`, `circuit_breaker`, `environment`, `log_safety`, `scopes`, `target_policy` | the standard library |
| `fastapi` | `errors`, `gateway_auth`, `tenancy`, `security_middleware` | FastAPI, Pydantic 2 |
| `auth` | `auth_utils` | FastAPI, PyJWT, passlib with bcrypt |
| `metrics` | `observability` | FastAPI, prometheus-client 0.20 or later |
| `events` | `cqrs`, `event_sourcing`, `feature_flags`; `idempotency` with `fastapi` | Redis, SQLAlchemy 2 with asyncio |
| `tracing` | `tracing` | the OpenTelemetry API, SDK, exporters and instrumentations |

`[tool.wildbox.module-extras]` in `pyproject.toml` is the same table for
`scripts/check_shared_dependencies.py`, which fails when a module imports
something its extras do not require.

The six FastAPI services use `fastapi` and `metrics`. Guardian (Django)
imports `scopes` and `target_policy` only, and the sensor (aiohttp) nothing:
both install the package without an extra. No image installs
`auth`, `events` or `tracing` today. `tracing` does not work yet: the module
imports the Jaeger Thrift exporter, whose last release (1.21.0) does not
import under a current OpenTelemetry SDK, so `install_observability` logs
that tracing is not initialized and the service runs without it.

In a service image the package is installed after the hash-checked lock,
offline:

```dockerfile
COPY --from=shared . /tmp/open-security-shared
RUN pip install --no-cache-dir --no-index --no-build-isolation \
        "/tmp/open-security-shared[fastapi,metrics]" \
    && pip check
```

With `--no-index` pip can resolve the extras' requirements only against what
`requirements.txt` installed, so the build fails when the lock lacks one or
pins it below the floor declared here; `pip check` fails it for any other
unmet requirement. A service that starts importing a module of another extra
adds the extra to that line and the packages to its `requirements.in`
(`make lock`); the Dependency Integrity job fails until it has.

For local work, from a service directory:
`pip install -r requirements.txt ../open-security-shared`. To run this
package's own tests (`tests/shared`):
`pip install "./open-security-shared[fastapi,auth,metrics]"`.
