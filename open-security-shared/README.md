# open-security-shared

Shared utilities for Wildbox security services.

The primary export is the **gateway authentication** dependency
(`open_security_shared.gateway_auth`): backend services trust the
`X-Wildbox-*` identity headers stamped by the API gateway, verified by the
shared `GATEWAY_INTERNAL_SECRET` proof-of-origin.

```python
from open_security_shared.gateway_auth import get_user_from_gateway_headers, GatewayUser, require_role
```

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

## Installing it

The package has no dependency of its own. Each group of modules has an extra
that lists what those modules import, and a service installs the package with
the extras of the modules it uses:

| Extra | Modules | Requires |
| --- | --- | --- |
| none | `api_docs`, `circuit_breaker` | the standard library |
| `fastapi` | `errors`, `gateway_auth`, `tenancy`, `security_middleware` | FastAPI, Pydantic 2 |
| `auth` | `auth_utils` | FastAPI, PyJWT, passlib with bcrypt |
| `metrics` | `observability` | FastAPI, prometheus-client 0.20 or later |
| `events` | `cqrs`, `event_sourcing`, `feature_flags`; `idempotency` with `fastapi` | Redis, SQLAlchemy 2 with asyncio |
| `tracing` | `tracing` | the OpenTelemetry API, SDK, exporters and instrumentations |

`[tool.wildbox.module-extras]` in `pyproject.toml` is the same table for
`scripts/check_shared_dependencies.py`, which fails when a module imports
something its extras do not require.

The six FastAPI services use `fastapi` and `metrics`. Guardian (Django) and
the sensor (aiohttp) install the package without an extra. No image installs
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
