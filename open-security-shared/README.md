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

Install (from the repo root, per service): `pip install ./open-security-shared`.

Optional extras: `observability` (OpenTelemetry), `events` (Redis/SQLAlchemy/httpx).
