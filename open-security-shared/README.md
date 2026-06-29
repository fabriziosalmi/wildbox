# open-security-shared

Shared utilities for Wildbox security services.

The primary export is the **gateway authentication** dependency
(`open_security_shared.gateway_auth`): backend services trust the
`X-Wildbox-*` identity headers stamped by the API gateway, verified by the
shared `GATEWAY_INTERNAL_SECRET` proof-of-origin.

```python
from open_security_shared.gateway_auth import get_user_from_gateway_headers, GatewayUser, require_role
```

Install (from the repo root, per service): `pip install ./open-security-shared`.

Optional extras: `observability` (OpenTelemetry), `events` (Redis/SQLAlchemy/httpx).
