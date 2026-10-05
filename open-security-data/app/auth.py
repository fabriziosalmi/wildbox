"""Gateway authentication for the Data service.

Delegates to the shared `open_security_shared.gateway_auth` dependency, which
verifies the `GATEWAY_INTERNAL_SECRET` proof-of-origin and validates the
gateway-injected `X-Wildbox-*` headers. The gateway is the sole entrypoint.

API-key scopes (#637). The gateway requires a scope of every request it
forwards here: `data:ingest` to post telemetry to `/api/v1/ingest`, the
generic `read` for every other GET and `write` for every other method
(`ROUTE_SCOPES`/`required_scope_for_request` in the gateway's
`auth_handler.lua`). The service used to take the gateway's word for it: it
was told the user, the team and the role, and a sensor's `data:ingest` key
looked the same as its owner's session. It now checks the same scopes on
what the gateway forwards about the credential (`X-Wildbox-Auth-Type`,
`X-Wildbox-Scopes`), so a mistake in the gateway's map does not turn a
sensor's key into a key for the team's data. A session is not limited by
scopes; a request that does not say what its credential is is refused.
"""

from open_security_shared.gateway_auth import (
    GatewayUser,
    require_role,
    require_scope,
)

# Every route but the ingest: `read` to read, `write` to change.
get_current_user = require_scope(read="read", write="write")

# POST /api/v1/ingest: the scope a sensor's key is limited to. `data:write`
# and `write` satisfy it too, as at the gateway.
get_ingest_user = require_scope("data:ingest")

__all__ = ["GatewayUser", "get_current_user", "get_ingest_user", "require_role"]
