"""Gateway authentication for the Agents service.

Delegates to the shared `open_security_shared.gateway_auth` dependency, which
verifies the `GATEWAY_INTERNAL_SECRET` proof-of-origin and validates the
gateway-injected `X-Wildbox-*` headers. The gateway is the sole entrypoint.
"""

from open_security_shared.gateway_auth import (
    GatewayUser,
    get_user_from_gateway_headers,
    require_role,
)

# The shared dependency IS this service's authentication dependency.
get_current_user = get_user_from_gateway_headers

__all__ = ["GatewayUser", "get_current_user", "require_role"]
