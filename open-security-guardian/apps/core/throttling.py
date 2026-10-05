"""guardian's request throttle: per user, as the gateway names the user (#645).

Every request under ``/api/`` reaches guardian through the gateway, already
authenticated: GatewayAuthMiddleware refuses anything else before a view
runs. The throttle counts those requests per user, on the user id the
gateway forwards in ``X-Wildbox-User-ID`` -- not on an address, which for
every caller is the gateway's own.

There is no throttle for anonymous callers, because under ``/api/`` there
are none. Django REST Framework's ``AnonRateThrottle`` was installed beside
the user throttle, at 100 requests an hour per address, and the one route
it could reach was the health check: ``/health/`` is probed by the
container's own health check twice a minute, 120 times an hour from
127.0.0.1. Once a hundred probes were in the window the next twenty were
refused with 429, so the container reported unhealthy for the last ten
minutes of every hour it was up. It read the address from
``X-Forwarded-For`` as the caller wrote it, so it limited nobody who cared
to change the header.

The rate is ``GUARDIAN_RATE_LIMIT_USER``; see guardian/rate_limit.py.
"""

from rest_framework.throttling import SimpleRateThrottle


class GatewayUserRateThrottle(SimpleRateThrottle):
    """``DEFAULT_THROTTLE_RATES['user']`` requests per gateway user."""

    scope = "user"

    def get_cache_key(self, request, view):
        gateway_user = getattr(request, "gateway_user", None)
        if gateway_user is None:
            # Not a gateway request: the health check, or the schema in
            # DEBUG. Nothing to count it under, so it is not throttled.
            return None
        return self.cache_format % {
            "scope": self.scope,
            "ident": gateway_user.user_id,
        }
