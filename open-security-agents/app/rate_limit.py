"""Rate limits on analysis submission, keyed by the verified caller (#651).

The limiter was keyed by ``get_remote_address``. Every request reaches this
service through the gateway, and uvicorn trusts no forwarding headers, so
the peer address was the gateway's for every caller: one bucket for the
whole platform, which one user of one team could empty for everyone.

The budget now belongs to the user the gateway authenticated. The key is
taken from the ``GatewayUser`` that ``get_current_user`` returned, which
exists only after the gateway secret has been verified; no header is read
here, so neither ``X-Forwarded-For`` nor an unverified ``X-Wildbox-*``
header can move a request to another bucket.

Why per user: the analysis is started by a person, and a per-team key
would let one member exhaust the budget of their teammates, the same
defect inside a team. An optional per-team ceiling
(``ANALYZE_TEAM_RATE_LIMIT``) bounds what a team with many members can
submit in total; it is off unless configured.

The counters live in Redis, so they survive a restart and are shared by
every process serving the API; see ``limiter`` below.

slowapi resolves the endpoint's dependencies before it checks the limit,
so ``rate_limited_caller`` has stored the verified caller on the request
by the time a key function runs. A request without one is refused rather
than counted under some shared key.
"""

from fastapi import Depends, HTTPException, status
from slowapi import Limiter
from starlette.requests import Request

from .auth import GatewayUser, get_current_user
from .config import settings

_STATE_ATTRIBUTE = "verified_caller"


def _verified_caller(request: Request) -> GatewayUser:
    caller = getattr(request.state, _STATE_ATTRIBUTE, None)
    if not isinstance(caller, GatewayUser):
        # Unreachable through a route that depends on rate_limited_caller;
        # refuse instead of falling back to a key every caller shares.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A verified caller identity is required",
        )
    return caller


def user_rate_limit_key(request: Request) -> str:
    """The rate limit bucket of the authenticated user."""
    return f"user:{_verified_caller(request).user_id}"


def team_rate_limit_key(request: Request) -> str:
    """The rate limit bucket of the authenticated user's team."""
    return f"team:{_verified_caller(request).team_id}"


async def rate_limited_caller(
    request: Request, user: GatewayUser = Depends(get_current_user)
) -> GatewayUser:
    """Authenticate the caller and make the identity available to the limiter."""
    setattr(request.state, _STATE_ATTRIBUTE, user)
    return user


# No route uses the default key: every limit names its own key function.
#
# The counters are kept in the service's Redis (REDIS_URL) unless
# ANALYZE_RATE_LIMIT_STORAGE_URI says otherwise. They were in this process's
# memory: every restart handed each user a new budget, which empties a limit
# per day of its meaning, and a second API process would have counted on its
# own (#652). The submission writes to the same Redis before it queues
# anything, so the limiter adds no dependency. When the storage cannot be
# reached the request is refused, not let through uncounted: slowapi raises
# (no in-memory fallback, errors not swallowed) and app.main answers 503.
limiter = Limiter(
    key_func=user_rate_limit_key,
    storage_uri=settings.rate_limit_storage_uri(),
    in_memory_fallback_enabled=False,
    swallow_errors=False,
)


def limit_analysis(func):
    """Apply the per-user limit and, when configured, the per-team ceiling.

    The values are read from the settings on each request, so they are the
    validated values from the environment (see ``Settings``).

    The limits are checked in the order they are registered: the user's
    first, so a request over the user's limit is refused before it is
    counted against the team.
    """
    func = limiter.limit(
        lambda: settings.analyze_rate_limit,
        key_func=user_rate_limit_key,
        error_message=lambda: f"{settings.analyze_rate_limit} per user",
    )(func)
    func = limiter.limit(
        lambda: settings.analyze_team_rate_limit or settings.analyze_rate_limit,
        key_func=team_rate_limit_key,
        exempt_when=lambda: not settings.analyze_team_rate_limit,
        error_message=lambda: f"{settings.analyze_team_rate_limit} per team",
    )(func)
    return func
