"""The per-caller hourly limit on operations, counted in Redis (#721).

``AuthorizationManager.check_rate_limit`` kept the timestamps of a caller's
runs in a dict of the process that checked. The API process and each child
of the Celery prefork worker therefore counted on their own, so a caller
limited to one destructive test an hour had one in the API and one more in
every worker child the task happened to land on, and a restart handed
everybody a new allowance.

The count now lives in the service's Redis (``REDIS_URL``, the database the
task records already use), one sorted set per caller and operation:

    wildbox:tools:operation-limit:<user id>:<operation>

Each member is one run that was let through, scored with the time it was let
through. A run is allowed when fewer than ``limit`` members are younger than
the window, which is the rule the in-process limiter applied: at most
``limit`` runs in any hour, not ``limit`` per clock hour.

Checking and recording are one Lua script, so they are one step for every
process that asks: two requests for the last allowance cannot both read
"one left" and both take it. The time is the Redis server's, so processes
whose clocks differ agree on the window. The key expires one window after
the last run it recorded.

When the count cannot be read or written the run is refused, not let
through uncounted: ``RateLimitUnavailable`` is raised, the API answers 503
and the worker fails the task. The agents service does the same for its
analysis limit.
"""

import threading
import uuid
from typing import Optional

from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

WINDOW_SECONDS = 3600

KEY_PREFIX = "wildbox:tools:operation-limit"

# What a caller is told. The reason (a host name, a port) goes to the log.
UNAVAILABLE_MESSAGE = "Rate limiting temporarily unavailable"

# KEYS[1]  the caller's sorted set for the operation
# ARGV[1]  the limit
# ARGV[2]  the window, in seconds
# ARGV[3]  a name for this run, unique to the call
#
# Returns 1 when the run is allowed (and recorded), 0 when the limit is
# reached. A run that is already recorded is allowed again without taking a
# second allowance, so a call repeated after a dropped connection counts
# once whether or not the first attempt reached the server.
ALLOW_SCRIPT = """
local now = redis.call('TIME')
local millis = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local window = tonumber(ARGV[2]) * 1000
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', millis - window)
if redis.call('ZSCORE', KEYS[1], ARGV[3]) then
    return 1
end
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then
    return 0
end
redis.call('ZADD', KEYS[1], millis, ARGV[3])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
return 1
"""


class RateLimitUnavailable(RuntimeError):
    """The limit cannot be checked, so the run must not start.

    Deliberately not a PermissionError: the caller is not refused for what
    they asked, and the answer is 503, not 403.
    """

    def __init__(self, reason: str = ""):
        super().__init__(UNAVAILABLE_MESSAGE)
        # For the log only; never part of str(), which may reach a client.
        self.reason = reason


class OperationRateLimiter:
    """At most ``limit`` runs per caller and operation in any window."""

    def __init__(
        self,
        client,
        window_seconds: int = WINDOW_SECONDS,
        key_prefix: str = KEY_PREFIX,
    ):
        self._redis = client
        self._window = int(window_seconds)
        self._prefix = key_prefix
        self._script = client.register_script(ALLOW_SCRIPT)

    def key(self, user_id: str, operation: str) -> str:
        return f"{self._prefix}:{user_id}:{operation}"

    def allow(self, user_id: str, operation: str, limit: int) -> bool:
        """Take one of the caller's allowances, if one is left.

        True when the run may start; it is then counted. False when the
        caller has used ``limit`` runs in the window; nothing is recorded.
        Raises RateLimitUnavailable when Redis cannot say.
        """
        run = uuid.uuid4().hex
        keys = [self.key(user_id, operation)]
        args = [int(limit), self._window, run]
        try:
            try:
                allowed = self._script(keys=keys, args=args)
            except RedisConnectionError:
                # A pooled connection that Redis closed (it restarted, or an
                # idle timeout). The script counts a run once however often
                # it is sent, so one more attempt on a new connection is safe.
                allowed = self._script(keys=keys, args=args)
        except (RedisError, OSError) as error:
            raise RateLimitUnavailable(f"{type(error).__name__}: {error}") from error
        return int(allowed) == 1


_limiter: Optional[OperationRateLimiter] = None
_limiter_lock = threading.Lock()


def get_rate_limiter() -> OperationRateLimiter:
    """The process's limiter, connected to the service's Redis.

    Every process of the service (the API and each worker child) builds its
    own client; what they share is the count.
    """
    global _limiter
    if _limiter is None:
        with _limiter_lock:
            if _limiter is None:
                from app.config import settings

                if not settings.redis_url:
                    raise RateLimitUnavailable("REDIS_URL is not set")
                import redis

                try:
                    client = redis.Redis.from_url(
                        settings.redis_url,
                        decode_responses=True,
                        # An unreachable Redis is answered with a 503 in
                        # seconds, not when the kernel gives up connecting.
                        socket_connect_timeout=2,
                        socket_timeout=2,
                    )
                    _limiter = OperationRateLimiter(client)
                except (RedisError, OSError, ValueError) as error:
                    raise RateLimitUnavailable(
                        f"{type(error).__name__}: {error}"
                    ) from error
    return _limiter
