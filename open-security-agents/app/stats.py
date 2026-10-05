"""Per-day task counters for GET /stats.

``completed_today`` and ``failed_today`` were two Redis keys the worker
incremented and nothing ever reset, so despite their names they counted
since the Redis data was last cleared (#652). Each day now has its own key,
named by the UTC date, which expires after two days: "today" is the key of
the current UTC date, and yesterday's count goes away by itself.
"""

from datetime import datetime, timezone
from typing import Optional

# Long enough that a key cannot expire during the day it counts, whatever
# the clock skew between the worker and Redis.
DAILY_COUNTER_TTL_SECONDS = 2 * 24 * 60 * 60

COMPLETED = "completed"
FAILED = "failed"

# The keys that were never reset. Nothing reads them any more; the API
# deletes them when it starts.
LEGACY_KEYS = ("stats:completed_today", "stats:failed_today")


def utc_day(now: Optional[datetime] = None) -> str:
    """The UTC calendar date of ``now`` (default: the current time)."""
    return (
        (now or datetime.now(timezone.utc))
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%d")
    )


def daily_key(name: str, now: Optional[datetime] = None) -> str:
    return f"stats:{name}:{utc_day(now)}"


def count_today(redis_client, name: str, now: Optional[datetime] = None) -> None:
    """Add one to today's ``name`` counter, and keep it from living forever."""
    key = daily_key(name, now)
    pipe = redis_client.pipeline()
    pipe.incr(key)
    pipe.expire(key, DAILY_COUNTER_TTL_SECONDS)
    pipe.execute()


def read_today(redis_client, name: str, now: Optional[datetime] = None) -> int:
    """Today's ``name`` counter; 0 when nothing was counted today."""
    return int(redis_client.get(daily_key(name, now)) or 0)
