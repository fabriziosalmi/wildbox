"""One run at a time for the periodic sweeps that must not overlap (#545).

guardian-worker runs two tasks at once, and a sweep can be started both by
guardian-beat and by hand (POST .../alerts/check_all/). Two concurrent runs
of check_sla_violations both see "no notification in the last 24 hours" and
both send one; two runs of check_all_alert_rules notify twice and race on
``trigger_count``. ``single_instance`` makes the second run return at once.

The lock is a cache key set with ``cache.add`` (SET NX on Redis), so taking
it is atomic. It expires after the task's hard time limit: a run is killed
at that limit, so it cannot outlive its lock, and a worker that dies
mid-run cannot leave the lock behind for longer.
"""

import functools
import logging
import uuid

from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

LOCK_PREFIX = "guardian:task-lock:"


def lock_timeout():
    return int(getattr(settings, "CELERY_TASK_TIME_LIMIT", 30 * 60)) + 60


def single_instance(func):
    """Skip a run of ``func`` while another run of it holds the lock."""
    key = f"{LOCK_PREFIX}{func.__module__}.{func.__name__}"

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        token = uuid.uuid4().hex
        if not cache.add(key, token, timeout=lock_timeout()):
            logger.info("%s is already running; this run is skipped", key)
            return {"skipped": "already running"}
        try:
            return func(*args, **kwargs)
        finally:
            # Only the holder releases it. Between get and delete the key
            # could only change hands if it had expired, i.e. after the
            # hard time limit, which this run cannot reach.
            if cache.get(key) == token:
                cache.delete(key)

    return wrapper
